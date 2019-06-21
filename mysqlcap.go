/*
 * mysqlcap.go
 *
 */

package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/xiewen/mysqlcap/mysql"
	"github.com/xiewen/mysqlcap/utils"

	_ "github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var port = flag.Int("port", 3306, "port of mysql server")
var errLog *utils.ErrLogService
var sqlLog *utils.SQLLogService

type mysqlStreamFactory struct {
	source map[string]*mysqlStream
}

type packet struct {
	seq     uint8
	payload []byte
}

type mysqlStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream

	stmtID2query map[uint32]*mysql.Stmt

	packets chan *packet
}

func (m *mysqlStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	mstream := &mysqlStream{
		net:          net,
		transport:    transport,
		r:            tcpreader.NewReaderStream(),
		stmtID2query: make(map[uint32]*mysql.Stmt),
		packets:      make(chan *packet, 1024),
	}

	// net: 10.18.69.137->10.18.68.212
	// transport: 34907->3306
	errLog.Log(fmt.Sprintf("new stream %s %s", net, transport))
	go mstream.readPackets()

	// key: 10.18.69.137->10.18.68.212:34907->3306
	// revKey: 10.18.68.212->10.18.69.137:3306->34907
	key := fmt.Sprintf("%v:%v", net, transport)
	revKey := fmt.Sprintf("%v:%v", net.Reverse(), transport.Reverse())

	// server to client stream
	if transport.Src().String() == strconv.Itoa(*port) {
		if client, ok := m.source[revKey]; ok {
			errLog.Log(fmt.Sprintf("run server to client: %s", revKey))
			go client.runClient(mstream.packets)
			delete(m.source, revKey)
		} else {
			// wait client stream
			m.source[key] = mstream
		}
	} else { // client to server stream
		if server, ok := m.source[revKey]; ok {
			errLog.Log(fmt.Sprintf("run client to server: %s", key))
			go mstream.runClient(server.packets)
			delete(m.source, revKey)
		} else {
			// wait server stream
			m.source[key] = mstream
		}
	}

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &mstream.r
}

func (m *mysqlStream) readPackets() {
	buf := bufio.NewReader(&m.r)
	for {
		seq, pk, err := mysql.ReadPacket(buf)
		if err == io.EOF {
			errLog.Log(fmt.Sprintf("%s %s leave", m.net, m.transport))
			close(m.packets)
			return
		} else if err != nil {
			errLog.Log(fmt.Sprintf("Error reading stream %s %s : %s", m.net, m.transport, err))
			close(m.packets)
		} else {
			// errLog.Log(fmt.Sprintf("Received package from stream %s %s seq: %s pk: %s", m.net, m.transport, seq, pk))
		}

		m.packets <- &packet{seq: seq, payload: pk}
	}

}

// for simplicy, does'n parse server response according to request
// just skip to the first response packet to try get response stmt_id now
func skip2Seq(srv chan *packet, seq uint8) *packet {
	for {
		select {
		case pk, ok := <-srv:
			if !ok {
				return nil
			}
			if pk.seq == seq {
				return pk
			}
		case <-time.After(5 * time.Second):
			return nil
		}
	}
}

func (m *mysqlStream) handlePacket(seq uint8, payload []byte, srvPackets chan *packet) {
	// text protocol command can just print it out
	// https://dev.mysql.com/doc/internals/en/text-protocol.html
	srvPK := skip2Seq(srvPackets, seq+1)
	switch payload[0] {
	// 131, 141 for handkshake
	// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake
	case 131, 141:
	// some old client may still use this, print it in sql query way
	case mysql.COM_INIT_DB:
		sqlLog.Log("COM_INIT_DB", string(payload[1:]))
	case mysql.COM_DROP_DB:
		sqlLog.Log("COM_DROP_DB", string(payload[1:]))
	case mysql.COM_CREATE_DB:
		sqlLog.Log("COM_CREATE_DB", string(payload[1:]))
	// just print the query
	case mysql.COM_QUERY:
		sqlLog.Log("COM_QUERY", string(payload[1:]))

	// prepare statements
	// https://dev.mysql.com/doc/internals/en/prepared-statements.html
	case mysql.COM_STMT_PREPARE:
		// find the return stmt_id, so we can know which prepare stmt execute later
		if srvPK == nil {
			errLog.Log("can't find resp packet from prepare")
			return
		}

		// https://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html#packet-COM_STMT_PREPARE_OK
		if srvPK.payload[0] != 0 {
			errLog.Log("prepare fail")
			return
		}

		stmtID := binary.LittleEndian.Uint32(srvPK.payload[1:5])
		stmt := &mysql.Stmt{
			ID:    stmtID,
			Query: string(payload[1:]),
		}
		m.stmtID2query[stmtID] = stmt
		stmt.Columns = binary.LittleEndian.Uint16(srvPK.payload[5:7])
		stmt.Params = binary.LittleEndian.Uint16(srvPK.payload[7:9])
		stmt.Args = make([]interface{}, stmt.Params)

		sqlLog.Log("COM_STMT_PREPARE", stmt.Query)
	case mysql.COM_STMT_SEND_LONG_DATA:
		// https://dev.mysql.com/doc/internals/en/com-stmt-send-long-data.html
		stmtID := binary.LittleEndian.Uint32(payload[1:5])
		paramID := binary.LittleEndian.Uint16(payload[5:7])
		stmt, ok := m.stmtID2query[stmtID]
		if !ok {
			return
		}
		if paramID >= stmt.Params {
			return
		}

		if stmt.Args[paramID] == nil {
			stmt.Args[paramID] = payload[7:]
		} else {
			if b, ok := stmt.Args[paramID].([]byte); ok {
				b = append(b, payload[7:]...)
				stmt.Args[paramID] = b
			}
		}
	case mysql.COM_STMT_RESET:
		// https://dev.mysql.com/doc/internals/en/com-stmt-reset.html
		stmtID := binary.LittleEndian.Uint32(payload[1:5])
		stmt, ok := m.stmtID2query[stmtID]
		if !ok {
			return
		}
		stmt.Args = make([]interface{}, stmt.Params)

	case mysql.COM_STMT_EXECUTE:
		// https://dev.mysql.com/doc/internals/en/com-stmt-execute.html
		idx := 1
		stmtID := binary.LittleEndian.Uint32(payload[idx : idx+4])
		idx += 4
		var stmt *mysql.Stmt
		var ok bool
		if stmt, ok = m.stmtID2query[stmtID]; ok == false {
			errLog.Log(fmt.Sprintf("not found stmt id query: %s", stmtID))
			return
		}
		//sqlLog.Log("COM_STMT_EXECUTE", "sql", stmt.Query)
		// parse params
		flags := payload[idx]
		_ = flags
		idx++
		// skip iterater_count alwasy 1
		_ = binary.LittleEndian.Uint32(payload[idx : idx+4])
		idx += 4
		if stmt.Params > 0 {
			len := int((stmt.Params + 7) / 8)
			nullBitmap := payload[idx : idx+len]
			idx += len

			newParamsBoundFlag := payload[idx]
			idx++

			var paramTypes []byte
			var paramValues []byte
			if newParamsBoundFlag == 1 {
				paramTypes = payload[idx : idx+int(stmt.Params)*2]
				idx += int(stmt.Params) * 2
				paramValues = payload[idx:]
			}
			err := stmt.BindStmtArgs(nullBitmap, paramTypes, paramValues)
			if err != nil {
				errLog.Log(fmt.Sprintf("bind args err: %s", err))
				return
			}
		}
		// utils.Logger.Println("exec smmt: ", *stmt)
		//fmt.Println("# binary exec a prepare stmt rewrite it like: ")
		//fmt.Println(string(stmt.WriteToText()))
		sqlLog.Log("COM_STMT_EXECUTE", string(stmt.WriteToText()))
	case mysql.COM_STMT_CLOSE:
		// https://dev.mysql.com/doc/internals/en/com-stmt-close.html
		// delete the stmt will not be use any more
		stmtID := binary.LittleEndian.Uint32(payload[1:5])
		delete(m.stmtID2query, stmtID)
	default:
	}
}

func (m *mysqlStream) runClient(srv chan *packet) {
	for packet := range m.packets {
		m.handlePacket(packet.seq, packet.payload, srv)
	}
}

func main() {
	flag.Parse()
	errLog = utils.NewErrLog()
	sqlLog = utils.NewSQLLog()
	sigs := make(chan os.Signal, 1)
	exit := make(chan bool, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		errLog.Log(fmt.Sprintf("received signal: %v", sig))
		exit <- true
	}()

	errLog.Log(fmt.Sprintf("Initializing MySQL capture on %s:%d...", *iface, *port))
	handle, err := pcap.OpenLive(*iface, 65535, false, pcap.BlockForever)
	if handle == nil || err != nil {
		msg := "unknown error"
		if err != nil {
			msg = err.Error()
		}
		errLog.Log(fmt.Sprintf("Failed to open device: %s", msg))
		os.Exit(1)
	}

	err = handle.SetBPFFilter(fmt.Sprintf("tcp port %d", *port))
	if err != nil {
		errLog.Log(fmt.Sprintf("Failed to set port filter: %s", err.Error()))
		os.Exit(1)
	}
	//defer handle.Close()

	// Set up assembly
	streamFactory := &mysqlStreamFactory{source: make(map[string]*mysqlStream)}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)

	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			// log.Println(packet)
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				errLog.Log("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		case <-ticker:
			// Every Minus, flush connections that haven't seen activity in the past 2 Minute.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		case <-exit:
			errLog.Log("exiting")
			os.Exit(0)
		}
	}
}
