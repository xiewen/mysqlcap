/*
 * mysqlcap.go
 *
 * [Packet Capture, Injection, and Analysis with Gopacket](https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket)
 * [MySQL Query Sniffer](https://github.com/zorkian/mysql-sniffer)
 *   This program uses libpcap to capture and analyze packets destined for a MySQL
 *   server.  With a variety of command line options, you can tune the output to
 *   show you a variety of outputs, such as:
 *       * top N queries since you started running the program
 *       * top N queries every X seconds (sliding window)
 *       * all queries (sanitized or not)
 * [go-sniffer](https://github.com/40t/go-sniffer)
 *   Capture mysql,redis,http,mongodb etc protocol...
 *   抓包截取项目中的数据库请求并解析成相应的语句，如mysql协议会解析为sql语句,便于调试。
 *   不要修改代码，直接嗅探项目中的数据请求。
 * [tidb_sql.go](https://github.com/july2993/tidb_sql)
 *   use pcap to read packets off the wire about tidb-server(or mysql), and print
 *   the sql which client send to server in stdout (some log will be print in stderr).
 *   for the prepared-staytements it will print it in the text-protocol way.
 */

package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"strconv"
	"time"

	"github.com/xiewen/mysqlcap/mysql"
	"github.com/xiewen/mysqlcap/query"

	_ "github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var port = flag.Int("port", 3306, "port of mysql server")

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

	log.Println("new stream ", net, transport)
	go mstream.readPackets()

	key := fmt.Sprintf("%v:%v", net, transport)
	revKey := fmt.Sprintf("%v:%v", net.Reverse(), transport.Reverse())

	// server to client stream
	if transport.Src().String() == strconv.Itoa(*port) {
		if client, ok := m.source[revKey]; ok {
			log.Println("run ", revKey)
			go client.runClient(mstream.packets)
			delete(m.source, revKey)
		} else {
			// wait client stream
			m.source[key] = mstream
		}
	} else { // client to server stream
		if server, ok := m.source[revKey]; ok {
			log.Println("run ", key)
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
			log.Println(m.net, m.transport, " leave")
			close(m.packets)
			return
		} else if err != nil {
			log.Println("Error reading stream", m.net, m.transport, ":", err)
			close(m.packets)
		} else {
			// log.Println("Received package from stream", m.net, m.transport, " seq: ", seq, " pk:", pk)
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
		fmt.Printf("use %s;\n", payload[1:])
	case mysql.COM_DROP_DB:
		fmt.Printf("DROP DATABASE %s;\n", payload[1:])
	case mysql.COM_CREATE_DB:
		fmt.Printf("CREATE DATABASE %s;\n", payload[1:])
	// just print the query
	case mysql.COM_QUERY:
		fmt.Printf("%s;\n", payload[1:])
		finesql := query.Fingerprint(string(payload[1:]))
		fineid := query.Id(finesql)
		fmt.Printf("#%s %s;\n",fineid,finesql)

	// prepare statements
	// https://dev.mysql.com/doc/internals/en/prepared-statements.html
	case mysql.COM_STMT_PREPARE:
		// find the return stmt_id, so we can know which prepare stmt execute later
		if srvPK == nil {
			log.Println("can't find resp packet from prepare")
			return
		}

		// https://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html#packet-COM_STMT_PREPARE_OK
		if srvPK.payload[0] != 0 {
			log.Println("prepare fail")
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

		log.Println("prepare stmt: ", *stmt)
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
			log.Println("not found stmt id query: ", stmtID)
			return
		}
		fmt.Printf("# exec prepare stmt:  %s;\n", stmt.Query)
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
				log.Println("bind args err: ", err)
				return
			}
		}
		// log.Println("exec smmt: ", *stmt)
		fmt.Println("# binary exec a prepare stmt rewrite it like: ")
		fmt.Println(string(stmt.WriteToText()))
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

	log.SetPrefix("")
	log.SetFlags(0)

	log.Printf("Initializing MySQL capture on %s:%d...", *iface, *port)
	handle, err := pcap.OpenLive(*iface, 65535, false, pcap.BlockForever)
	if handle == nil || err != nil {
		msg := "unknown error"
		if err != nil {
			msg = err.Error()
		}
		log.Fatalf("Failed to open device: %s", msg)
	}

	err = handle.SetBPFFilter(fmt.Sprintf("tcp port %d", *port))
	if err != nil {
		log.Fatalf("Failed to set port filter: %s", err.Error())
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
			if packet == nil {
				return
			}
			// log.Println(packet)
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		case <-ticker:
			// Every Minus, flush connections that haven't seen activity in the past 2 Minute.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
