/*
 * mysqlcap.go
 */

package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/xiewen/mysqlcap/query"

	_ "github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// Internal tuning
	timeBuckets = 10000

	// ANSI colors
	colorRED     = "\x1b[31m"
	colorGREEN   = "\x1b[32m"
	colorYELLOW  = "\x1b[33m"
	colorCYAN    = "\x1b[36m"
	colorWHITE   = "\x1b[37m"
	colorDEFAULT = "\x1b[39m"

	// MySQL packet types
	comQUERY = 3

	// These are used for formatting outputs
	fNONE = iota
	fQUERY
	fROUTE
	fSOURCE
	fSOURCEIP
)

type packet struct {
	request bool // request or response
	data    []byte
}

type sortable struct {
	value float64
	line  string
}
type sortableSlice []sortable

type source struct {
	src       string
	srcip     string
	synced    bool
	reqbuffer []byte
	resbuffer []byte
	reqSent   *time.Time
	reqTimes  [timeBuckets]uint64
	qbytes    uint64
	qdata     *queryData
	qtext     string
}

type queryData struct {
	count uint64
	bytes uint64
	times [timeBuckets]uint64
}

func unixNow() int64 {
	return time.Now().Unix()
}

var (
	start      = unixNow()
	qbuf       = make(map[string]*queryData)
	querycount int
	chmap      = make(map[string]*source)
	verbose    = false
	noclean    = false
	dirty      = false
	format     []interface{}
	port       uint16
	times      [timeBuckets]uint64
)

var stats struct {
	packets struct {
		rcvd     uint64
		rcvdSync uint64
	}
	desyncs uint64
	streams uint64
}

func main() {
	lport := flag.Int("P", 3306, "MySQL port to use")
	eth := flag.String("i", "eth0", "Interface to sniff")
	ldirty := flag.Bool("u", false, "Unsanitized -- do not canonicalize queries")
	period := flag.Int("t", 10, "Seconds between outputting status")
	displaycount := flag.Int("d", 15, "Display this many queries in status updates")
	doverbose := flag.Bool("v", false, "Print every query received (spammy)")
	nocleanquery := flag.Bool("n", false, "no clean queries")
	formatstr := flag.String("f", "#s:#q", "Format for output aggregation")
	sortby := flag.String("s", "count", "Sort by: count, max, avg, maxbytes, avgbytes")
	cutoff := flag.Int("c", 0, "Only show queries over count/second")
	flag.Parse()

	verbose = *doverbose
	noclean = *nocleanquery
	port = uint16(*lport)
	dirty = *ldirty
	parseFormat(*formatstr)
	rand.Seed(time.Now().UnixNano())

	log.SetPrefix("")
	log.SetFlags(0)

	log.Printf("Initializing MySQL capture on %s:%d...", *eth, port)
	handle, err := pcap.OpenLive(*eth, 1024, false, pcap.BlockForever)
	if handle == nil || err != nil {
		msg := "unknown error"
		if err != nil {
			msg = err.Error()
		}
		log.Fatalf("Failed to open device: %s", msg)
	}

	err = handle.SetBPFFilter(fmt.Sprintf("tcp port %d", port))
	if err != nil {
		log.Fatalf("Failed to set port filter: %s", err.Error())
	}
	defer handle.Close()

	last := unixNow()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	for packet := range packetSource.Packets() {
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			fmt.Println("unexpected packet")
			continue
		}
		handlePacket(packet)
		// simple output printer... this should be super fast since we expect that a
		// system like this will have relatively few unique queries once they're
		// canonicalized.
		if !verbose && querycount%1000 == 0 && last < unixNow()-int64(*period) {
			last = unixNow()
			handleStatusUpdate(*displaycount, *sortby, *cutoff)
		}
	}
}

func calculateTimes(timings *[timeBuckets]uint64) (fmin, favg, fmax float64) {
	var counts, total, min, max, avg uint64 = 0, 0, 0, 0, 0
	hasMin := false
	for _, val := range *timings {
		if val == 0 {
			// Queries should never take 0 nanoseconds. We are using 0 as a
			// trigger to mean 'uninitialized reading'.
			continue
		}
		if val < min || !hasMin {
			hasMin = true
			min = val
		}
		if val > max {
			max = val
		}
		counts++
		total += val
	}
	if counts > 0 {
		avg = total / counts // integer division
	}
	return float64(min) / 1000000, float64(avg) / 1000000,
		float64(max) / 1000000
}

func handleStatusUpdate(displaycount int, sortby string, cutoff int) {
	elapsed := float64(unixNow() - start)

	// print status bar
	log.Printf("\n")
	log.SetFlags(log.Ldate | log.Ltime)
	log.Printf("%s%d total queries, %0.2f per second%s", colorRED, querycount,
		float64(querycount)/elapsed, colorDEFAULT)
	log.SetFlags(0)

	log.Printf("%d packets (%0.2f%% on synchronized streams) / %d desyncs / %d streams",
		stats.packets.rcvd, float64(stats.packets.rcvdSync)/float64(stats.packets.rcvd)*100,
		stats.desyncs, stats.streams)

	// global timing values
	gmin, gavg, gmax := calculateTimes(&times)
	log.Printf("%0.2fms min / %0.2fms avg / %0.2fms max query times", gmin, gavg, gmax)
	log.Printf("%d unique results in this filter", len(qbuf))
	log.Printf(" ")
	log.Printf("%s count     %sqps     %s  min    avg   max      %sbytes      per qry%s",
		colorYELLOW, colorCYAN, colorYELLOW, colorGREEN, colorDEFAULT)

	// we cheat so badly here...
	tmp := make(sortableSlice, 0, len(qbuf))
	for q, c := range qbuf {
		qps := float64(c.count) / elapsed
		if qps < float64(cutoff) {
			continue
		}

		qmin, qavg, qmax := calculateTimes(&c.times)
		bavg := uint64(float64(c.bytes) / float64(c.count))

		sorted := float64(c.count)
		if sortby == "avg" {
			sorted = qavg
		} else if sortby == "max" {
			sorted = qmax
		} else if sortby == "maxbytes" {
			sorted = float64(c.bytes)
		} else if sortby == "avgbytes" {
			sorted = float64(bavg)
		}

		tmp = append(tmp, sortable{sorted, fmt.Sprintf(
			"%s%6d  %s%7.2f/s  %s%6.2f %6.2f %6.2f  %s%9db %6db %s%s%s",
			colorYELLOW, c.count, colorCYAN, qps, colorYELLOW, qmin, qavg, qmax,
			colorGREEN, c.bytes, bavg, colorWHITE, q, colorDEFAULT)})
	}
	sort.Sort(tmp)

	// now print top to bottom, since our sorted list is sorted backwards
	// from what we want
	if len(tmp) < displaycount {
		displaycount = len(tmp)
	}
	for i := 1; i <= displaycount; i++ {
		log.Printf(tmp[len(tmp)-i].line)
	}
}

// Do something with a packet for a source.
func processPacket(rs *source, request bool, data []byte) {
	//		log.Printf("[%s] request=%t, got %d bytes", rs.src, request,
	//			len(data))

	stats.packets.rcvd++
	if rs.synced {
		stats.packets.rcvdSync++
	}

	ptype := -1
	var pdata []byte

	if request {
		// If we still have response buffer, we're in some weird state and
		// didn't successfully process the response.
		if rs.resbuffer != nil {
			//				log.Printf("[%s] possibly pipelined request? %d bytes",
			//					rs.src, len(rs.resbuffer))
			stats.desyncs++
			rs.resbuffer = nil
			rs.synced = false
		}
		rs.reqbuffer = data
		ptype, pdata = carvePacket(&rs.reqbuffer)
	} else {
		// FIXME: For now we're not doing anything with response data, just using the first packet
		// after a query to determine latency.
		rs.resbuffer = nil
		ptype, pdata = 0, data
	}

	// The synchronization logic: if we're not presently, then we want to
	// keep going until we are capable of carving off of a request/query.
	if !rs.synced {
		if !(request && ptype == comQUERY) {
			rs.reqbuffer, rs.resbuffer = nil, nil
			return
		}
		rs.synced = true
	}
	//log.Printf("[%s] request=%b ptype=%d plen=%d", rs.src, request, ptype, len(pdata))

	// No (full) packet detected yet. Continue on our way.
	if ptype == -1 {
		return
	}
	plen := uint64(len(pdata))

	// If this is a response then we want to record the timing and
	// store it with this channel so we can keep track of that.
	var reqtime uint64
	if !request {
		// Keep adding the bytes we're getting, since this is probably still part of
		// an earlier response
		if rs.reqSent == nil {
			if rs.qdata != nil {
				rs.qdata.bytes += plen
			}
			return
		}
		reqtime = uint64(time.Since(*rs.reqSent).Nanoseconds())

		// We keep track of per-source, global, and per-query timings.
		randn := rand.Intn(timeBuckets)
		rs.reqTimes[randn] = reqtime
		times[randn] = reqtime
		if rs.qdata != nil {
			// This should never fail but it has. Probably because of a
			// race condition I need to suss out, or sharing between
			// two different goroutines. :(
			rs.qdata.times[randn] = reqtime
			rs.qdata.bytes += plen
		}
		rs.reqSent = nil

		// If we're in verbose mode, just dump statistics from this one.
		if verbose && len(rs.qtext) > 0 {
			log.Printf("    %s%s %s## %sbytes: %d time: %0.2f%s\n", colorGREEN, rs.qtext, colorRED,
				colorYELLOW, rs.qbytes, float64(reqtime)/1000000, colorDEFAULT)
		}

		return
	}

	// This is for sure a request, so let's count it as one.
	if rs.reqSent != nil {
		//			log.Printf("[%s] ...sending two requests without a response?",
		//				rs.src)
	}
	tnow := time.Now()
	rs.reqSent = &tnow

	// Convert this request into whatever format the user wants.
	querycount++
	var text string

	for _, item := range format {
		switch item.(type) {
		case int:
			switch item.(int) {
			case fNONE:
				log.Fatalf("fNONE in format string")
			case fQUERY, fROUTE:
				sql := string(pdata)
				if dirty {
					text += sql
				} else {
					s := query.Fingerprint(sql)
					text += s
				}
			case fSOURCE:
				text += rs.src
			case fSOURCEIP:
				text += rs.srcip
			default:
				log.Fatalf("Unknown F_XXXXXX int in format string")
			}
		case string:
			text += item.(string)
		default:
			log.Fatalf("Unknown type in format string")
		}
	}
	qdata, ok := qbuf[text]
	if !ok {
		qdata = &queryData{}
		qbuf[text] = qdata
	}
	qdata.count++
	qdata.bytes += plen
	rs.qtext, rs.qdata, rs.qbytes = text, qdata, plen
}

// carvePacket tries to pull a packet out of a slice of bytes. If so, it removes
// those bytes from the slice.
func carvePacket(buf *[]byte) (int, []byte) {
	datalen := uint32(len(*buf))
	if datalen < 5 {
		return -1, nil
	}

	size := uint32((*buf)[0]) + uint32((*buf)[1])<<8 + uint32((*buf)[2])<<16
	if size == 0 || datalen < size+4 {
		return -1, nil
	}

	// Else, has some length, try to validate it.
	end := size + 4
	ptype := int((*buf)[4])
	data := (*buf)[5 : size+4]
	if end >= datalen {
		*buf = nil
	} else {
		*buf = (*buf)[end:]
	}

	//	log.Printf("datalen=%d size=%d end=%d ptype=%d data=%d buf=%d",
	//		datalen, size, end, ptype, len(data), len(*buf))

	return ptype, data
}

// extract the data... we have to figure out where it is, which means extracting data
// from the various headers until we get the location we want.  this is crude, but
// functional and it should be fast.
func handlePacket(packet gopacket.Packet) {
	// https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
	// https://blog.csdn.net/u014762921/article/details/78275428
	ip := packet.NetworkLayer().(*layers.IPv4)
	srcIP := ip.SrcIP
	dstIP := ip.DstIP
	tcp := packet.TransportLayer().(*layers.TCP)
	srcPort := tcp.SrcPort
	dstPort := tcp.DstPort
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer == nil {
		return
	}
	// This is either an inbound or outbound packet. Determine by seeing which
	// end contains our port. Either way, we want to put this on the channel of
	// the remote end.
	var src string
	request := false
	if srcPort == layers.TCPPort(port) {
		src = fmt.Sprintf("%s:%d", dstIP, dstPort)
		//log.Printf("response to %s", src)
	} else if dstPort == layers.TCPPort(port) {
		src = fmt.Sprintf("%s:%d", srcIP, srcPort)
		request = true
		//log.Printf("request from %s", src)
	} else {
		log.Fatalf("got packet src = %d, dst = %d", srcPort, dstPort)
	}

	// Get the data structure for this source, then do something.
	rs, ok := chmap[src]
	if !ok {
		srcip := src[0:strings.Index(src, ":")]
		rs = &source{src: src, srcip: srcip, synced: false}
		stats.streams++
		chmap[src] = rs
	}

	// Now with a source, process the packet.
	processPacket(rs, request, applicationLayer.Payload())
}

// parseFormat takes a string and parses it out into the given format slice
// that we later use to build up a string. This might actually be an overcomplicated
// solution?
func parseFormat(formatstr string) {
	formatstr = strings.TrimSpace(formatstr)
	if formatstr == "" {
		formatstr = "#b:#k"
	}

	isSpecial := false
	curstr := ""
	doAppend := fNONE
	for _, char := range formatstr {
		if char == '#' {
			if isSpecial {
				curstr += string(char)
				isSpecial = false
			} else {
				isSpecial = true
			}
			continue
		}

		if isSpecial {
			switch strings.ToLower(string(char)) {
			case "s":
				doAppend = fSOURCE
			case "i":
				doAppend = fSOURCEIP
			case "r":
				doAppend = fROUTE
			case "q":
				doAppend = fQUERY
			default:
				curstr += "#" + string(char)
			}
			isSpecial = false
		} else {
			curstr += string(char)
		}

		if doAppend != fNONE {
			if curstr != "" {
				format = append(format, curstr, doAppend)
				curstr = ""
			} else {
				format = append(format, doAppend)
			}
			doAppend = fNONE
		}
	}
	if curstr != "" {
		format = append(format, curstr)
	}
}

func (s sortableSlice) Len() int {
	return len(s)
}

func (s sortableSlice) Less(i, j int) bool {
	return s[i].value < s[j].value
}

func (s sortableSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
