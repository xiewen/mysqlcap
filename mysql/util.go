package mysql

import (
	"bytes"
	"encoding/binary"
	"io"
	"time"
)

func GetNowStr(isClient bool) string {
	var msg string
	msg += time.Now().Format("2006-01-02 15:04:05")
	if isClient {
		msg += "| cli -> ser |"
	}else{
		msg += "| ser -> cli |"
	}
	return msg
}

func ReadStringFromByte(b []byte) (string,int) {

	var l int
	l = bytes.IndexByte(b, 0x00)
	if l == -1 {
		l = len(b)
	}
	return string(b[0:l]), l
}

func LengthBinary(b []byte) (uint32, int) {

	var first = int(b[0])
	if first > 0 && first <= 250 {
		return uint32(first), 1
	}
	if first == 251 {
		return 0,1
	}
	if first == 252 {
		return binary.LittleEndian.Uint32(b[1:2]),1
	}
	if first == 253 {
		return binary.LittleEndian.Uint32(b[1:4]),3
	}
	if first == 254 {
		return binary.LittleEndian.Uint32(b[1:9]),8
	}
	return 0,0
}

func LengthEncodedInt(b []byte) (num uint64, isNull bool, n int) {
	switch b[0] {

	// 251: NULL
	case 0xfb:
		n = 1
		isNull = true
		return

	// 252: value of following 2
	case 0xfc:
		num = uint64(b[1]) | uint64(b[2])<<8
		n = 3
		return

	// 253: value of following 3
	case 0xfd:
		num = uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16
		n = 4
		return

	// 254: value of following 8
	case 0xfe:
		num = uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16 |
			uint64(b[4])<<24 | uint64(b[5])<<32 | uint64(b[6])<<40 |
			uint64(b[7])<<48 | uint64(b[8])<<56
		n = 9
		return
	}

	// 0-250: value of first byte
	num = uint64(b[0])
	n = 1
	return
}

func LengthEncodedString(b []byte) ([]byte, bool, int, error) {
	// Get length
	num, isNull, n := LengthEncodedInt(b)
	if num < 1 {
		return nil, isNull, n, nil
	}

	n += int(num)

	// Check data length
	if len(b) >= n {
		return b[n-int(num) : n], false, n, nil
	}
	return nil, false, n, io.EOF
}

func SkipLengthEncodedString(b []byte) (int, error) {
	// Get length
	num, _, n := LengthEncodedInt(b)
	if num < 1 {
		return n, nil
	}

	n += int(num)

	// Check data length
	if len(b) >= n {
		return n, nil
	}
	return n, io.EOF
}

var (
	DONTESCAPE = byte(255)

	EncodeMap [256]byte
)

func Escape(sql string) string {
	dest := make([]byte, 0, 2*len(sql))

	for i := 0; i < len(sql); i++ {
		w := sql[i]
		if c := EncodeMap[w]; c == DONTESCAPE {
			dest = append(dest, w)
		} else {
			dest = append(dest, '\\', c)
		}
	}

	return string(dest)
}

var encodeRef = map[byte]byte{
	'\x00': '0',
	'\'':   '\'',
	'"':    '"',
	'\b':   'b',
	'\n':   'n',
	'\r':   'r',
	'\t':   't',
	26:     'Z', // ctl-Z
	'\\':   '\\',
}

func init() {
	for i := range EncodeMap {
		EncodeMap[i] = DONTESCAPE
	}
	for i := range EncodeMap {
		if to, ok := encodeRef[byte(i)]; ok {
			EncodeMap[byte(i)] = to
		}
	}
}
