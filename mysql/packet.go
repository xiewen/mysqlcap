package mysql

import (
	"bytes"
	"io"

	"errors"
)

const (
	MaxPayloadLen int = 1<<24 - 1
)

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html
// return the seq and payload of package
func ReadPacket(r io.Reader) (uint8, []byte, error) {
	var buf bytes.Buffer

	if seq, err := ReadPacketTo(r, &buf); err != nil {
		return 0, nil, err
	} else {
		return seq, buf.Bytes(), nil
	}
}

func ReadPacketTo(r io.Reader, w io.Writer) (uint8, error) {
	header := make([]byte, 4)
	var seq uint8

	if nread, err := io.ReadFull(r, header); err != nil {
		if nread == 0 && err == io.EOF {
			return 0, io.EOF
		}
		return 0, errors.New("bad conn")
	}

	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	seq = header[3]

	if n, err := io.CopyN(w, r, int64(length)); err != nil {
		return 0, errors.New("bad conn")
	} else if n != int64(length) {
		return 0, errors.New("bad conn")
	} else {
		if length < MaxPayloadLen {
			return seq, nil
		}

		// handle the case packet more than 16Mb
		if _, err := ReadPacketTo(r, w); err != nil {
			return 0, err
		}
	}

	return seq, nil
}
