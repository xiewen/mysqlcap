package mysql

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"errors"
)

type Stmt struct {
	ID      uint32
	Query   string
	Params  uint16
	Columns uint16

	Args []interface{}
}

var ErrMalformPacket = errors.New("malform packet")

func (s *Stmt) WriteToText() []byte {
	var buf bytes.Buffer

	str := fmt.Sprintf("prepare stmt%d from '%s';\n", s.ID, s.Query)
	buf.WriteString(str)

	for i := 0; i < int(s.Params); i++ {
		var str string
		switch s.Args[i].(type) {
		case nil:
			str = fmt.Sprintf("set @p%v = NULL;\n", i)
		case []byte:
			param := string(s.Args[i].([]byte))
			//str = fmt.Sprintf("set @p%v = '%s';\n", i, strings.TrimSpace(param))
			str = fmt.Sprintf("set @p%v = '%s';\n", i, Escape(param))
		default:
			str = fmt.Sprintf("set @p%v = %v;\n", i, s.Args[i])
		}
		buf.WriteString(str)
	}

	str = fmt.Sprintf("execute stmt%d ", s.ID)
	buf.WriteString(str)
	for i := 0; i < int(s.Params); i++ {
		if i == 0 {
			buf.WriteString(" using ")
		}
		if i > 0 {
			buf.WriteString(", ")
		}
		str := fmt.Sprintf("@p%v", i)
		buf.WriteString(str)
	}
	buf.WriteString(";\n")

	str = fmt.Sprintf("drop prepare stmt%d;\n", s.ID)
	buf.WriteString(str)

	return buf.Bytes()
}

func (s *Stmt) BindStmtArgs(nullBitmap, paramTypes, paramValues []byte) error {
	args := s.Args

	pos := 0

	var v []byte
	var n int = 0
	var isNull bool
	var err error

	for i := 0; i < int(s.Params); i++ {
		if nullBitmap[i>>3]&(1<<(uint(i)%8)) > 0 {
			args[i] = nil
			continue
		}

		tp := paramTypes[i<<1]
		isUnsigned := (paramTypes[(i<<1)+1] & 0x80) > 0

		switch tp {
		case MYSQL_TYPE_NULL:
			args[i] = nil
			continue

		case MYSQL_TYPE_TINY:
			if len(paramValues) < (pos + 1) {
				return ErrMalformPacket
			}
			value := paramValues[pos]
			if isUnsigned {
				args[i] = uint8(value)
			} else {
				args[i] = int8(value)
			}

			pos++
			continue

		case MYSQL_TYPE_SHORT, MYSQL_TYPE_YEAR:
			if len(paramValues) < (pos + 2) {
				return ErrMalformPacket
			}

			value := binary.LittleEndian.Uint16(paramValues[pos : pos+2])
			if isUnsigned {
				args[i] = uint16(value)
			} else {
				args[i] = int16(value)
			}
			pos += 2
			continue

		case MYSQL_TYPE_INT24, MYSQL_TYPE_LONG:
			if len(paramValues) < (pos + 4) {
				return ErrMalformPacket
			}

			value := binary.LittleEndian.Uint32(paramValues[pos : pos+4])
			if isUnsigned {
				args[i] = uint32(value)
			} else {
				args[i] = int32(value)
			}
			pos += 4
			continue

		case MYSQL_TYPE_LONGLONG:
			if len(paramValues) < (pos + 8) {
				return ErrMalformPacket
			}

			value := binary.LittleEndian.Uint64(paramValues[pos : pos+8])
			if isUnsigned {
				args[i] = value
			} else {
				args[i] = int64(value)
			}
			pos += 8
			continue

		case MYSQL_TYPE_FLOAT:
			if len(paramValues) < (pos + 4) {
				return ErrMalformPacket
			}

			value := math.Float32frombits(binary.LittleEndian.Uint32(paramValues[pos : pos+4]))
			args[i] = float32(value)
			pos += 4
			continue

		case MYSQL_TYPE_DOUBLE:
			if len(paramValues) < (pos + 8) {
				return ErrMalformPacket
			}

			value := math.Float64frombits(binary.LittleEndian.Uint64(paramValues[pos : pos+8]))
			args[i] = value
			pos += 8
			continue

		case MYSQL_TYPE_DECIMAL, MYSQL_TYPE_NEWDECIMAL, MYSQL_TYPE_VARCHAR,
			MYSQL_TYPE_BIT, MYSQL_TYPE_ENUM, MYSQL_TYPE_SET, MYSQL_TYPE_TINY_BLOB,
			MYSQL_TYPE_MEDIUM_BLOB, MYSQL_TYPE_LONG_BLOB, MYSQL_TYPE_BLOB,
			MYSQL_TYPE_VAR_STRING, MYSQL_TYPE_STRING, MYSQL_TYPE_GEOMETRY,
			MYSQL_TYPE_DATE, MYSQL_TYPE_NEWDATE,
			MYSQL_TYPE_TIMESTAMP, MYSQL_TYPE_DATETIME, MYSQL_TYPE_TIME:
			if len(paramValues) < (pos + 1) {
				return ErrMalformPacket
			}

			v, isNull, n, err = LengthEncodedString(paramValues[pos:])
			pos += n
			if err != nil {
				return err
			}

			if !isNull {
				args[i] = v
				continue
			} else {
				args[i] = nil
				continue
			}
		default:
			return errors.New(fmt.Sprintf("Stmt Unknown FieldType %d", tp))
		}
	}
	return nil
}
