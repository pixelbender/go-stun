package stun

import (
	"errors"
	"io"
)

var ErrWrongFormat = errors.New("stun: wrong message format")

type Decoder struct {
}

func (dec *Decoder) ReadMessage(b []byte) (*Message, error) {
	if len(b) < 20 {
		return nil, io.EOF
	}
	n, p := getInt16(b[2:]), b[20:]
	if len(p) < n {
		return nil, io.EOF
	}
	msg := &Message{
		Type:       getUint16(b),
		Cookie:     getUint32(b[4:]),
		Attributes: make(map[uint16]Attribute),
	}
	copy(msg.Transaction[:], b[8:20])
	for len(p) > 4 {
		at, an := getUint16(p), getInt16(p[2:])
		m := an
		if mod := n & 3; mod != 0 {
			m += 4 - mod
		}
		if p = p[4:]; len(p) < m {
			return nil, ErrWrongFormat
		}
		msg.Attributes[at], p = RawAttribute(p[:an]), p[an:]
	}

	// TODO: check message integrity + fingerprint

	return msg, nil
}

func getInt16(b []byte) int {
	return int(b[1]) | int(b[0])<<8
}

func getUint16(b []byte) uint16 {
	return uint16(b[1]) | uint16(b[0])<<8
}

func getUint32(b []byte) uint32 {
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}
