package stun

import (
	"io"
)

var defaultBufferSize = 1024

type Encoder struct {
	buf []byte
	pos int
}

func (enc *Encoder) Reset() {
	enc.pos = 0
}

func (enc *Encoder) Bytes() []byte {
	return enc.buf[:enc.pos]
}

func (enc *Encoder) WriteMessage(msg *Message) error {
	if enc.buf == nil {
		enc.buf = make([]byte, 0, defaultBufferSize)
	}
	b := enc.buf[enc.pos:]
	if len(b) < 20 {
		return io.EOF
	}
	putInt16(b, msg.Type)
	putUint32(b[4:], msg.Cookie)
	copy(b[8:], msg.Transaction[:])
	p := b[20:]

	for at, attr := range msg.Attributes {
		if len(p) < 4 {
			return nil, io.EOF
		}
		a := p[4:]
		n, err := attr.Encode(a)
		if err != nil {
			return err
		}
		putUint16(p, at)
		putInt16(p[2:], n)
		if mod := n & 3; mod != 0 {
			for i := 4 - mod; i > 0; i-- {
				a[n] = 0
				n++
			}
		}
		p = a[n:]
	}

	// TODO: create message integrity + fingerprint

	return nil
}

func putInt16(b []byte, v int) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func putUint16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func putUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}
