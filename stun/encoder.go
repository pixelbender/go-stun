package stun

import (
	"fmt"
	"io"
)

var defaultBufferSize = 1024

// An Encoder writes and encodes STUN messages to the byte array.
type Encoder struct {
	buf []byte
	pos int
}

// Reset resets the encoder buffer to be empty, but it retains the underlying storage for use by future writes.
func (enc *Encoder) Reset() {
	enc.pos = 0
}

// Bytes returns the byte array representation of the encoded messages.
func (enc *Encoder) Bytes() []byte {
	return enc.buf[:enc.pos]
}

// WriteMessage writes STUN message to the byte array.
func (enc *Encoder) WriteMessage(msg *Message) error {
	if enc.buf == nil {
		enc.buf = make([]byte, 0, defaultBufferSize)
	}
	b := enc.buf[enc.pos:]
	if len(b) < 20 {
		return io.ErrUnexpectedEOF
	}
	putUint16(b, msg.Type)
	putUint32(b[4:], msg.Cookie)
	copy(b[8:], msg.Transaction[:])
	p := b[20:]

	for at, attr := range msg.Attributes {
		if attr == nil {
			return fmt.Errorf("stun: empty attribute 0x%x", at)
		}
		if len(p) < 4 {
			return io.ErrUnexpectedEOF
		}
		a := p[4:]
		n, err := attr.Encode(a)
		if err != nil {
			return err
		}
		if n < 0 || len(a) < n {
			return fmt.Errorf("stun: attribute encoding error 0x%x", at)
		}
		putUint16(p, at)
		putInt16(p[2:], n)
		pad := n
		if mod := n & 3; mod != 0 {
			pad += 4 - mod
		}
		if len(a) < pad {
			return io.ErrUnexpectedEOF
		}
		for i := n; i < pad; i++ {
			a[i] = 0
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
