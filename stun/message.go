package stun

import (
	"crypto/rand"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// STUN message types introduced by the RFC 3489 Section 8.
const (
	BindingRequest       = uint16(0x0001)
	BindingResponse      = uint16(0x0101)
	BindingError         = uint16(0x0111)
	SharedSecretRequest  = uint16(0x0002)
	SharedSecretResponse = uint16(0x0102)
	SharedSecretError    = uint16(0x0112)
)

// ErrWrongFormat is returned by ReadMessage when data format is wrong.
var ErrWrongFormat = errors.New("stun: wrong message format")

const magicCookie = uint32(0x2112a442)
const bufferSize = 2048

// Message represents a STUN message.
type Message struct {
	Type        uint16
	Cookie      uint32
	Transaction []byte
	Attributes  map[uint16]Attribute
}

// NewMessage creates a STUN message.
func NewMessage(t uint16, attrs map[uint16]Attribute) *Message {
	m := &Message{
		Type:        t,
		Cookie:      magicCookie,
		Transaction: make([]byte, 12),
		Attributes:  attrs,
	}
	rand.Reader.Read(m.Transaction)
	return m
}

// Encode writes STUN message to the buffer.
// Returns io.ErrUnexpectedEOF error if the buffer length is not enough.
func (msg *Message) Encode(b []byte) (n int, err error) {
	if msg == nil {
		err = errors.New("stun: empty message")
		return
	}
	if len(b) < 20 {
		return 0, io.ErrUnexpectedEOF
	}
	putUint16(b, msg.Type)
	putUint32(b[4:], msg.Cookie)
	copy(b[8:], msg.Transaction)
	p, pos := b[20:], 20

	for at, attr := range msg.Attributes {
		if attr == nil {
			err = fmt.Errorf("stun: empty attribute 0x%x", at)
			return
		}
		if len(p) < 4 {
			err = io.ErrUnexpectedEOF
			return
		}
		ap, an := p[4:], 0
		if an, err = attr.Encode(ap); err != nil {
			return
		}
		if an < 0 || len(ap) < an {
			err = fmt.Errorf("stun: attribute encoding error 0x%x", at)
			return
		}
		putUint16(p, at)
		putInt16(p[2:], an)
		pad := an
		if mod := an & 3; mod != 0 {
			pad += 4 - mod
		}
		if len(ap) < pad {
			err = io.ErrUnexpectedEOF
			return
		}
		for i := an; i < pad; i++ {
			ap[i] = 0
		}
		pos += 4 + pad
		p = ap[pad:]
	}
	return pos, nil
}

// Checksum calculates FINGERPRINT attribute value for the STUN message bytes.
// See RFC 5389 Section 15.5
func Checksum(v []byte) uint32 {
	return crc32.ChecksumIEEE(v) ^ 0x5354554e
}

// ReadMessage reads STUN message from the buffer by wrapping it.
// Returns io.EOF if buffer is empty or message length is greater than buffer length.
func ReadMessage(b []byte) (*Message, error) {
	if len(b) < 20 {
		return nil, io.EOF
	}
	n, p := getInt16(b[2:]), b[20:]
	if len(p) < n {
		return nil, io.EOF
	}
	msg := &Message{
		Type:        getUint16(b),
		Cookie:      getUint32(b[4:]),
		Transaction: b[8:20],
		Attributes:  make(map[uint16]Attribute),
	}
	for len(p) > 4 {
		at, an := getUint16(p), getInt16(p[2:])
		m := an
		if mod := an & 3; mod != 0 {
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
