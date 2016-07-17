package stun

import (
	"crypto/md5"
	"crypto/rand"
	"hash/crc32"
	"io"
)

// STUN message types introduced by the RFC 3489 Section 8.
const (
	BindingRequest      = uint16(0x0001)
	SharedSecretRequest = uint16(0x0002)
)

const (
	typeIndication = uint16(0x0010)
	typeResponse   = uint16(0x0100)
	typeError      = uint16(0x0110)
	typeMask       = uint16(0x0110)
)

const magicCookie = uint32(0x2112a442)
const bufferSize = 1400

// Attributes represents a set of STUN attributes.
type Attributes map[uint16]Attribute

// Message represents a STUN message.
type Message struct {
	Type        uint16
	Cookie      uint32
	Transaction []byte
	Attributes  Attributes
}

// NewMessage creates a STUN message.
func NewMessage(t uint16, attrs map[uint16]Attribute) *Message {
	m := &Message{
		Type:        t,
		Cookie:      magicCookie,
		Transaction: make([]byte, 12),
		Attributes:  Attributes(attrs),
	}
	rand.Read(m.Transaction)
	return m
}

// DecodeMessage reads STUN message from the buffer.
// Returns io.EOF if buffer is empty or message length is greater than buffer length.
func DecodeMessage(b []byte, key func(attr Attributes) []byte) (*Message, error) {
	if len(b) < 20 {
		return nil, io.EOF
	}
	n := getInt16(b[2:]) + 20
	if len(b) < n {
		return nil, io.EOF
	}
	buf := make([]byte, n)
	copy(buf, b)
	msg := &Message{
		Type:        getUint16(buf),
		Cookie:      getUint32(buf[4:]),
		Transaction: buf[8:20],
		Attributes:  make(Attributes),
	}
	p, pos := buf[20:], 20

	return msg, nil
}

//
//func LongTermKey(username, realm, password []byte) []byte {
//	s := md5.New()
//	s.Write(username)
//	s.Write(colon)
//	s.Write(realm)
//	s.Write(colon)
//	s.Write(password)
//	return s.Sum(nil)
//}
//
//func ShortTermKey(password []byte) []byte {
//	s := md5.New()
//	s.Write(password)
//	return s.Sum(nil)
//}
