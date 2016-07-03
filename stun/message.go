package stun

import (
	"crypto/rand"
	"hash/crc32"
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

const magicCookie = uint32(0x2112a442)

// Message represents a STUN message.
type Message struct {
	Type        uint16
	Cookie      uint32
	Transaction [12]byte
	Attributes  map[uint16]Attribute
}

// NewMessage creates a STUN message.
func NewMessage(t uint16, attrs map[uint16]Attribute) *Message {
	m := &Message{
		Type:       t,
		Cookie:     magicCookie,
		Attributes: attrs,
	}
	rand.Reader.Read(m.Transaction[:])
	return m
}

// Checksum calculates FINGERPRINT attribute value for the previous STUN message bytes
// See RFC 5389 Section 15.5
func Checksum(v []byte) uint32 {
	return crc32.ChecksumIEEE(v) ^ 0x5354554e
}
