package stun

import (
	"crypto/rand"
	"hash/crc32"
)

const (
	BindingRequest       = uint16(0x0001)
	BindingResponse      = uint16(0x0101)
	BindingError         = uint16(0x0111)
	SharedSecretRequest  = uint16(0x0002)
	SharedSecretResponse = uint16(0x0102)
	SharedSecretError    = uint16(0x0112)
)

var magicCookie = []byte{0x21, 0x12, 0xa4, 0x42}

type Message struct {
	Type        uint16
	Cookie      uint32
	Transaction [12]byte
	Attributes  map[uint16]Attribute
}

func NewMessage(t uint16, attrs map[uint16]Attribute) *Message {
	m := &Message{
		Type:       t,
		Cookie:     magicCookie,
		Attributes: attrs,
	}
	rand.Reader.Read(m.Transaction[:])
	return m
}

func Checksum(v []byte) uint32 {
	return crc32.ChecksumIEEE(v) ^ 0x5354554e
}
