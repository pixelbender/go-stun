package stun

import (
	"io"
)

// Attributes introduced by the RFC 5389 Section 18.2.
const (
	AttrMappedAddress     = uint16(0x0001)
	AttrXorMappedAddress  = uint16(0x0020)
	AttrUsername          = uint16(0x0006)
	AttrMessageIntegrity  = uint16(0x0008)
	AttrFingerprint       = uint16(0x8028)
	AttrErrorCode         = uint16(0x0009)
	AttrRealm             = uint16(0x0014)
	AttrNonce             = uint16(0x0015)
	AttrUnknownAttributes = uint16(0x000a)
	AttrSoftware          = uint16(0x8022)
	AttrAlternateServer   = uint16(0x8023)
)

// Attributes introduced by the RFC 3489 Section 11.2 except listed in RFC 5389.
const (
	AttrResponseAddress = uint16(0x0002)
	AttrChangeRequest   = uint16(0x0003)
	AttrSourceAddress   = uint16(0x0004)
	AttrChangedAddress  = uint16(0x0005)
	AttrPassword        = uint16(0x0007)
	AttrReflectedFrom   = uint16(0x000b)
)

// Attributes introduced by the RFC 5780 Section 7.
const (
	AttrPadding        = uint16(0x0026)
	AttrResponsePort   = uint16(0x0027)
	AttrResponseOrigin = uint16(0x802b)
	AttrOtherAddress   = uint16(0x802c)
)

// Attribute is the interface that represents a STUN message attribute.
type Attribute interface {
	// Encode writes the attribute to the byte array.
	Encode(b []byte) (int, error)
}

// RawAttribute is the byte array representation of message attribute.
type RawAttribute []byte

// Encode copies the raw attribute to the byte array.
func (attr RawAttribute) Encode(b []byte) (int, error) {
	if len(b) < len(attr) {
		return 0, io.ErrUnexpectedEOF
	}
	return copy(b, attr), nil
}

// ChangeRequest represents the CHANGE-REQUEST attribute
type ChangeRequest uint8

// ChangeRequest flags
const (
	ChangeIP   = ChangeRequest(0x04)
	ChangePort = ChangeRequest(0x02)
)

// Encode writes the attribute to the byte array.
func (attr ChangeRequest) Encode(b []byte) (int, error) {
	if len(b) < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	b[0] = 0
	b[1] = 0
	b[2] = 0
	b[4] = byte(attr)
	return 4, nil
}

// UnknownAttributes represents the UNKNOWN-ATTRIBUTES attribute
type UnknownAttributes []uint16

// Encode writes the attribute to the byte array.
func (attr UnknownAttributes) Encode(b []byte) (int, error) {
	n := len(attr) << 1
	if len(b) < n {
		return 0, io.ErrUnexpectedEOF
	}
	for i, it := range attr {
		putUint16(b[i<<1:], it)
	}
	return n, nil
}
