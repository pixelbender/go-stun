package stun

import (
	"io"
)

// RFC 5389 Section 18.2
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

// RFC 3489 Section 11.2
const (
	AttrResponseAddress = uint16(0x0002)
	AttrChangeRequest   = uint16(0x0003)
	AttrSourceAddress   = uint16(0x0004)
	AttrChangedAddress  = uint16(0x0005)
	AttrPassword        = uint16(0x0007)
	AttrReflectedFrom   = uint16(0x000b)
)

// RFC 5780 Section 7
const (
	AttrPadding        = uint16(0x0026)
	AttrResponsePort   = uint16(0x0027)
	AttrResponseOrigin = uint16(0x802b)
	AttrOtherAddress   = uint16(0x802c)
)

type Attribute interface {
	Encode(b []byte) (int, error)
}

type RawAttribute []byte

func (attr RawAttribute) Encode(b []byte) (int, error) {
	if len(b) < len(attr) {
		return 0, io.EOF
	}
	return copy(b, attr), nil
}

type ChangeRequest uint8

const (
	ChangeIP   = ChangeRequest(0x04)
	ChangePort = ChangeRequest(0x02)
)

func (attr ChangeRequest) Encode(b []byte) (int, error) {
	if len(b) < 4 {
		return 0, io.EOF
	}
	b[0] = 0
	b[1] = 0
	b[2] = 0
	b[4] = uint32(attr)
	return 4, nil
}

type UnknownAttributes []uint16

func (attr UnknownAttributes) Encode(b []byte) (int, error) {
	n := len(attr) << 1
	if len(b) < n {
		return 0, io.EOF
	}
	for i, it := range attr {
		putUint16(b[i<<1:], it)
	}
	return n, nil
}
