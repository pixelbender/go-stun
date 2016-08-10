package stun

import (
	"fmt"
	"io"
	"reflect"
)

// Attributes introduced by the RFC 5389 Section 18.2.
const (
	AttrMappedAddress     = uint16(0x0001)
	AttrXorMappedAddress  = uint16(0x0020)
	AttrUsername          = uint16(0x0006)
	AttrMessageIntegrity  = uint16(0x0008)
	AttrErrorCode         = uint16(0x0009)
	AttrRealm             = uint16(0x0014)
	AttrNonce             = uint16(0x0015)
	AttrUnknownAttributes = uint16(0x000a)
	AttrSoftware          = uint16(0x8022)
	AttrAlternateServer   = uint16(0x8023)
	AttrFingerprint       = uint16(0x8028)
)

// Attributes introduced by the RFC 5780 Section 7.
const (
	AttrChangeRequest  = uint16(0x0003)
	AttrPadding        = uint16(0x0026)
	AttrResponsePort   = uint16(0x0027)
	AttrResponseOrigin = uint16(0x802b)
	AttrOtherAddress   = uint16(0x802c)
)

// Attributes introduced by the RFC 3489 Section 11.2 except listed above.
const (
	AttrResponseAddress = uint16(0x0002)
	AttrSourceAddress   = uint16(0x0004)
	AttrChangedAddress  = uint16(0x0005)
	AttrPassword        = uint16(0x0007)
	AttrReflectedFrom   = uint16(0x000b)
)

// AttrCodec interface represents a STUN attribute encoder/decoder.
type AttrCodec interface {
	Encode(msg *Message, v interface{}, b []byte) (int, error)
	Decode(msg *Message, b []byte) (interface{}, error)
}

var attrCodecs = map[uint16]AttrCodec{
	AttrMappedAddress:     AddrCodec,
	AttrXorMappedAddress:  XorAddrCodec,
	AttrUsername:          DefaultAttrCodec,
	AttrMessageIntegrity:  DefaultAttrCodec,
	AttrErrorCode:         errorCodec{},
	AttrRealm:             DefaultAttrCodec,
	AttrNonce:             DefaultAttrCodec,
	AttrUnknownAttributes: nil,
	AttrSoftware:          DefaultAttrCodec,
	AttrAlternateServer:   AddrCodec,
	AttrFingerprint:       uintCodec{},
	AttrChangeRequest:     uintCodec{},
	AttrPadding:           DefaultAttrCodec,
	AttrResponsePort:      nil,
	AttrResponseOrigin:    AddrCodec,
	AttrOtherAddress:      AddrCodec,
	AttrResponseAddress:   AddrCodec,
	AttrSourceAddress:     AddrCodec,
	AttrChangedAddress:    AddrCodec,
	AttrPassword:          DefaultAttrCodec,
	AttrReflectedFrom:     AddrCodec,
}

// DefaultAttrCodec decodes a STUN attribute as []byte.
// Encodes []byte or string using copy.
var DefaultAttrCodec attrCodec

type attrCodec struct{}

func (attrCodec) Encode(msg *Message, v interface{}, b []byte) (int, error) {
	switch c := v.(type) {
	case []byte:
		if len(b) < len(c) {
			return 0, io.ErrUnexpectedEOF
		}
		return copy(b, c), nil
	case string:
		if len(b) < len(c) {
			return 0, io.ErrUnexpectedEOF
		}
		return copy(b, c), nil
	}
	return 0, errUnsupportedAttr{reflect.TypeOf(v)}
}

func (attrCodec) Decode(msg *Message, b []byte) (interface{}, error) {
	return b, nil
}

type errUnsupportedAttr struct {
	reflect.Type
}

func (e errUnsupportedAttr) Error() string {
	return "stun: unsupported attribute type: " + reflect.Type(e).String()
}

// Attributes represents a set of STUN attributes.
type Attributes map[uint16]interface{}

func (at Attributes) String(id uint16) string {
	r, ok := at[id]
	if ok {
		switch v := r.(type) {
		case []byte:
			return string(v)
		case string:
			return v
		case (fmt.Stringer):
			return v.String()
		default:
			return fmt.Sprintf("%", r)
		}
	}
	return ""
}
