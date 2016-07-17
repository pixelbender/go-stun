package stun

import (
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"unicode/utf8"
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

// Attribute is the interface that represents a STUN message attribute.
type Attribute interface {
}

// AttributeCodec interface represents a STUN attribute encoder/decoder.
type AttributeCodec interface {
	Encode(attr Attribute, b []byte) (int, error)
	Decode(b []byte) (Attribute, error)
}

type attrRegistry struct {
	name  string
	codec AttributeCodec
}

var registry = make(map[uint16]*attrRegistry)

func getAttributeCodec(at uint16) AttributeCodec {
	if it, ok := registry[at]; ok {
		return it.codec
	}
	return nil
}

func getAttributeName(at uint16) string {
	if it, ok := registry[at]; ok {
		return it.name
	}
	return strconv.FormatInt(int(at), 16)
}

func Register(at uint16, name string, codec AttributeCodec) {
	if codec == nil {
		codec = defaultCodec
	}
	registry[at] = &attrRegistry{name, codec}
}

// bytesAttribute is raw bytes representation of a message attribute.
type bytesAttribute []byte

func (ba bytesAttribute) String() string {
	if utf8.Valid(ba) {
		return string(ba)
	}
	return hex.EncodeToString(ba)
}

type bytesCodec struct{}

func (codec bytesCodec) Encode(attr Attribute, b []byte) (int, error) {
	switch c := attr.(type) {
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
	return 0, fmt.Errorf("stun: unsupported attribute type: %v", reflect.TypeOf(attr))
}

func (codec bytesCodec) Decode(b []byte) (Attribute, error) {
	return bytesAttribute(b), nil
}

var defaultCodec bytesCodec

func init() {
	// Attributes introduced by the RFC 5389 Section 18.2.
	Register(AttrMappedAddress, "MAPPED-ADDRESS", AddressCodec)
	Register(AttrXorMappedAddress, "XOR-MAPPED-ADDRESS", XorAddressCodec)
	Register(AttrUsername, "USERNAME", nil)
	Register(AttrMessageIntegrity, "MESSAGE-INTEGRITY", nil)
	Register(AttrFingerprint, "FINGERPRINT", nil)
	Register(AttrErrorCode, "ERROR-CODE", defaultErrorCodec)
	Register(AttrRealm, "REALM", nil)
	Register(AttrNonce, "NONCE", nil)
	Register(AttrUnknownAttributes, "UNKNOWN-ATTRIBUTES", nil)
	Register(AttrSoftware, "SOFTWARE", nil)
	Register(AttrAlternateServer, "ALTERNATE-SERVER", AddressCodec)

	// Attributes introduced by the RFC 5780 Section 7.
	Register(AttrChangeRequest, "CHANGE-REQUEST", nil)
	Register(AttrPadding, "PADDING", nil)
	Register(AttrResponsePort, "RESPONSE-PORT", nil)
	Register(AttrResponseOrigin, "RESPONSE-ORIGIN", AddressCodec)
	Register(AttrOtherAddress, "OTHER-ADDRESS", AddressCodec)

	// Attributes introduced by the RFC 3489 Section 11.2 except listed above.
	Register(AttrResponseAddress, "RESPONSE-ADDRESS", AddressCodec)
	Register(AttrSourceAddress, "SOURCE-ADDRESS", AddressCodec)
	Register(AttrChangedAddress, "CHANGED-ADDRESS", AddressCodec)
	Register(AttrPassword, "PASSWORD", nil)
	Register(AttrReflectedFrom, "REFLECTED-FROM", AddressCodec)
}
