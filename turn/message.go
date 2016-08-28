package turn

import (
	"encoding/binary"
	"github.com/pixelbender/go-stun/stun"
	"reflect"
)

// STUN methods introduced by the RFC 5766 Section 13.
const (
	MethodAllocate         = uint16(0x3)
	MethodRefresh          = uint16(0x4)
	MethodSend             = uint16(0x6)
	MethodData             = uint16(0x7)
	MethodCreatePermission = uint16(0x8)
	MethodChannelBind      = uint16(0x9)
)

// STUN attributes introduced by the RFC 5766 Section 14.
const (
	AttrChannelNumber      = uint16(0x000c)
	AttrLifeTime           = uint16(0x000d)
	AttrXorPeerAddress     = uint16(0x0012)
	AttrData               = uint16(0x0013)
	AttrXorRelayedAddress  = uint16(0x0016)
	AttrEvenPort           = uint16(0x0018)
	AttrRequestedTransport = uint16(0x0019)
	AttrDontFragment       = uint16(0x001a)
	AttrReservationToken   = uint16(0x0022)
)

var attrNames = map[uint16]string{
	AttrChannelNumber:      "CHANNEL-NUMBER",
	AttrLifeTime:           "LIFETIME",
	AttrXorPeerAddress:     "XOR-PEER-ADDRESS",
	AttrData:               "DATA",
	AttrXorRelayedAddress:  "XOR-RELAYED-ADDRESS",
	AttrEvenPort:           "EVEN-PORT",
	AttrRequestedTransport: "REQUESTED-TRANSPORT",
	AttrDontFragment:       "DONT-FRAGMENT",
	AttrReservationToken:   "RESERVATION-TOKEN",
}

// GetAttributeName returns a STUN attribute name.
// It returns the empty string if the attribute is unknown.
func GetAttributeName(at uint16) (n string) {
	if n = attrNames[at]; n == "" {
		n = stun.GetAttributeName(at)
	}
	return
}

var attrCodecs = map[uint16]stun.AttrCodec{
	AttrChannelNumber:      channelCodec{},
	AttrLifeTime:           uint32Codec{},
	AttrXorPeerAddress:     stun.XorAddrCodec,
	AttrData:               stun.RawCodec,
	AttrXorRelayedAddress:  stun.XorAddrCodec,
	AttrEvenPort:           evenPortCodec{},
	AttrRequestedTransport: transportCodec{},
	AttrDontFragment:       emptyCodec{},
	AttrReservationToken:   stun.RawCodec,
}

// GetAttributeCodec returns a STUN attribute codec for TURN.
func GetAttributeCodec(at uint16) (c stun.AttrCodec) {
	if c = attrCodecs[at]; c == nil {
		c = stun.GetAttributeCodec(at)
	}
	return
}

// STUN errors introduced by the RFC 5766 Section 15.
const (
	CodeForbidden                    = 403
	CodeAllocationMismatch           = 437
	CodeWrongCredentials             = 441
	CodeUnsupportedTransportProtocol = 442
	CodeAllocationQuotaReached       = 486
	CodeInsufficientCapacity         = 508
)

var errorText = map[int]string{
	CodeForbidden:                    "Forbidden",
	CodeAllocationMismatch:           "Allocation Mismatch",
	CodeWrongCredentials:             "Wrong Credentials",
	CodeUnsupportedTransportProtocol: "Unsupported Transport Protocol",
	CodeAllocationQuotaReached:       "Allocation Quota Reached",
	CodeInsufficientCapacity:         "Insufficient Capacity",
}

// ErrorText returns a reason phrase text for the STUN error code.
// It returns the empty string if the code is unknown.
func ErrorText(code int) (r string) {
	if r = errorText[code]; r == "" {
		r = stun.ErrorText(code)
	}
	return
}

var be = binary.BigEndian

type errUnsupportedAttrType struct {
	reflect.Type
}

func (err errUnsupportedAttrType) Error() string {
	return "turn: unsupported attribute type: " + reflect.Type(err).String()
}

type channelCodec struct{}

func (c channelCodec) Encode(w stun.Writer, v interface{}) error {
	if v, ok := v.(uint16); ok {
		be.PutUint32(w.Next(4), uint32(v)<<16)
		return nil
	}
	return &errUnsupportedAttrType{Type: reflect.TypeOf(v)}
}

func (c channelCodec) Decode(r stun.Reader) (interface{}, error) {
	b, err := r.Next(4)
	if err != nil {
		return nil, err
	}
	return be.Uint16(b), nil
}

type uint32Codec struct{}

func (c uint32Codec) Encode(w stun.Writer, v interface{}) error {
	if v, ok := v.(uint32); ok {
		be.PutUint32(w.Next(4), v)
		return nil
	}
	return &errUnsupportedAttrType{Type: reflect.TypeOf(v)}
}

func (c uint32Codec) Decode(r stun.Reader) (interface{}, error) {
	b, err := r.Next(4)
	if err != nil {
		return nil, err
	}
	return be.Uint32(b), nil
}

type evenPortCodec struct{}

func (c evenPortCodec) Encode(w stun.Writer, v interface{}) error {
	if v, ok := v.(uint8); ok {
		w.Next(1)[0] = v
		return nil
	}
	return &errUnsupportedAttrType{Type: reflect.TypeOf(v)}
}

func (c evenPortCodec) Decode(r stun.Reader) (interface{}, error) {
	b, err := r.Next(1)
	if err != nil {
		return nil, err
	}
	return b[0], nil
}

type transportCodec struct{}

func (c transportCodec) Encode(w stun.Writer, v interface{}) error {
	if v, ok := v.(uint8); ok {
		be.PutUint32(w.Next(4), uint32(v)<<24)
		return nil
	}
	return &errUnsupportedAttrType{Type: reflect.TypeOf(v)}
}

func (c transportCodec) Decode(r stun.Reader) (interface{}, error) {
	b, err := r.Next(4)
	if err != nil {
		return nil, err
	}
	return b[0], nil
}

type emptyCodec struct{}

func (c emptyCodec) Encode(w stun.Writer, v interface{}) error {
	return nil
}

func (c emptyCodec) Decode(r stun.Reader) (interface{}, error) {
	return true, nil
}
