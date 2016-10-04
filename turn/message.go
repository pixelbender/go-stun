package turn

import (
	"encoding/binary"
	"fmt"
	"github.com/pixelbender/go-stun/mux"
	"github.com/pixelbender/go-stun/stun"
	"golang.org/x/tools/go/gcimporter15/testdata"
	"io"
	"net"
	"reflect"
	"strconv"
	"time"
)

const (
	// TURN allocation transport types
	allocUDP uint8 = 17
	allocTCP uint8 = 6
)

const (
	// TURN methods introduced by the RFC 5766 Section 13.
	methodAllocate         uint16 = 0x3
	methodRefresh          uint16 = 0x4
	methodSend             uint16 = 0x6
	methodData             uint16 = 0x7
	methodCreatePermission uint16 = 0x8
	methodChannelBind      uint16 = 0x9

	// TURN methods introduced by the RFC 6062 Section 6.1.
	methodConnect        uint16 = 0xa
	methodConnectionBind uint16 = 0xb
	methodSend           uint16 = 0xc
)

const (
	// TURN attributes introduced by the RFC 5766 Section 14.
	attrChannelNumber      attr = 0x000c
	attrLifeTime           attr = 0x000d
	attrXorPeerAddress     attr = 0x0012
	attrData               attr = 0x0013
	attrXorRelayedAddress  attr = 0x0016
	attrEvenPort           attr = 0x0018
	attrRequestedTransport attr = 0x0019
	attrDontFragment       attr = 0x001a
	attrReservationToken   attr = 0x0022

	// TURN attribute introduced by the RFC 6062 Section 6.2.
	attrConnectionId attr = 0x000c
)

var attrNames = map[attr]string{
	attrChannelNumber:      "CHANNEL-NUMBER",
	attrLifeTime:           "LIFETIME",
	attrXorPeerAddress:     "XOR-PEER-ADDRESS",
	attrData:               "DATA",
	attrXorRelayedAddress:  "XOR-RELAYED-ADDRESS",
	attrEvenPort:           "EVEN-PORT",
	attrRequestedTransport: "REQUESTED-TRANSPORT",
	attrDontFragment:       "DONT-FRAGMENT",
	attrReservationToken:   "RESERVATION-TOKEN",
	attrConnectionId:       "CONNECTION-ID",
}

type attr uint16

func (at attr) Decode(m *stun.Message, r mux.Reader) (v interface{}, err error) {
	var b []byte
	switch at {
	case attrChannelNumber:
		if b, err = r.Next(4); err == nil {
			v = be.Uint16(b)
		}
	case attrLifeTime:
		if b, err = r.Next(4); err == nil {
			v = time.Second * time.Duration(be.Uint32(b))
		}
	case attrXorPeerAddress, attrXorRelayedAddress:
		v, err = stun.AttrXorMappedAddress.Decode(r)
	case attrEvenPort:
		if b, err = r.Next(1); err == nil {
			v = b[0]&0x80 != 0
		}
	case attrRequestedTransport:
		if b, err = r.Next(4); err == nil {
			v = b[0]
		}
	case attrDontFragment:
		v = true
	case attrData, attrReservationToken:
		v, err = r.Next(r.Buffered())
	case attrConnectionId:
		if b, err = r.Next(4); err == nil {
			v = be.Uint32(b)
		}
	}
	return
}

func (at attr) Encode(m *stun.Message, v interface{}, w mux.Writer) error {
	if raw, ok := v.([]byte); ok {
		w.Write(raw)
	}
	switch at {
	case attrChannelNumber:
		be.PutUint32(w.Next(4), uint32(v.(uint16))<<16)
	case attrLifeTime:
		be.PutUint32(w.Next(4), uint32(v.(time.Duration).Seconds()))
	case attrXorPeerAddress, attrXorRelayedAddress:
		stun.AttrXorMappedAddress.Encode(v, w)
	case attrEvenPort:
		if v.(bool) == true {
			w.Next(1)[0] = 0x80
		} else {
			w.Next(1)[0] = 0
		}
	case attrRequestedTransport:
		be.PutUint32(w.Next(4), uint32(v.(uint8))<<24)
	case attrConnectionId:
		be.PutUint32(w.Next(4), v.(uint32))
	}
}

func (at attr) String() string {
	if v, ok := attrNames[at]; ok {
		return v
	}
	return fmt.Sprintf("0x%4x", at)
}

type message stun.Message

const (
	// STUN errors introduced by the RFC 5766 Section 15.
	ErrForbidden                    code = 403
	ErrAllocationMismatch           code = 437
	ErrWrongCredentials             code = 441
	ErrUnsupportedTransportProtocol code = 442
	ErrAllocationQuotaReached       code = 486
	ErrInsufficientCapacity         code = 508

	// STUN errors introduced by the RFC 6062 Section 6.3.
	ErrConnectionAlreadyExists    code = 446
	ErrConnectionTimeoutOrFailure code = 447
)

var errorText = map[code]string{
	ErrForbidden:                    "Forbidden",
	ErrAllocationMismatch:           "Allocation mismatch",
	ErrWrongCredentials:             "Wrong credentials",
	ErrUnsupportedTransportProtocol: "Unsupported transport protocol",
	ErrAllocationQuotaReached:       "Allocation quota reached",
	ErrInsufficientCapacity:         "Insufficient capacity",
	ErrConnectionAlreadyExists:      "Connection already exists",
	ErrConnectionTimeoutOrFailure:   "Connection timeout or failure",
}

type code int

func (c code) Code() int {
	return int(c)
}

func (c code) Error() string {
	return errorText[c]
}

var be = binary.BigEndian

type errAttr attr

func (e errAttr) Error() string {
	return "turn: attribute error " + attr.String()
}
