package turn

import "github.com/pixelbender/go-stun/stun"

// STUN Attributes introduced by the RFC 5766 Section 14.
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

// STUN Errors introduced by the RFC 5766 Section 15.
const (
	CodeForbidden                    = 403
	CodeAllocationMismatch           = 437
	CodeWrongCredentials             = 441
	CodeUnsupportedTransportProtocol = 442
	CodeAllocationQuotaReached       = 486
	CodeInsufficientCapacity         = 508
)

//
//var attrNames = map[uint16]string{
//	AttrChannelNumber:      "CHANNEL-NUMBER",
//	AttrLifeTime:           "LIFETIME",
//	AttrXorPeerAddress:     "XOR-PEER-ADDRESS",
//	AttrData:               "DATA",
//	AttrXorRelayedAddress:  "XOR-RELAYED-ADDRESS",
//	AttrEvenPort:           "EVEN-PORT",
//	AttrRequestedTransport: "REQUESTED-TRANSPORT",
//	AttrDontFragment:       "DONT-FRAGMENT",
//	AttrReservationToken:   "RESERVATION-TOKEN",
//}

var attrCodecs = map[uint16]stun.AttrCodec{
	AttrXorPeerAddress:    stun.XorAddrCodec,
	AttrXorRelayedAddress: stun.XorAddrCodec,
}

// GetAttributeCodec returns a STUN attribute codec for TURN.
func GetAttributeCodec(at uint16) stun.AttrCodec {
	return attrCodecs[at]
}

var errorText = map[int]string{
	CodeForbidden:                    "Forbidden",
	CodeAllocationMismatch:           "Allocation Mismatch",
	CodeWrongCredentials:             "Wrong Credentials",
	CodeUnsupportedTransportProtocol: "Unsupported Transport Protocol",
	CodeAllocationQuotaReached:       "Allocation Quota Reached",
	CodeInsufficientCapacity:         "Insufficient Capacity",
}

// ErrorText returns a reason phrase text for the STUN error code. It returns the empty string if the code is unknown.
func ErrorText(code int) (v string) {
	if v = errorText[code]; v == "" {
		v = stun.ErrorText(code)
	}
	return
}
