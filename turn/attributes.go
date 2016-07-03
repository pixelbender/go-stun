package turn

import "github.com/pixelbender/go-stun/stun"

// STUN Attributes introduced by the RFC 5766 Section 14
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

// STUN Errors introduced by the RFC 5766 Section 15
const (
	ErrForbidden                    = 403
	ErrAllocationMismatch           = 437
	ErrWrongCredentials             = 441
	ErrUnsupportedTransportProtocol = 442
	ErrAllocationQuotaReached       = 486
	ErrInsufficientCapacity         = 508
)

var errorText = map[int]string{
	ErrForbidden:                    "Forbidden",
	ErrAllocationMismatch:           "Allocation Mismatch",
	ErrWrongCredentials:             "Wrong Credentials",
	ErrUnsupportedTransportProtocol: "Unsupported Transport Protocol",
	ErrAllocationQuotaReached:       "Allocation Quota Reached",
	ErrInsufficientCapacity:         "Insufficient Capacity",
}

// ErrorText returns a reason phrase text for the STUN error code. It returns the empty string if the code is unknown.
func ErrorText(code int) string {
	if r, ok := errorText[code]; ok {
		return r
	}
	return stun.ErrorText(code)
}
