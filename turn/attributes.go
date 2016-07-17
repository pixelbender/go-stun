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
	StatusForbidden                    = 403
	StatusAllocationMismatch           = 437
	StatusWrongCredentials             = 441
	StatusUnsupportedTransportProtocol = 442
	StatusAllocationQuotaReached       = 486
	StatusInsufficientCapacity         = 508
)

var statusText = map[int]string{
	StatusForbidden:                    "Forbidden",
	StatusAllocationMismatch:           "Allocation Mismatch",
	StatusWrongCredentials:             "Wrong Credentials",
	StatusUnsupportedTransportProtocol: "Unsupported Transport Protocol",
	StatusAllocationQuotaReached:       "Allocation Quota Reached",
	StatusInsufficientCapacity:         "Insufficient Capacity",
}

// StatusText returns a reason phrase text for the STUN status code. It returns the empty string if the code is unknown.
func StatusText(code int) string {
	if r, ok := statusText[code]; ok {
		return r
	}
	return stun.StatusText(code)
}

func init() {
	stun.Register(AttrChannelNumber, "CHANNEL-NUMBER", nil)
	stun.Register(AttrLifeTime, "LIFETIME", nil)
	stun.Register(AttrXorPeerAddress, "XOR-PEER-ADDRESS", stun.XorAddressCodec)
	stun.Register(AttrData, "DATA", nil)
	stun.Register(AttrXorRelayedAddress, "XOR-RELAYED-ADDRESS", stun.XorAddressCodec)
	stun.Register(AttrEvenPort, "EVEN-PORT", nil)
	stun.Register(AttrRequestedTransport, "REQUESTED-TRANSPORT", nil)
	stun.Register(AttrDontFragment, "DONT-FRAGMENT", nil)
	stun.Register(AttrReservationToken, "RESERVATION-TOKEN", nil)
}
