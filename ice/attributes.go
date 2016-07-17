package ice

import "github.com/pixelbender/go-stun/stun"

// STUN Attributes introduced by the RFC 5245 Section 19.1
const (
	AttrPriority       = uint16(0x0024)
	AttrUseCandidate   = uint16(0x0025)
	AttrIceControlled  = uint16(0x8029)
	AttrIceControlling = uint16(0x802a)
)

// STUN Errors codes introduced by the RFC 5245 Section 19.2
const (
	StatusRoleConflict = 487
)

// ErrorText returns a reason phrase text for the STUN status code. It returns the empty string if the code is unknown.
func StatusText(code int) string {
	if code == StatusRoleConflict {
		return "Role Conflict"
	}
	return stun.StatusText(code)
}

func init() {
	stun.Register(AttrPriority, "PRIORITY", nil)
	stun.Register(AttrUseCandidate, "USE-CANDIDATE", nil)
	stun.Register(AttrIceControlled, "ICE-CONTROLLED", nil)
	stun.Register(AttrIceControlling, "ICE-CONTROLLING", nil)
}
