package ice

import "github.com/pixelbender/go-stun/stun"

// STUN Attributes introduced by the RFC 5245 Section 19.1
const (
	AttrPriority       = uint16(0x0024)
	AttrUseCandidate   = uint16(0x0025)
	AttrIceControlled  = uint16(0x8029)
	AttrIceControlling = uint16(0x802a)
)

// STUN Errors introduced by the RFC 5245 Section 19.2
const (
	ErrRoleConflict = 487
)

var errorText = map[int]string{
	ErrRoleConflict: "Role Conflict",
}

// ErrorText returns a reason phrase text for the STUN error code. It returns the empty string if the code is unknown.
func ErrorText(code int) string {
	if r, ok := errorText[code]; ok {
		return r
	}
	return stun.ErrorText(code)
}
