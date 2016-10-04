package ice

/*
// STUN attributes introduced by the RFC 5245 Section 19.1
const (
	AttrPriority       = uint16(0x0024)
	AttrUseCandidate   = uint16(0x0025)
	AttrIceControlled  = uint16(0x8029)
	AttrIceControlling = uint16(0x802a)
)

var attrNames = map[uint16]string{
	AttrPriority:       "PRIORITY",
	AttrUseCandidate:   "USE-CANDIDATE",
	AttrIceControlled:  "ICE-CONTROLLED",
	AttrIceControlling: "ICE-CONTROLLING",
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
	AttrPriority:       nil,
	AttrUseCandidate:   nil,
	AttrIceControlled:  nil,
	AttrIceControlling: nil,
}

// GetAttributeCodec returns a STUN attribute codec for TURN.
func GetAttributeCodec(at uint16) (c stun.AttrCodec) {
	if c = attrCodecs[at]; c == nil {
		c = stun.GetAttributeCodec(at)
	}
	return
}

// STUN errors codes introduced by the RFC 5245 Section 19.2
const (
	CodeRoleConflict = 487
)

// ErrorText returns a reason phrase text for the STUN error code.
// It returns the empty string if the code is unknown.
func ErrorText(code int) string {
	if code == CodeRoleConflict {
		return "Role Conflict"
	}
	return stun.ErrorText(code)
}
*/
