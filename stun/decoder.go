package stun

import (
	"errors"
	"fmt"
)

//
// ErrIntegrityCheckFailure is returned by Decode when a STUN message contains
// a MESSAGE-INTEGRITY attribute and it does not equal to HMAC-SHA1 sum.
var ErrIntegrityCheckFailure = errors.New("stun: integrity check failure")

// ErrIncorrectFingerprint is returned by Decode when a STUN message contains
// a FINGERPRINT attribute and it does not equal to checksum.
var ErrIncorrectFingerprint = errors.New("stun: incorrect fingerprint")

//
//// ErrFormat is returned by Decode when a buffer is not a valid STUN message.
//var ErrFormat = errors.New("stun: incorrect format")
//
//// ErrFormat is returned by ReadMessage when a STUN message was truncated.
//var ErrTruncated = errors.New("stun: truncated")
//

// ErrUnknownAttrs is returned when a STUN message contains unknown comprehension-required attributes.
type ErrUnknownAttrs []uint16

func (e ErrUnknownAttrs) Error() string {
	return fmt.Sprintf("stun: unknown attributes %#v", []uint16(e))
}
