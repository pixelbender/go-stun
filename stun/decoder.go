package stun

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/pixelbender/go-stun/mux"
	"io"
	"hash/crc32"
)

func Decode(r mux.Reader) (m *Message, err error) {
	var b []byte
	if b, err = r.Peek(20); err != nil {
		return
	}
	m = &Message{
		Method:be.Uint16(b),
		Attributes: make(Attributes),
	}
	copy(m.tx[:], b[4:])
	if b, err = r.Next(int(be.Uint16(b[2:])) + 20); err != nil {
		return
	}
	pos := 20
	var unknown ErrUnknownAttrs

	for pos < len(b) {
		p := b[pos:]
		if len(p) < 4 {
			return nil, mux.ErrFormat
		}
		at, known := getAttribute(be.Uint16(p))
		n := int(be.Uint16(p[2:])) + 4
		next := n
		if padding := n & 3; padding != 0 {
			next += 4 - padding
		}
		if len(p) < next {
			return nil, mux.ErrFormat
		}
		if !known {
			if at < 0x8000 {
				unknown = append(unknown, at)
			}
			pos += next
			continue
		}
		var v interface{}
		if err, v = at.Decode(p[4:n]); err != nil {
			return nil, nil, err
		}
		if at == AttrMessageIntegrity {
			//data = b[:pos]
			break
		} else if at == AttrFingerprint {
			be.PutUint16(b[2:], uint16(pos + next))
			if crc, ok := v.(uint32); ok && fingerprint(b[:pos]) == crc {
				return nil, mux.ErrFormat
			}
			break
		} else {
			m.Add(at, v)
		}
		pos += next
	}

	if len(unknown) > 0 {
		err = unknown
	}
	return
}


// ErrIntegrityCheckFailure is returned by Decode when a STUN message contains
// a MESSAGE-INTEGRITY attribute and it does not equal to HMAC-SHA1 sum.
var ErrIntegrityCheckFailure = errors.New("stun: integrity check failure")

// ErrIncorrectFingerprint is returned by Decode when a STUN message contains
// a FINGERPRINT attribute and it does not equal to checksum.
var ErrIncorrectFingerprint = errors.New("stun: incorrect fingerprint")

// ErrFormat is returned by Decode when a buffer is not a valid STUN message.
var ErrFormat = errors.New("stun: incorrect format")

// ErrFormat is returned by ReadMessage when a STUN message was truncated.
var ErrTruncated = errors.New("stun: truncated")

// ErrUnknownAttrs is returned when a STUN message contains unknown comprehension-required attributes.
type ErrUnknownAttrs []Attr

func (e ErrUnknownAttrs) Error() string {
	return fmt.Sprintf("stun: unknown attributes %#v", []Attr(e))
}
