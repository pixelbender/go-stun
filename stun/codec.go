package stun

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"hash/crc32"
	"io"
)

// AuthProvider returns a key for HMAC-SHA1 sum used in a MESSAGE-INTEGRITY attribute.
// For long-term credentials: key = MD5(username ":" realm ":" SASLprep(password)).
// For short-term credentials: key = SASLprep(password).
// SASLPrep is described in RFC 4013.
type AuthProvider func(attrs Attributes) []byte

// MessageCodec represents a STUN message encoder/decoder.
type MessageCodec struct {
	AuthProvider AuthProvider
	Fingerprint  bool
}

// Encode writes STUN message to the buffer.
// Generates MESSAGE-INTEGRITY attribute if AuthProvider is specified.
// Generates FINGERPRINT attribute if Fingerprint is true.
// Returns io.ErrUnexpectedEOF if the buffer size is not enough.
func (codec *MessageCodec) Encode(msg *Message, b []byte) (int, error) {
	if len(b) < 20 {
		return nil, io.ErrUnexpectedEOF
	}

	putUint16(b, msg.Type)
	putUint32(b[4:], msg.Cookie)
	copy(b[8:], msg.Transaction)
	p, pos := b[20:], 20

	var key []byte
	if ap := codec.AuthProvider; ap != nil {
		key = ap(msg.Attributes)
	}

	for at, attr := range msg.Attributes {
		if attr == nil {
			continue
		}
		if len(p) < 4 {
			return nil, io.ErrUnexpectedEOF
		}
		ap := p[4:]
		c := getAttributeCodec(at)
		if c == nil {
			return nil, fmt.Errorf("stun: attribute codec is not registered 0x%x", at)
		}
		an, err := c.Encode(attr, ap)
		if err != nil {
			return nil, err
		}
		pad := an
		if mod := an & 3; mod != 0 {
			pad += 4 - mod
		}
		if an < 0 || len(ap) < pad {
			return nil, fmt.Errorf("stun: attribute codec error 0x%x", at)
		}
		putUint16(p, at)
		putInt16(p[2:], an)
		for i := an; i < pad; i++ {
			ap[i] = 0
		}
		p, pos = ap[pad:], pos+pad+4
	}

	if key != nil {
		if len(p) < 24 {
			return nil, io.ErrUnexpectedEOF
		}
		putUint16(p, AttrMessageIntegrity)
		putInt16(p[2:], 20)
		h := hmac.New(sha1.New, key)
		h.Write(b[:pos])
		h.Sum(p[4:])
		p, pos = p[24:], pos+24
	}

	if codec.Fingerprint {
		if len(p) < 8 {
			return nil, io.ErrUnexpectedEOF
		}
		putUint16(p, AttrFingerprint)
		putInt16(p[2:], 4)
		putUint32(p[4:], checksum(b[:pos]))
		p, pos = p[8:], pos+8
	}

	return pos, nil
}

// Decode reads STUN message from the buffer wrapping it.
// Checks MESSAGE-INTEGRITY attribute if AuthProvider is specified.
// Checks FINGERPRINT attribute if present.
// Returns io.EOF if the buffer size is not enough.
func (codec *MessageCodec) Decode(b []byte) (*Message, error) {
	if len(b) < 20 {
		return nil, io.EOF
	}
	n := getInt16(b[2:]) + 20
	if len(b) < n {
		return nil, io.EOF
	}

	var integrity, sum []byte
	var unk ErrUnknownAttributes

	msg := &Message{
		Type:        getUint16(b),
		Cookie:      getUint32(b[4:]),
		Transaction: b[8:20],
		Attributes:  make(Attributes),
	}
	p, pos := b[20:], 20

	for len(p) > 4 {
		at, an := getUint16(p), getInt16(p[2:])
		pad := an
		if mod := an & 3; mod != 0 {
			pad += 4 - mod
		}
		if p = p[4:]; len(p) < pad {
			return nil, ErrBadFormat
		}
		c := getAttributeCodec(at)
		if c == nil {
			unk = append(unk, at)
			continue
		}
		if at == AttrMessageIntegrity && integrity == nil {
			if an != 20 {
				return nil, ErrBadFormat
			}
			integrity = b[:pos]
			sum = p[:an]
			break
		} else if at == AttrFingerprint {
			if an != 4 {
				return nil, ErrBadFormat
			}
			if getUint32(p) != checksum(b[:pos]) {
				return nil, ErrBadFormat
			}
			break
		}
		attr, err := c.Decode(p[:an])
		if err != nil {
			return nil, err
		}
		msg.Attributes[at] = attr
		p, pos = p[pad:], pos+pad+4
	}

	if ap := codec.AuthProvider; ap != nil {
		key := ap(msg.Attributes)
		h := hmac.New(sha1.New, key)
		h.Write(integrity)
		if !bytes.Equal(sum, h.Sum(nil)) {
			return nil, ErrUnauthorized
		}
	}

	if unk != nil {
		return nil, unk
	}
	return msg, nil
}

// checksum calculates FINGERPRINT attribute value for the STUN message bytes.
// See RFC 5389 Section 15.5
func checksum(v []byte) uint32 {
	return crc32.ChecksumIEEE(v) ^ 0x5354554e
}

func getInt16(b []byte) int {
	return int(b[1]) | int(b[0])<<8
}

func getUint16(b []byte) uint16 {
	return uint16(b[1]) | uint16(b[0])<<8
}

func getUint32(b []byte) uint32 {
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}

func putInt16(b []byte, v int) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func putUint16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func putUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}
