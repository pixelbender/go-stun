package stun

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strconv"
)

// ErrUnauthorized is returned by Decode when GetAuthKey is defined
// but a STUN request does not contain a MESSAGE-INTEGRITY attribute.
var ErrUnauthorized = errors.New("stun: unauthorized")

// ErrIntegrityCheckFailure is returned by Decode when a STUN message contains
// a MESSAGE-INTEGRITY attribute and it does not equal to HMAC-SHA1 sum.
var ErrIntegrityCheckFailure = errors.New("stun: integrity check failure")

// ErrIncorrectFingerprint is returned by Decode when a STUN message contains
// a FINGERPRINT attribute and it does not equal to checksum.
var ErrIncorrectFingerprint = errors.New("stun: incorrect fingerprint")

// ErrFormat is returned by Decode when a buffer is not a valid STUN message.
var ErrFormat = errors.New("stun: incorrect format")

// ErrUnknownAttrs is returned when a STUN message contains unknown comprehension-required attributes.
type ErrUnknownAttrs []uint16

func (e ErrUnknownAttrs) Error() string {
	return fmt.Sprintf("stun: unknown attributes %#v", []uint16(e))
}

// MessageCodec represents a STUN message encoder/decoder.
// GetAuthKey is required for MESSAGE-INTEGRITY generation.
// GetAuthKey must return a key for HMAC-SHA1 sum for a MESSAGE-INTEGRITY attribute.
// LongTermKey returns key = MD5(username ":" realm ":" SASLprep(password)) for long-term credentials.
// ShortTermKey returns key = SASLprep(password) for short-term credentials.
// SASLprep is defined in RFC 4013.
type MessageCodec struct {
	GetAuthKey        func(attrs Attributes) []byte
	GetAttributeCodec func(at uint16) AttrCodec
	Fingerprint       bool
}

// Encode writes STUN message to the buffer.
// Generates MESSAGE-INTEGRITY attribute if GetAuthKey is specified.
// Adds FINGERPRINT attribute if Fingerprint is true.
func (codec *MessageCodec) Encode(m *Message, b []byte) (int, error) {
	if m.Transaction == nil {
		m.Transaction = newTransaction()
	}
	if m.Key == nil && codec != nil && codec.GetAuthKey != nil {
		m.Key = codec.GetAuthKey(m.Attributes)
	}
	putUint16(b, m.Method)
	copy(b[4:], m.Transaction)
	p, n := b[20:], 20
	for attr, v := range m.Attributes {
		s, err := codec.putAttribute(m, attr, v, p)
		if err != nil {
			return 0, err
		}
		p, n = p[s:], n+s
	}
	if m.Key != nil {
		putInt16(b[2:], n+4)
		s, err := codec.putMessageIntegrity(b[:n], m.Key, p)
		if err != nil {
			return 0, err
		}
		return n + s, nil
	}
	if codec != nil && codec.Fingerprint {
		putInt16(b[2:], n-12)
		s, err := codec.putFingerprint(b[:n], p)
		if err != nil {
			return 0, err
		}
		return n + s, nil
	}
	putInt16(b[2:], n-20)
	return n, nil
}

func (codec *MessageCodec) putAttribute(msg *Message, attr uint16, v interface{}, b []byte) (int, error) {
	if len(b) < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	c := attrCodecs[attr]
	if c == nil && codec != nil && codec.GetAttributeCodec != nil {
		c = codec.GetAttributeCodec(attr)
	}
	if c == nil {
		c = DefaultAttrCodec
	}
	s, err := c.Encode(msg, v, b[4:])
	if err != nil {
		return 0, err
	}
	n := s + 4
	if s < 0 || len(b) < n {
		return 0, errAttrEncode(attr)
	}
	putUint16(b, attr)
	putInt16(b[2:], s)

	// Padding
	mod := s & 3
	if mod == 0 {
		return n, nil
	}
	pad := n + 4 - mod
	if len(b) < pad {
		return 0, io.ErrUnexpectedEOF
	}
	for i := n; i < pad; i++ {
		b[i] = 0
	}
	return pad, nil
}

func (codec *MessageCodec) putMessageIntegrity(msg, key, b []byte) (int, error) {
	if len(b) < 24 {
		return 0, io.ErrUnexpectedEOF
	}
	putUint16(b, AttrMessageIntegrity)
	putInt16(b[2:], 20)
	h := hmac.New(sha1.New, key)
	h.Write(msg)
	h.Sum(b[4:])
	return 24, nil
}

func (codec *MessageCodec) putFingerprint(msg, b []byte) (int, error) {
	if len(b) < 8 {
		return 0, io.ErrUnexpectedEOF
	}
	putUint16(b, AttrFingerprint)
	putInt16(b[2:], 4)
	putUint32(b[4:], checksum(msg))
	return 8, nil
}

// Decode reads STUN message from the buffer.
// Checks MESSAGE-INTEGRITY attribute if GetAuthKey is specified.
// Checks FINGERPRINT attribute if present.
// Returns io.EOF if the buffer size is not enough.
// Returns ErrUnknownAttrs containing unknown comprehension-required STUN attributes.
func (codec *MessageCodec) Decode(bb []byte) (*Message, error) {
	if len(bb) < 20 {
		return nil, io.EOF
	}
	s := getInt16(bb[2:]) + 20
	if len(bb) < s {
		return nil, io.EOF
	}
	b := make([]byte, s)
	copy(b, bb[:s])

	m := &Message{
		Method:      getUint16(b),
		Transaction: b[4:20],
		Attributes:  make(Attributes),
	}

	buf, n, checked := b[20:], 20, false
	var unk ErrUnknownAttrs

	for len(buf) > 4 {
		attr, s := getUint16(buf), getInt16(buf[2:])
		mod, pad := s&3, s+4
		if mod != 0 {
			pad += 4 - mod
		}
		if len(buf) < pad {
			return nil, errAttrDecode(attr)
		}
		c := attrCodecs[attr]
		if c == nil && codec != nil && codec.GetAttributeCodec != nil {
			c = codec.GetAttributeCodec(attr)
		}
		if c == nil {
			if attr < 0x8000 {
				unk = append(unk, attr)
			}
			c = DefaultAttrCodec
		}
		v, err := c.Decode(m, buf[4:s+4])
		if err != nil {
			return nil, err
		}
		m.Attributes[attr] = v
		if attr == AttrMessageIntegrity {
			putInt16(b[2:], n+4)
			if codec != nil && codec.GetAuthKey != nil {
				m.Key = codec.GetAuthKey(m.Attributes)
			}
			if err = codec.checkMessageIntegrity(b[:n], m.Key, v.([]byte)); err != nil {
				return nil, err
			}
			checked = true
			break
		}
		if attr == AttrFingerprint {
			if s != 4 {
				return nil, errAttrDecode(attr)
			}
			putInt16(b[2:], n-12)
			if v.(uint32) != checksum(b[:n]) {
				return nil, ErrIncorrectFingerprint
			}
			break
		}
		buf, n = buf[pad:], n+pad
	}
	if !checked && codec != nil && codec.GetAuthKey != nil {
		return nil, ErrUnauthorized
	}
	if unk != nil {
		return m, unk
	}
	return m, nil
}

func (codec *MessageCodec) checkMessageIntegrity(msg, key, v []byte) error {
	if len(v) != 20 {
		return errAttrDecode(AttrMessageIntegrity)
	}
	h := hmac.New(sha1.New, key)
	h.Write(msg)
	if !bytes.Equal(v, h.Sum(nil)) {
		return ErrIntegrityCheckFailure
	}
	return nil
}

type errAttrEncode uint16

func (e errAttrEncode) Error() string {
	return "stun: attribute encode error: 0x" + strconv.FormatUint(uint64(e), 16)
}

type errAttrDecode uint16

func (e errAttrDecode) Error() string {
	return "stun: attribute decode error: 0x" + strconv.FormatUint(uint64(e), 16)
}

type errAttrNoCodec uint16

func (e errAttrNoCodec) Error() string {
	return "stun: attribute codec not found: 0x" + strconv.FormatUint(uint64(e), 16)
}

type uintCodec struct{}

func (uintCodec) Encode(msg *Message, attr interface{}, b []byte) (int, error) {
	if len(b) < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	switch v := attr.(type) {
	case uint32:
		putUint32(b, v)
	case int:
		putUint32(b, uint32(v))
	}
	return DefaultAttrCodec.Encode(msg, attr, b)
}

func (uintCodec) Decode(msg *Message, b []byte) (interface{}, error) {
	if len(b) < 4 {
		return nil, io.EOF
	}
	return getUint32(b), nil
}

const magicCookie = uint32(0x2112a442)

func newTransaction() (tx []byte) {
	tx = make([]byte, 16)
	putUint32(tx, magicCookie)
	rand.Read(tx[4:])
	return
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
