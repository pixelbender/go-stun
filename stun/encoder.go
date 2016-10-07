package stun

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"hash/crc32"
	"github.com/pixelbender/go-stun/mux"
)

type encoder struct {
	mux.Writer
	key []byte
	fingerprint bool
}

func (enc *encoder) Encode(m *Message) (err error) {
	h := enc.Header(20)
	crc := enc.fingerprint
	for at, it := range m.Attributes {
		switch at {
		case AttrMessageIntegrity:
		case AttrFingerprint:
			crc = true
		default:
			for _, v := range it {
				if err = enc.encodeAttribute(at, v); err != nil {
					return
				}
			}
		}
	}
	if enc.key != nil {
		enc.encodeMessageIntegrity(h)
	} else if crc {
		enc.encodeFingerprint(h)
	}
	b := h.Bytes()
	be.PutUint16(b, m.Method)
	be.PutUint16(b[2:], uint16(h.Payload()))
	copy(b[4:], m.tx)
	return
}

func (enc *encoder) encodeMessageIntegrity(h mux.Header) {
	p := enc.Next(24)
	b, n := h.Bytes(), h.Payload()
	be.PutUint16(b[2:], uint16(n))
	be.PutUint16(p, AttrMessageIntegrity.Type())
	be.PutUint16(p[2:], 20)
	integrity(b[:n - 24], enc.key, p[4:4])
}

func (enc *encoder) encodeFingerprint(h mux.Header) {
	p := enc.Next(8)
	b, n := h.Bytes(), h.Payload()
	be.PutUint16(b[2:], uint16(n))
	be.PutUint16(p, AttrFingerprint.Type())
	be.PutUint16(p[2:], 4)
	be.PutUint32(p[4:], fingerprint(b[:n - 8]))
}

func (enc *encoder) encodeAttribute(at Attr, v interface{}) (err error) {
	h := enc.Header(4)
	if err = at.Encode(enc, v); err != nil {
		return
	}
	n := h.Payload()
	if padding := n & 3; padding != 0 {
		b := enc.Next(4 - padding)
		for i := range b {
			b[i] = 0
		}
	}
	b := h.Bytes()
	be.PutUint16(b, at.Type())
	be.PutUint16(b[2:], uint16(n))
	return
}

// fingerprint calculates FINGERPRINT attribute value for the STUN message bytes.
// See RFC 5389 Section 15.5
func fingerprint(v []byte) uint32 {
	return crc32.ChecksumIEEE(v) ^ 0x5354554e
}

// integrity calculates MESSAGE-INTEGRITY attribute value for the STUN message bytes.
func integrity(v, key, r []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(v)
	return h.Sum(r)
}
