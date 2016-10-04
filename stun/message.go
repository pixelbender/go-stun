package stun

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"github.com/pixelbender/go-stun/mux"
	"github.com/ugorji/go/codec"
	"io"
	"net"
)

const methodBinding uint16 = 0x0001

// Types of a STUN message.
const (
	TypeRequest    uint16 = 0x0000
	TypeIndication uint16 = 0x0010
	TypeResponse   uint16 = 0x0100
	TypeError      uint16 = 0x0110
)

type Attr interface {
	Type() uint16
	Decode(m *Message, r mux.Reader) error
	Encode(m *Message, v interface{}, w mux.Writer) error
	String() string
}

type Error interface {
	Code() int
	Error() string
}

// Message represents a STUN message.
type Message struct {
	Method      uint16
	Transaction []byte
	Attributes  map[Attr]interface{}
	Key []byte
}

// NewTransaction regenerates transaction id or creates it if does not exist.
func (m *Message) NewTransaction() {
	if len(m.Transaction) < 16 {
		b := make([]byte, 16)
		b[0], b[1], b[2], b[3] = 0x21, 0x12, 0xa4, 0x42
		m.Transaction = b
	}
	rand.Read(m.Transaction[4:])
}

func (m *Message) UnmarshalBinary(b []byte) error {
	if len(b) < 4 {
		return io.EOF
	}
	n := int(be.Uint16(b[2:])) + 20
	if len(b) < n {
		return io.EOF
	}
	b = b[:n]
	m := &Message{
		Method:      be.Uint16(b),
		Transaction: b[4:20], // ??
	}
	copy(m.Transaction[])
	p := 20

	var unk []uint16

	for len(b) > 4 {
		at, n := be.Uint16(d), int(be.Uint16(d[2:])+4)
		// Padding
		s := n
		if mod := n & 3; mod != 0 {
			s = n + 4 - mod
		}
		if len(d) < s {
			return nil, io.EOF
		}
		buf := d[4:n]
		d = d[s:]
		codec := dec.getAttrCodec(at)
		if codec == nil {
			if at < 0x8000 {
				unk = append(unk, at)
			}
			p += s
			continue
		}
		attr, err := codec.Decode(&reader{msg: r.buf, buf: buf})
		if err != nil {
			return nil, err
		}
		m.Attributes[at] = attr
		switch at {
		case AttrMessageIntegrity:
			be.PutUint16(h[2:], uint16(p+4))
			if key == nil {
				key, err = dec.getAuthKey(m.Attributes)
				if err != nil {
					return nil, err
				}
			}
			sum := integrity(r.buf[:p], key)
			if !bytes.Equal(attr.([]byte), sum) {
				return nil, ErrIntegrityCheckFailure
			}
			m.Key = key
			d = nil
		case AttrFingerprint:
			be.PutUint16(h[2:], uint16(p-12))
			crc := fingerprint(r.buf[:p])
			if attr.(uint32) != crc {
				return nil, ErrIncorrectFingerprint
			}
			d = nil
		}
		p += s
	}
	if unk != nil {
		return m, &ErrUnknownAttrs{unk}
	}
	return m, nil
}

func (m *Message) Encode(w mux.Writer) (err error) {
	s := w.Len()
	h := w.Next(20)
	be.PutUint16(h, m.Method)
	copy(h[4:], m.Transaction)

	fingerprint := false
	for at, v := range m.Attributes {
		if at == AttrFingerprint {
			fingerprint = true
			continue
		}
		b := w.Next(4)
		p := w.Len()
		if err = at.Encode(m, w, v); err != nil {
			return
		}
		n := w.Len() - p
		be.PutUint16(b, at.Type())
		be.PutUint16(b[2:], uint16(n))

		// Padding
		if mod := n & 3; mod != 0 {
			b = w.Next(4 - mod)
			for i := range b {
				b[i] = 0
			}
		}
	}

	if m.Key != nil {
		data := w.Bytes()[s:]
		p := w.Next(24)
		b := w.Bytes()[s:]
		be.PutUint16(b[2:], uint16(len(b)-20))
		be.PutUint16(p, AttrMessageIntegrity)
		be.PutUint16(p[2:], 20)
		integrity(data, m.Key, p[4:4])
	} else if fingerprint {
		data := w.Bytes()[s:]
		p := w.Next(8)
		b := w.Bytes()[s:]
		be.PutUint16(b[2:], uint16(len(b)-20))
		be.PutUint16(p, AttrFingerprint)
		be.PutUint16(p[2:], 4)
		be.PutUint32(p[4:], fingerprint(data))
	} else {
		b := w.Bytes()[s:]
		be.PutUint16(b[2:], uint16(len(b)-20))
	}

	return nil
}

// IsType checks if the STUN message corresponds the specified type.
func (m *Message) IsType(t uint16) bool {
	return (m.Method & 0x110) == t
}

type errNoAttr Attr

func (e errNoAttr) Error() string {
	return "stun: no attribute " + Attr(e).String()
}

