package stun

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"github.com/pixelbender/go-stun/mux"
	"hash/crc32"
	"io"
	"math/rand"
	"net"
	"strconv"
	"time"
)

const MethodBinding uint16 = 0x0001

// Types of a STUN message.
const (
	TypeRequest    uint16 = 0x0000
	TypeIndication uint16 = 0x0010
	TypeResponse   uint16 = 0x0100
	TypeError      uint16 = 0x0110
)

// Message represents a STUN message.
type Message struct {
	Attributes
	Method uint16
}

// IsType checks if the STUN message corresponds the specified type.
func (m *Message) IsType(t uint16) bool {
	return (m.Method & 0x110) == t
}

type Attributes map[Attr][]interface{}

func (a Attributes) Add(at Attr, v interface{}) {
	a[at] = append(a[at], v)
}

func (a Attributes) Set(at Attr, v interface{}) {
	a[at] = []interface{}{v}
}

func (a Attributes) Get(at Attr) (v interface{}) {
	if l := a[at]; len(l) > 0 {
		v = l[0]
	}
	return
}

func (a Attributes) GetString(at Attr) string {
	switch c := a.Get(at).(type) {
	case []byte:
		return string(c)
	case string:
		return c
	case fmt.Stringer:
		return c.String()
	}
	return ""
}

func (a Attributes) Del(at Attr) {
	delete(a, at)
}

type Packet struct {
	*Message
	Transaction Transaction
	Key         []byte
	Payload     []byte
}

func (p *Packet) Encode(w mux.Writer) (err error) {
	h := w.Header(20)
	crc := false
	for at, it := range p.Attributes {
		switch at {
		case AttrMessageIntegrity:
		case AttrFingerprint:
			crc = true
		default:
			for _, v := range it {
				if err = p.encodeAttribute(w, at, v); err != nil {
					return
				}
			}
		}
	}
	if p.Key != nil {
		p.encodeMessageIntegrity(w, h)
	} else if crc {
		p.encodeFingerprint(w, h)
	}
	b, n := h.Bytes(), h.Payload()
	be.PutUint16(b, p.Method)
	be.PutUint16(b[2:], uint16(n))
	copy(b[4:], p.Transaction)
	return
}

func (p *Packet) encodeMessageIntegrity(w mux.Writer, h mux.Header) {
	a := w.Next(24)
	b, n := h.Bytes(), h.Payload()
	be.PutUint16(b[2:], uint16(n))
	be.PutUint16(a, AttrMessageIntegrity.Type())
	be.PutUint16(a[2:], 20)
	integrity(b[:n-24], p.Key, a[4:4])
}

func (p *Packet) encodeFingerprint(w mux.Writer, h mux.Header) {
	a := w.Next(8)
	b, n := h.Bytes(), h.Payload()
	be.PutUint16(b[2:], uint16(n))
	be.PutUint16(a, AttrFingerprint.Type())
	be.PutUint16(a[2:], 4)
	be.PutUint32(a[4:], fingerprint(b[:n-8]))
}

func (p *Packet) encodeAttribute(w mux.Writer, at Attr, v interface{}) (err error) {
	h := w.Header(4)
	if err = at.Encode(p, w, v); err != nil {
		return
	}
	n := h.Payload()
	if padding := n & 3; padding != 0 {
		b := w.Next(4 - padding)
		for i := range b {
			b[i] = 0
		}
	}
	b := h.Bytes()
	be.PutUint16(b, at.Type())
	be.PutUint16(b[2:], uint16(n))
	return
}

func (p *Packet) Decode(r mux.Reader) (err error) {
	b := r.Bytes()
	if len(b) < 20 {
		return io.EOF
	}
	p.Message = &Message{
		Attributes: make(Attributes),
		Method:     be.Uint16(b),
	}
	p.Transaction = Transaction(b[4:20])
	if b, err = r.Next(int(be.Uint16(b[2:])) + 20); err != nil {
		return
	}
	pos := 20
	var unknown []uint16
	for pos < len(b) {
		a := b[pos:]
		if len(a) < 4 {
			return mux.ErrFormat
		}
		at := be.Uint16(a)
		attr, known := p.config.GetAttribute(at)
		n := int(be.Uint16(a[2:])) + 4
		next := n
		if padding := n & 3; padding != 0 {
			next += 4 - padding
		}
		if len(a) < next {
			return mux.ErrFormat
		}
		if !known {
			if at < 0x8000 {
				unknown = append(unknown, at)
			}
			pos += next
			continue
		}
		var v interface{}
		if v, err = attr.Decode(p, mux.NewReader(a[4:n])); err != nil {
			return err
		}
		p.Add(attr, v)
		if attr == AttrMessageIntegrity {
			be.PutUint16(b[2:], uint16(pos+next-20))
			p.Payload = b[:pos]
			break
		} else if attr == AttrFingerprint {
			be.PutUint16(b[2:], uint16(pos+next-20))
			if p.config.Fingerprint && fingerprint(b[:pos]) != v.(uint32) {
				return ErrIncorrectFingerprint
			}
			break
		}
		pos += next
	}
	if len(unknown) > 0 {
		err = ErrUnknownAttrs(unknown)
	}
	return
}

func (p *Packet) checkMessageIntegrity(key []byte) bool {
	if v, ok := p.Attributes.Get(AttrMessageIntegrity).([]byte); ok {
		return bytes.Equal(integrity(p.Integrity, key, nil), v)
	}
	return false
}

// fingerprint calculates FINGERPRINT attribute value for the STUN message bytes.
// See RFC 5389 Section 15.5
func fingerprint(data []byte) uint32 {
	return crc32.ChecksumIEEE(data) ^ 0x5354554e
}

// integrity calculates MESSAGE-INTEGRITY attribute value for the STUN message bytes.
func integrity(data, key, b []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(b)
}

var be = binary.BigEndian
var magicCookie = []byte{0x21, 0x12, 0xa4, 0x42}
var random = rand.New(rand.NewSource(time.Now().Unix()))

type Transaction []byte

func NewTransaction() Transaction {
	b := make([]byte, 16)
	copy(b, magicCookie)
	random.Read(b[4:])
	return Transaction(b)
}

func (tx Transaction) Reset() {
	random.Read(tx[4:])
}

// Addr represents a transport address.
type Addr struct {
	IP   net.IP
	Port int
}

func (addr *Addr) Network() string {
	return "udp" // TODO: change
}

func (addr *Addr) String() string {
	return net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))
}
