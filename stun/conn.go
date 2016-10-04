package stun

import (
	"io"
	"net"
	"time"
	"bytes"
	"crypto/rand"
	"sync"
	"errors"
	"github.com/pixelbender/go-stun/mux"
	"net/http"
	"crypto/hmac"
	"crypto/sha1"
	"github.com/prometheus/common/config"
)


// A Conn represents the STUN connection and implements the STUN protocol over net.Conn interface.
type Conn struct {
	mux.Conn
	config *Config
	key    []byte
}

// NewConn creates a STUN connection over the net.Conn with specified configuration.
func NewConn(inner net.Conn, config *Config) *Conn {
	c := &Conn{}
	m := &mux.Mux{}
	c.Conn = mux.ServeConn(inner, m)
	m.Handle()
	return NewConnMux(mux.ServeConn(inner, m), m, config)
}

// NewConnMux creates a STUN connection over the multiplexed connection with specified configuration.
func NewConnMux(c mux.Conn, config *Config) *Conn {
	return &Conn{Conn:c, config:config}
}

func (c *Conn) Handle(c mux.Conn, r mux.Reader) error {

}

// Decode reads and decodes the STUN message from r.
// Returns ErrUnknownAttrs if the STUN message contains comprehension-required attributes that are not decoded.
// Ignores optional attributes if not decoded.
func (c *Conn) Decode(r mux.Reader, key []byte) (m *Message, err error) {
	var b []byte
	if b, err = r.Peek(20); err != nil {
		return
	}
	n := int(be.Uint16(b[2:])) + 20
	if r, err = r.Reader(n); err != nil {
		return
	}
	m = &Message{
		Method:      be.Uint16(b),
		Transaction: b[4:20],
	}
	var unknown ErrUnknownAttrs
	var ar mux.Reader
	b = r.Bytes()
	r.Next(20)
	p := 20
	for r.Buffered() > 4 {
		ah, _ := r.Next(4)
		at, n := be.Uint16(ah), int(be.Uint16(ah[2:]) + 4)
		if ar, err = r.Reader(n); err != nil {
			return
		}
		if attr := c.config.GetAttribute(at); attr == nil {
			if at < 0x8000 {
				unknown = append(unknown, at)
			}
		} else if err = attr.Decode(m, ar); err != nil {
			return
		} else if attr == AttrMessageIntegrity {
			be.PutUint16(b[2:], uint16(p + 4))
			m.raw = b[:p]
			break
		} else if attr == AttrFingerprint {
			be.PutUint16(b[2:], uint16(p + 12))
			m.raw = b[:p]
			break
		}
		if pad := n & 3; pad != 0 {
			p += n + 8 - pad
		} else {
			p += n + 4
		}
	}
	if len(unknown) > 0 {
		err = unknown
	}
	return
}

func (c *Conn) Encode(w mux.Writer, m *Message) (err error) {
	h := w.Header(20)
	b := h.Bytes()
	be.PutUint16(b, m.Method)
	copy(b[4:], m.Transaction)

	for at, v := range m.Attributes {
		if at == AttrFingerprint || at == AttrMessageIntegrity {
			continue
		}
		ah := w.Header(4)
		if err = at.Encode(m, v, w); err != nil {
			return
		}
		b = ah.Bytes()
		be.PutUint16(b, at.Type())
		be.PutUint16(b[2:], uint16(ah.Payload()))

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
}

func (c *Conn) EncodeAttribute(w mux.Writer, m *Message) (err error) {

}

var ErrTimeout = errors.New("request timeout")
var ErrCancelled = errors.New("request is cancelled")
