package stun
// +build ignore
import (
	"bytes"
	"errors"
	"github.com/pixelbender/go-stun/mux"
	"net"
	"time"
	"golang.org/x/net/context"
	"math/rand"
	"encoding/hex"
	"github.com/miekg/coredns/middleware/etcd/msg"
)

// Config represents a STUN connection configuration.
type Config struct {
	// GetAuthKey returns a key for a MESSAGE-INTEGRITY attribute generation and validation.
	// Key = MD5(username ":" realm ":" SASLprep(password)) for long-term credentials.
	// Key = SASLprep(password) for short-term credentials.
	// SASLprep is defined in RFC 4013.
	GetAuthKey            func(m *Message) ([]byte, error)

	// GetAttribute returns STUN attribute for the specified attribute type.
	// If nil, using stun.GetAttribute
	GetAttribute          func(at uint16) Attr

	// If nil, using stun.GetError
	GetError              func(code int) ErrorCode

	// Retransmission timeout, default is 500ms
	RetransmissionTimeout time.Duration

	// Transaction timeout, default is 39.5 seconds
	TransactionTimeout    time.Duration

	// Fingerprint controls whether a FINGERPRINT attribute will be generated.
	Fingerprint           bool

	// Software is a value for SOFTWARE attribute.
	Software              string
}

func (c *Config) getRetransmissionTimeout() time.Duration {
	if c != nil && c.RetransmissionTimeout > 0 {
		return c.RetransmissionTimeout
	}
	return 500 * time.Millisecond
}

func (c *Config) getTransactionTimeout() time.Duration {
	if c != nil && c.TransactionTimeout > 0 {
		return c.TransactionTimeout
	}
	return 39500 * time.Millisecond
}

// A Conn represents the STUN connection and implements the STUN protocol over net.Conn interface.
type Conn struct {
	mux.Conn
	config *Config
	key    []byte
}

// NewConn creates a STUN connection over the net.Conn with specified configuration.
func NewConn(inner net.Conn, config *Config) *Conn {
	m := mux.NewConn(inner)
	c := NewConnMux(m, config)
	//
	return c
}

// NewConnMux creates a STUN connection over the multiplexed connection with specified configuration.
func NewConnMux(m mux.Conn, config *Config) *Conn {
	c := &Conn{Conn: m, config: config}
	m.Handle(c.ServeMux)
	return c
}

func (t *Conn) SendMessage(w mux.Writer, m *Message) error {
	p := t.NewPacket()
	enc := &encoder{Writer:p}
	err = enc.Encode(m)
	return p.Send()
}

func (t *Conn) DecodeMessage(r mux.Reader) (*Message, error) {
	dec := &decoder{Reader:r}
	return dec.Decode()
}

// RoundTrip executes a single STUN transaction, returning a response for the provided request.
func (t *Conn) RoundTrip(req *Message) (*Message, error) {
	return t.RoundTripContext(context.Background(), req)
}

// RoundTrip executes a single STUN transaction, returning a response for the provided request.
func (t *Conn) RoundTripContext(ctx context.Context, req *Message) (msg *Message, err error) {
	var cancel func()

	rto := t.config.getRetransmissionTimeout()
	ctx, cancel = context.WithDeadline(ctx, time.Now().Add(t.config.getTransactionTimeout()))
	req.tx.Reset()

	for {
		if err = t.Send(); err != nil {
			return
		}
		select {
		case r, connected := <-t.ReadMatch(ctx, req.tx.MatchPacket):
			if !connected {
				return nil, ErrCancelled
			}
			if msg, err = t.DecodeMessage(r); err != nil {
				return
			}
		case t.LocalAddr().Network() == "udp" && <-time.After(rto):
			rto <<= 1
		}
	}
	return nil, nil
}

func (c *Conn) ServeMux(t mux.Transport, r mux.Reader) error {
	return nil
}

var ErrTimeout = errors.New("request timeout")
var ErrCancelled = errors.New("request is cancelled")




