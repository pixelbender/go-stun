package stun

import (
	"bytes"
	"errors"
	"github.com/pixelbender/go-stun/mux"
	"io"
	"math/rand"
	"net"
	"time"
)

var ErrTimeout = errors.New("stun: transaction timeout")
var ErrBadResponse = errors.New("stun: bad response")

type Config struct {
	// GetAuthKey returns a key for a MESSAGE-INTEGRITY attribute generation and validation.
	// Key = MD5(username ":" realm ":" SASLprep(password)) for long-term credentials.
	// Key = SASLprep(password) for short-term credentials.
	// SASLprep is defined in RFC 4013.
	GetAuthKey func(m *Message) ([]byte, error)

	// Retransmission timeout, default is 500ms
	RetransmissionTimeout time.Duration

	// Transaction timeout, default is 39.5 seconds
	TransactionTimeout time.Duration

	AdditionalAttributes []Attr
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

func (c *Config) setAttributes(m *Message) {
	if c != nil {
		m.Attributes = append(m.Attributes, c.AdditionalAttributes...)
	}
}

type Conn struct {
	mux.Conn
	config *Config
}

func NewConn(inner net.Conn, config *Config) *Conn {
	return &Conn{mux.NewConn(inner, &mux.Mux{}), config}
}

func (c *Conn) Discover() (*Addr, error) {
	res, err := c.RoundTrip(&Message{Type: MethodBinding})
	if err != nil {
		return nil, err
	}
	if err := res.GetError(); err != nil {
		return nil, err
	}
	for _, typ := range []uint16{AttrXorMappedAddress, AttrMappedAddress} {
		if addr, ok := res.Get(typ).(*Addr); ok {
			return addr, nil
		}
	}
	return nil, ErrBadResponse
}

func (c *Conn) RoundTrip(req *Message) (*Message, error) {
	var rto time.Duration
	if !c.Reliable() {
		rto = c.config.getRetransmissionTimeout()
	}
	deadline := time.Now().Add(c.config.getTransactionTimeout())

	c.config.setAttributes(req)
	tx := newTransaction(req)

	for time.Now().Before(deadline) {
		if err := c.Send(tx.Marshal); err != nil {
			return nil, err
		}
		timeout := deadline.Sub(time.Now())
		if timeout <= 0 {
			break
		} else if 0 < rto && rto < timeout {
			timeout = rto
		}
		err := c.Receive(tx.Handle, timeout)
		switch err {
		case mux.ErrTimeout:
			rto <<= 1
		case nil:
			return tx.res, nil
		default:
			return nil, err
		}
	}
	return nil, ErrTimeout
}

type transaction struct {
	*Message
	res *Message
}

func newTransaction(req *Message) *transaction {
	b := make([]byte, 16)
	copy(b, magicCookie)
	random.Read(b[4:])

	req.Transaction = b
	return &transaction{req, &Message{}}
}

func (tx *transaction) Write(b []byte) []byte {
	return tx.Marshal(b)
}

func (tx *transaction) Handle(b []byte) (int, error) {
	if len(b) < 20 {
		return 0, io.EOF
	}
	if !bytes.Equal(b[4:20], tx.Transaction) {
		return 0, io.EOF
	}
	n := int(be.Uint16(b[2:])) + 20
	if len(b) < n {
		return 0, io.EOF
	}
	return n, tx.res.Unmarshal(b[:n])
}

var magicCookie = []byte{0x21, 0x12, 0xa4, 0x42}
var random = rand.New(rand.NewSource(time.Now().Unix()))
