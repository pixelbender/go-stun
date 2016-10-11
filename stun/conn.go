package stun

import (
	"errors"
	"github.com/pixelbender/go-stun/mux"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Config represents a STUN connection configuration.
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

	// Fingerprint controls whether a FINGERPRINT attribute will be generated.
	Fingerprint bool

	// Software is a value for SOFTWARE attribute.
	Software string

	// Realm is a value for REALM attribute.
	Realm string
}

func (c *Config) getRetransmissionTimeout() time.Duration {
	if c.RetransmissionTimeout > 0 {
		return c.RetransmissionTimeout
	}
	return 500 * time.Millisecond
}

func (c *Config) getTransactionTimeout() time.Duration {
	if c.TransactionTimeout > 0 {
		return c.TransactionTimeout
	}
	return 39500 * time.Millisecond
}

// A Conn represents the STUN connection and implements the STUN protocol over net.Conn interface.
type Conn struct {
	*Transport
	inner net.Conn
}

// NewConn creates a multiplexed connection over the c.
func NewConn(c net.Conn, config *Config) *Conn {
	t := NewTransport(mux.NewTransport(c), config)
	go t.m.Serve()
	return &Conn{t, c}
}

func (c *Conn) Close() error {
	c.Transport.Close()
	c.m.Close()
	return c.inner.Close()
}

type Transport struct {
	m      *mux.Transport
	config *Config
	key    []byte

	mu   sync.RWMutex
	reqs map[string]chan *Packet
}

func NewTransport(m *mux.Transport, config *Config) *Transport {
	if config == nil {
		config = &Config{}
	}
	c := &Transport{m: m, config: config}
	m.Receive(c.serve)
	return c
}

func (t *Transport) serve(c mux.Conn, r mux.Reader) error {
	b := r.Bytes()
	if len(b) < 20 {
		return io.EOF
	}
	t.mu.RLock()
	ch := t.reqs[string(b[4:20])]
	t.mu.RUnlock()
	if ch == nil {
		// Skip unknown transaction
		n := int(be.Uint16(b[2:]))
		r.Next(n)
		return nil
	}
	p := &Packet{}
	p.Key = t.key
	err := p.Decode(r)
	if err != nil {
		return err
	}
	select {
	case ch <- p:
	default:
	}
	return nil
}

func (t *Transport) SendMessage(m *Message) error {
	p := &Packet{}
	p.Transaction = NewTransaction()
	p.Key = t.key
	return t.m.Send(p.Encode)
}

func (t *Transport) Discover() (*Addr, error) {
	msg, err := t.RoundTrip(&Message{Method: MethodBinding})
	if err != nil {
		return nil, err
	}
	log.Printf(">> %+v", msg)
	return nil, nil
}

// RoundTrip executes a single STUN transaction, returning a response for the provided request.
func (t *Transport) RoundTrip(m *Message) (*Message, error) {
	var rto time.Duration
	if t.m.LocalAddr().Network() == "udp" {
		rto = t.config.getRetransmissionTimeout()
	}
	deadline := time.Now().Add(t.config.getTransactionTimeout())
	p := &Packet{
		Message: m,
		Key:     t.key,
		Transaction: NewTransaction(),
	}
	ch := t.newTx(p.Transaction)
	defer t.cancelTx(p.Transaction)
	for {
		timeout := deadline.Sub(time.Now())
		if timeout <= 0 {
			break
		} else if 0 < rto && rto < timeout {
			timeout = rto
		}
		if err := t.m.Send(p.Encode); err != nil {
			return nil, err
		}
		select {
		case p, connected := <-ch:
			if !connected {
				return nil, ErrCancelled
			}
			return p.Message, nil
		case <-time.After(timeout):
			rto <<= 1
		}
	}
	return nil, ErrTimeout
}

func (t *Transport) newTx(tx Transaction) <-chan *Packet {
	ch := make(chan *Packet, 10)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.reqs == nil {
		t.reqs = make(map[string]chan *Packet)
	} else {
		for {
			if _, found := t.reqs[string(tx)]; !found {
				break
			}
			tx.Reset()
		}
	}
	t.reqs[string(tx)] = ch
	return ch
}

func (t *Transport) cancelTx(tx Transaction) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ch, ok := t.reqs[string(tx)]; ok {
		delete(t.reqs, string(tx))
		close(ch)
	}
}

func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, it := range t.reqs {
		close(it)
	}
	t.reqs = nil
	return nil
}

var ErrTimeout = errors.New("i/o timeout")
var ErrCancelled = errors.New("cancelled")

type request struct {
	Transaction
	ch chan *Message
	tr *Transport
}
