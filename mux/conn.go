package mux

import (
	"io"
	"net"
	"sync"
	"time"
)

type Unmarshal func([]byte) (int, error)
type Marshal func([]byte) []byte

type Conn interface {
	io.Writer
	Reliable() bool
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	Send(m Marshal) error
	Receive(u Unmarshal, t time.Duration) error
	Close() error
}

func NewConn(inner net.Conn, m *Mux) Conn {
	_, ok := inner.(net.PacketConn)
	c := &conn{inner, m, !ok}
	go c.serve()
	return c
}

type conn struct {
	net.Conn
	m        *Mux
	reliable bool
}

func (c *conn) Reliable() bool {
	return c.reliable
}

func (c *conn) Receive(u Unmarshal, t time.Duration) error {
	return c.m.Receive(u, t)
}

func (c *conn) serve() error {
	defer c.m.Close()
	defer c.Conn.Close()
	if _, ok := c.Conn.(net.PacketConn); ok {
		return c.servePacket()
	}
	return c.serveStream()
}

func (c *conn) serveStream() error {
	b := pool.Get().([]byte)
	defer pool.Put(b)

	pos := 0
	for {
		if pos >= len(b) {
			return ErrBufferOverflow
		}
		n, err := c.Read(b[pos:])
		if err != nil {
			return err
		}
		pos += n
		n = 0
		for n < pos {
			s, err := c.m.handle(c, b[n:pos])
			if err != nil {
				return err
			}
			if s == 0 {
				break
			}
			n += s
		}
		if 0 < n && n < pos {
			copy(b, b[n:pos])
			pos -= n
		}
	}
}

func (c *conn) servePacket() error {
	b := pool.Get().([]byte)
	defer pool.Put(b)

	for {
		n, err := c.Read(b)
		if err != nil {
			return err
		}
		if n > 0 {
			c.m.handle(c, b[:n])
		}
	}
}

func (c *conn) Send(m Marshal) error {
	return marshalAndSend(m, c.Conn)
}

func marshalAndSend(m Marshal, w io.Writer) (err error) {
	b := pool.Get().([]byte)
	defer pool.Put(b)

	_, err = w.Write(m(b[:0]))
	return
}

var pool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 1024)
	},
}
