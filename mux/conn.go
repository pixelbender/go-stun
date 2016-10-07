package mux

import (
	"net"
	"context"
)

// A Conn is a multiplexed connection over net.Conn interface.
type Conn interface {
	net.Conn
	ReadMatch(ctx context.Context, match func(b []byte) int) <-chan Reader
	Handle(h func(Transport, *Reader) error) func()
	NewPacket() Packet
}

type Packet interface {
	Next(n int) []byte
	Send() int
}

// NewConn creates a multiplexed connection over net.Conn interface.
func NewConn(c net.Conn) Conn {
	if _, ok := c.(net.PacketConn); ok {
		return &packetConn{Conn: c, mux: &Mux{}}
	}
	return &streamConn{Conn: c, mux: &Mux{}}
}

type packetConn struct {
	net.Conn
	mux *Mux
}

func (c *packetConn) NewPacket() Packet {

}

func (c *packetConn) Handle(h func(Transport, *Reader) error) {
	c.mux.Handle(h)
}

func (c *packetConn) Serve() error {
	defer c.Close()

	pool := c.mux.getBufferPool()
	buf := pool.Get().([]byte)
	defer pool.Put(buf)

	r := &Reader{}
	for {
		c.mux.setDeadline(c.Conn)
		n, err := c.Read(buf)
		if err != nil {
			return err
		}
		if n > 0 {
			r.buf, r.pos = buf[:n], 0
			if err = c.mux.handle(c, r); err != nil {
				return err
			}
		}
	}
}

func (c *packetConn) Write(p []byte) (int, error) {
	c.mux.setDeadline(c.Conn)
	return c.Conn.Write(p)
}

func (c *packetConn) Send(enc func(*Writer) error) error {
	return c.mux.send(c.Conn, enc)
}

func (packetConn) Network() string {
	return "udp"
}

type streamConn struct {
	net.Conn
	mux *Mux
}

func (c *streamConn) Handle(h func(Transport, *Reader) error) {
	c.mux.Handle(h)
}

func (c *streamConn) Serve() error {
	defer c.Close()

	pool := c.mux.getBufferPool()
	buf := pool.Get().([]byte)
	defer pool.Put(buf)

	r := &Reader{buf: buf[:0], fill: c.Read}
	for {
		c.mux.setDeadline(c.Conn)
		_, err := r.Peek(r.Buffered() + 1)
		if err != nil {
			return err
		}
		n := r.counter
		for r.Buffered() > 0 {
			if err = c.mux.handle(c, r); err != nil {
				return err
			}
			if n == r.counter {
				break
			} else {
				n = r.counter
			}
		}
	}
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.mux.setDeadline(c.Conn)
	return c.Conn.Write(p)
}

func (c *streamConn) Send(enc func(*Writer) error) error {
	return c.mux.send(c.Conn, enc)
}

func (streamConn) Network() string {
	return "tcp"
}
