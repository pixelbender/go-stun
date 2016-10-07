// Package mux implements connection multiplexer.
// It can be used to handle multiple protocols over the same connection.
package mux

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"
	"context"
)

// ErrFormat is returned by a handler if a message format is not supported.
var ErrFormat = errors.New("format error")

// A Transport is a network transport, it provides send operation.
type Transport interface {
	Network() string
	Send(enc func(*Writer) error) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}

type BufferPool interface {
	Put(x interface{})
	Get() interface{}
}

var bufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 2048)
	},
}

// A Mux is a multiprotocol connection multiplexer.
type Mux struct {
	mu sync.RWMutex
	chain []func(Transport, *Reader) error
}

func (m *Mux) Match(ctx context.Context, match func(b []byte) int) (Reader, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
}

func (m *Mux) Handle(r io.Reader) error {
	m.mu.
}

// Handle appends h to the decoder chain of the muxer.
// When data becomes available on connection, muxer calls handlers sequentially.
// The handler h must return ErrFormat if message format is not supported
// or io.EOF if r does not contain required bytes to determine a message format.
// Connection will be closed if there are no handlers,
// all handlers return ErrFormat or another error, except io.EOF.
func (m *Mux) Handle(h func(Transport, *Reader) error) {
	m.mu.Lock()
	m.chain = append(m.chain, h)
	m.mu.Unlock()
}

// ServeConn reads c and calls handlers from decoder chain when data becomes available.
// It closes c after the specified Timeout of inactivity.
// ServeConn always returns a non-nil error.
func (m *Mux) ServeConn(c net.Conn) error {
	if _, ok := c.(net.PacketConn); ok {
		conn := &packetConn{Conn: c, mux: m}
		return conn.Serve()
	}
	conn := &streamConn{Conn: c, mux: m}
	return conn.Serve()
}

// ServePacket receives incoming packets over the packet-oriented network listener
// and calls handlers from decoder chain.
// ServePacket always returns a non-nil error.
func (m *Mux) ServePacket(c net.PacketConn) error {
	defer c.Close()

	pool := m.getBufferPool()
	buf := pool.Get().([]byte)
	defer pool.Put(buf)

	r := &Reader{}
	for {
		n, addr, err := c.ReadFrom(buf)
		if err != nil {
			return err
		}
		if n > 0 {
			r.buf, r.pos = buf[:n], 0
			m.handle(&packetServer{c, m, addr.(*net.UDPAddr)}, r)
		}
	}
}

// Serve accepts incoming connection on the listener and calls ServeConn on each connection.
// Serve always returns a non-nil error.
func (m *Mux) Serve(l net.Listener) error {
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(time.Millisecond)
				continue
			}
			return err
		}
		go m.ServeConn(c)
	}
}

// ListenAndServe listens on the network address addr
// and then calls Serve or ServePacket to handle requests
// on incoming connections.
// ListenAndServe always returns a non-nil error.
func (m *Mux) ListenAndServe(network, addr string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		l, err := net.Listen(network, addr)
		if err != nil {
			return err
		}
		return m.Serve(l)
	case "udp", "udp4", "udp6":
		l, err := net.ListenPacket(network, addr)
		if err != nil {
			return err
		}
		return m.ServePacket(l)
	default:
		return errUnsupportedNetwork(network)
	}
}

// ListenAndServeTLS acts identically to ListenAndServe, except that it expects connections over TLS.
// ListenAndServeTLS always returns a non-nil error.
func (m *Mux) ListenAndServeTLS(network, addr, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	l = tls.NewListener(l, config)
	return m.Serve(l)
}

// DialAndServe connects to the address on the named network and then calls ServeConn.
// DialAndServe always returns a non-nil error.
func (m *Mux) DialAndServe(network, addr string) error {
	c, err := net.Dial(network, addr)
	if err != nil {
		return err
	}
	return m.ServeConn(c)
}

// DialAndServeTLS connects to the address using tls.Dial and then calls ServeConn.
// DialAndServeTLS always returns a non-nil error.
func (m *Mux) DialAndServeTLS(network, addr string, config *tls.Config) error {
	c, err := tls.Dial(network, addr, config)
	if err != nil {
		return err
	}
	return m.ServeConn(c)
}

func (m *Mux) handle(c Transport, r *Reader) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	f := 0
	for _, h := range m.chain {
		if r.Buffered() <= 0 {
			break
		}
		err := h(c, r)
		if err != nil && err != io.EOF {
			if err == ErrFormat {
				f++
			} else {
				return err
			}
		}
	}
	if f == len(m.chain) {
		return ErrFormat
	}
	return nil
}

func (m *Mux) send(conn io.Writer, enc func(*Writer) error) (err error) {
	pool := m.getBufferPool()
	buf := pool.Get().([]byte)
	defer pool.Put(buf)

	w := &Writer{buf: buf}
	err = enc(w)
	if err != nil {
		return
	}
	if w.Len() > 0 {
		_, err = conn.Write(w.Bytes())
	}
	return
}

func (m *Mux) setDeadline(conn net.Conn) error {
	if m.Timeout > 0 {
		return conn.SetDeadline(time.Now().Add(m.Timeout))
	}
	return nil
}

func (m *Mux) getBufferPool() BufferPool {
	if m.BufferPool != nil {
		return m.BufferPool
	}
	return bufferPool
}

type packetServer struct {
	net.PacketConn
	mux  *Mux
	addr *net.UDPAddr
}

func (packetServer) Network() string {
	return "udp"
}

func (c *packetServer) Write(p []byte) (int, error) {
	return c.WriteTo(p, c.addr)
}

func (c *packetServer) Send(enc func(*Writer) error) error {
	return c.mux.send(c, enc)
}

func (c *packetServer) RemoteAddr() net.Addr {
	return c.addr
}

func (packetServer) Close() error {
	return nil
}

type errUnsupportedNetwork string

func (e errUnsupportedNetwork) Error() string {
	return "unsupported network: " + string(e)
}
