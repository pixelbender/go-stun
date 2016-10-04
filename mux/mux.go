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
)

var bufferSize = 2048 // TODO: buffer pool

// ErrFormat is returned by a handler if a message format is not supported.
var ErrFormat = errors.New("format error")

// A Conn is a multiplexed half-connection.
// Use muxer to handle incoming messages.
type Conn interface {
	Send(enc func(*Writer) error) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}

// A Mux is a multiprotocol connection multiplexer.
type Mux struct {
	// An idle timeout for connections.
	// If zero, then the default value which is 1 minute.
	Timeout time.Duration

	// A buffer size for reading from connection.
	// If zero, then the default value which is 2048 bytes.
	BufferSize int

	BufferPool sync.Pool

	mu    sync.RWMutex
	chain []func(Conn, *Reader) error
}

// Handle appends h to the decoder chain of the muxer.
// When data becomes available on connection, muxer calls handlers sequentially.
// The handler h must return ErrFormat if message format is not supported
// or io.EOF if r does not contain required bytes to determine a message format.
// Connection will be closed if there are no handlers, all handlers return ErrFormat or another error, except io.EOF.
func (m *Mux) Handle(h func(Conn, *Reader) error) {
	m.mu.Lock()
	m.chain = append(m.chain, h)
	m.mu.Unlock()
}

// NewConn creates a multiplexed connection over net.Conn interface.
// It starts goroutine, reads c and calls muxer when data becomes available.
// It closes c after the specified Timeout of inactivity.
func (m *Mux) NewConn(inner net.Conn) Conn {
	if _, ok := inner.(net.PacketConn); ok {
		c := &packetConn{Conn: inner, mux: m}
		go c.serve()
		return c
	}
	c := &streamConn{Conn: inner, mux: m}
	go c.serve()
	return c
}

// ServeConn reads c and calls handlers from decoder chain when data becomes available.
// It closes c after the specified Timeout of inactivity.
// ServeConn always returns a non-nil error.
func (m *Mux) ServeConn(c net.Conn) error {
	if _, ok := c.(net.PacketConn); ok {
		conn := &packetConn{Conn: c, mux: m}
		return conn.serve()
	}
	conn := &streamConn{Conn: c, mux: m}
	return conn.serve()
}

// ServePacket receives incoming packets over the packet-oriented network listener
// and calls handlers from decoder chain.
// ServePacket always returns a non-nil error.
func (m *Mux) ServePacket(c net.PacketConn) error {
	defer c.Close()
	buf := make([]byte, bufferSize)
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

func (m *Mux) handle(c Conn, r *Reader) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, h := range m.chain {
		if r.Buffered() > 0 {
			if err := h(c, r); err != nil && err != io.EOF {
				return err
			}
		} else {
			break
		}
	}
	return nil
}

func (m *Mux) send(conn io.Writer, enc func(*Writer) error) (err error) {
	w := &Writer{}
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
	return conn.SetDeadline(time.Now().Add(time.Minute))
}

type packetServer struct {
	net.PacketConn
	mux  *Mux
	addr *net.UDPAddr
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

type packetConn struct {
	net.Conn
	mux   *Mux
	chain []func(r Reader) error
}

func (c *packetConn) serve() error {
	defer c.Close()
	buf := make([]byte, bufferSize)
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

type streamConn struct {
	net.Conn
	mux *Mux
}

func (c *streamConn) Mux() *Mux {
	return c.mux
}

func (c *streamConn) Network() string {
	return "tcp"
}

func (c *streamConn) serve() error {
	defer c.Close()
	buf := make([]byte, bufferSize)
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

type errUnsupportedNetwork string

func (e errUnsupportedNetwork) Error() string {
	return "unsupported network: " + string(e)
}
