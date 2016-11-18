package mux

import (
	"crypto/tls"
	"net"
	"time"
)

type Server struct {
	m Mux
}

func (srv *Server) Handle(h Handler) {
	srv.m.Handle(h)
}

// ServeUDP receives incoming packets over the packet-oriented network listener
// and calls handlers from decoder chain.
// ServePacket always returns a non-nil error.

func (srv *Server) ServeUDP(c *net.UDPConn) error {
	defer c.Close()

	b := pool.Get().([]byte)
	defer pool.Put(b)

	conns := make(map[string]map[int]*udpConn)
	for {
		n, addr, err := c.ReadFromUDP(b)
		if err != nil {
			return err
		}
		if n > 0 {
			a := conns[string(addr.IP)]
			if a == nil {
				a = make(map[int]*udpConn)
				conns[string(addr.IP)] = a
			}
			p := a[addr.Port]
			if p == nil {
				p = &udpConn{c, addr, srv.m.clone()}
				a[addr.Port] = p
			}
			p.m.handle(p, b[:n])
		}
	}
}

// Serve accepts incoming connection on the listener and calls ServeConn on each connection.
// Serve always returns a non-nil error.
func (srv *Server) Serve(l net.Listener) error {
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
		go srv.ServeConn(c)
	}
}

// ServeConn reads c and calls handlers from decoder chain when data becomes available.
// It closes c after the specified Timeout of inactivity.
// ServeConn always returns a non-nil error.
func (srv *Server) ServeConn(c net.Conn) error {
	_, ok := c.(net.PacketConn)
	t := &conn{c, srv.m.clone(), !ok}
	return t.serve()
}

// ListenAndServe listens on the network address addr
// and then calls Serve or ServePacket to handle requests
// on incoming connections.
// ListenAndServe always returns a non-nil error.
func (srv *Server) ListenAndServe(network, addr string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		l, err := net.Listen(network, addr)
		if err != nil {
			return err
		}
		return srv.Serve(l)
	case "udp", "udp4", "udp6":
		laddr, err := net.ResolveUDPAddr(network, addr)
		if err != nil {
			return err
		}
		c, err := net.ListenUDP(network, laddr)
		if err != nil {
			return err
		}
		return srv.ServeUDP(c)
	default:
		return errUnsupportedNetwork(network)
	}
}

// ListenAndServeTLS acts identically to ListenAndServe, except that it expects connections over TLS.
// ListenAndServeTLS always returns a non-nil error.
func (srv *Server) ListenAndServeTLS(network, addr, certFile, keyFile string) error {
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
	return srv.Serve(l)
}

type udpConn struct {
	net.PacketConn
	addr *net.UDPAddr
	m    *Mux
}

func (c *udpConn) Reliable() bool {
	return false
}

func (c *udpConn) Receive(u Unmarshal, t time.Duration) error {
	return c.m.Receive(u, t)
}

func (c *udpConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.addr)
}

func (c *udpConn) Send(m Marshal) error {
	return marshalAndSend(m, c)
}

func (c *udpConn) RemoteAddr() net.Addr {
	return c.addr
}

type errUnsupportedNetwork string

func (e errUnsupportedNetwork) Error() string {
	return "unsupported network: " + string(e)
}
