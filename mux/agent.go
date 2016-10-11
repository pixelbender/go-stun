package mux

import (
	"crypto/tls"
	"net"
	"time"
)

type Agent struct {
	Mux
}

// ServePacket receives incoming packets over the packet-oriented network listener
// and calls handlers from decoder chain.
// ServePacket always returns a non-nil error.
func (a *Agent) ServePacket(l net.PacketConn) error {
	defer l.Close()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	for {
		n, addr, err := l.ReadFrom(buf)
		if err != nil {
			return err
		}
		if n > 0 {
			a.serve(&packetServer{l, addr}, &reader{buf: buf[:n]})
		}
	}
}

// Serve accepts incoming connection on the listener and calls ServeConn on each connection.
// Serve always returns a non-nil error.
func (a *Agent) Serve(l net.Listener) error {
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
		go a.ServeConn(c)
	}
}

// ServeConn reads c and calls handlers from decoder chain when data becomes available.
// It closes c after the specified Timeout of inactivity.
// ServeConn always returns a non-nil error.
func (a *Agent) ServeConn(c net.Conn) error {
	t := &Transport{Conn: c, m: &a.Mux}
	return t.Serve()
}

// ListenAndServe listens on the network address addr
// and then calls Serve or ServePacket to handle requests
// on incoming connections.
// ListenAndServe always returns a non-nil error.
func (a *Agent) ListenAndServe(network, addr string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		l, err := net.Listen(network, addr)
		if err != nil {
			return err
		}
		return a.Serve(l)
	case "udp", "udp4", "udp6":
		l, err := net.ListenPacket(network, addr)
		if err != nil {
			return err
		}
		return a.ServePacket(l)
	default:
		return errUnsupportedNetwork(network)
	}
}

// ListenAndServeTLS acts identically to ListenAndServe, except that it expects connections over TLS.
// ListenAndServeTLS always returns a non-nil error.
func (a *Agent) ListenAndServeTLS(network, addr, certFile, keyFile string) error {
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
	return a.Serve(l)
}

type packetServer struct {
	net.PacketConn
	addr net.Addr
}

func (c *packetServer) Write(p []byte) (int, error) {
	return c.WriteTo(p, c.addr)
}

func (c *packetServer) Send(enc func(Writer) error) error {
	return encodeAndSend(c, enc)
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
