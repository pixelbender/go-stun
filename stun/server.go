package stun

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// A ResponseWriter interface is used by a STUN handler to construct a STUN response.
type ResponseWriter interface {
	WriteMessage(*Message) error
}

// A Handler responds to a STUN request.
type Handler interface {
	ServeSTUN(w ResponseWriter, r *Message)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions as STUN handlers.
type HandlerFunc func(w ResponseWriter, r *Message)

// ServeSTUN calls f(w, r).
func (f HandlerFunc) ServeSTUN(w ResponseWriter, r *Message) {
	f(w, r)
}

// Server represents a STUN server.
type Server struct {
	Handler Handler
	mutex   sync.Mutex
}

// ListenAndServe listens on the network address and calls handler to serve requests.
func (srv *Server) ListenAndServe(network, addr string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		l, err := net.Listen(network, addr)
		if err != nil {
			return err
		}
		return srv.Serve(l)
	case "udp", "udp4", "udp6":
		l, err := net.ListenPacket(network, addr)
		if err != nil {
			return err
		}
		return srv.ServePacket(l)
	}
	return fmt.Errorf("stun: listen unsupported network %v", network)
}

// ServePacket accepts incoming STUN requests on the packet-oriented network listener and calls handler to serve requests.
func (srv *Server) ServePacket(l net.PacketConn) error {
	buf := make([]byte, bufferSize)
	for {
		n, addr, err := l.ReadFrom(buf)
		if err != nil {
			return err
		}
		msg, err := ReadMessage(buf[:n])
		if err != nil {
			return err
		}
		go srv.serveMessage(&clientConn{l, addr}, msg)
	}
}

// Serve accepts incoming STUN requests on the listener and calls handler to serve requests.
func (srv *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(time.Millisecond)
				continue
			}
			return err
		}
		go srv.serveConn(NewConn(c))
	}
}

func (srv *Server) serveConn(conn *Conn) error {
	defer conn.Close()
	for {
		msg, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		srv.serveMessage(conn, msg)
	}
}

func (srv *Server) serveMessage(w ResponseWriter, r *Message) {
	if srv.Handler != nil {
		srv.Handler.ServeSTUN(w, r)
	}
}

type clientConn struct {
	net.PacketConn
	addr net.Addr
}

func (c *clientConn) WriteMessage(msg *Message) error {
	buf := make([]byte, bufferSize)
	n, err := msg.Encode(buf)
	if err != nil {
		return err
	}
	_, err = c.WriteTo(buf[:n], c.addr)
	if err != nil {
		return err
	}
	return nil
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.addr
}
