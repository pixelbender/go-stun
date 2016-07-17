package stun

import (
	"fmt"
	"net"
	"time"
)

// A Handler handles a STUN message.
type Handler interface {
	ServeSTUN(tr *Transaction)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions as STUN handlers.
type HandlerFunc func(tr *Transaction)

// ServeSTUN calls f(tr).
func (f HandlerFunc) ServeSTUN(tr *Transaction) {
	f(tr)
}

// Server represents a STUN server.
type Server struct {
	Handler Handler
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

// ServePacket receives incoming packets on the packet-oriented network listener and calls handler to serve STUN requests.
func (srv *Server) ServePacket(l net.PacketConn) error {
	buf := make([]byte, bufferSize)
	for {
		n, addr, err := l.ReadFrom(buf)
		if err != nil {
			return err
		}
		msg, err := DecodeMessage(buf[:n])
		if err != nil {
			return err
		}
		go srv.ServeSTUN(&Transaction{netPacketConn(l, addr), msg})
	}
}

// Serve accepts incoming connection on the listener and calls handler to serve STUN requests.
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
		go srv.serveConn(c)
	}
}

func (srv *Server) serveConn(conn net.Conn) error {
	c := NewConn(conn)
	defer c.Close()
	for {
		msg, err := c.ReadMessage()
		if err != nil {
			return err
		}
		srv.ServeSTUN(&Transaction{c, msg})
	}
}

// ServeSTUN handles the STUN message.
func (srv *Server) ServeSTUN(tr *Transaction) {
	if srv.Handler != nil {
		srv.Handler.ServeSTUN(tr)
	}
}

type clientConn interface {
	WriteMessage(msg *Message) error
	RemoteAddr() net.Addr
	Close() error
}

// A Transaction represents an incoming STUN transaction.
type Transaction struct {
	clientConn
	Message *Message
}

func (tr *Transaction) WriteResponse(t uint16, attrs map[uint16]Attribute) error {
	res := &Message{
		Type:        t,
		Cookie:      tr.Message.Cookie,
		Transaction: tr.Message.Transaction,
		Attributes:  attrs,
	}
	return tr.WriteMessage(res)
}

type packetConn struct {
	net.PacketConn
	addr net.Addr
}

func netPacketConn(l net.PacketConn, addr net.Addr) *packetConn {
	return &packetConn{l, addr}
}

func (pc *packetConn) RemoteAddr() net.Addr {
	return pc.addr
}

func (pc *packetConn) WriteMessage(msg *Message) error {
	// TODO: buffer pool

	buf := make([]byte, bufferSize)
	n, err := msg.Encode(buf)
	if err != nil {
		return err
	}
	_, err = pc.WriteTo(buf[:n], pc.addr)
	if err != nil {
		return err
	}
	return nil
}

func (pc *packetConn) Close() error {
	return nil
}
