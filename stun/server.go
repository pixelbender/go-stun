package stun

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// A Handler handles a STUN message.
type Handler interface {
	ServeSTUN(tx *Transaction)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions as STUN handlers.
type HandlerFunc func(tx *Transaction)

// ServeSTUN calls f(tx).
func (f HandlerFunc) ServeSTUN(tx *Transaction) {
	f(tx)
}

// Server represents a STUN server.
type Server struct {
	Realm    string
	Software string
	Handler  Handler
	Codec    *MessageCodec
}

// ListenAndServe listens on the network address and calls handler to serve requests.
// Accepted connections are configured to enable TCP keep-alives.
func (srv *Server) ListenAndServe(network, addr string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		l, err := net.Listen(network, addr)
		if err != nil {
			return err
		}
		return srv.Serve(tcpKeepAliveListener{l.(*net.TCPListener)})
	case "udp", "udp4", "udp6":
		l, err := net.ListenPacket(network, addr)
		if err != nil {
			return err
		}
		return srv.ServePacket(l)
	}
	return fmt.Errorf("stun: listen unsupported network %v", network)
}

// ListenAndServeTLS listens on the network address secured by TLS and calls handler to serve requests.
// Accepted connections are configured to enable TCP keep-alives.
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
	l = tls.NewListener(tcpKeepAliveListener{l.(*net.TCPListener)}, config)
	return srv.Serve(l)
}

// ServePacket receives incoming packets on the packet-oriented network listener and calls handler to serve STUN requests.
// Multiple goroutines may invoke ServePacket on the same PacketConn simultaneously.
func (srv *Server) ServePacket(l net.PacketConn) error {
	buf := make([]byte, bufferSize)
	for {
		n, addr, err := l.ReadFrom(buf)
		if err != nil {
			return err
		}
		msg, err := srv.Codec.Decode(buf[:n])
		srv.serve(&packetWriter{l, addr, srv.Codec}, msg, err)
	}
}

// Serve accepts incoming connection on the listener and calls handler to serve STUN requests.
// Multiple goroutines may invoke Serve on the same Listener simultaneously.
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
	c := NewConn(conn, srv.Codec)
	defer c.Close()
	for {
		b, err := c.PeekMessage()
		if err != nil {
			return err
		}
		msg, err := srv.Codec.Decode(b)
		srv.serve(c, msg, err)
	}
}

func (srv *Server) serve(conn transConn, msg *Message, err error) {
	tx := &Transaction{conn, msg}
	switch err {
	case ErrUnauthorized, ErrIncorrectFingerprint:
		tx.WriteResponse(TypeError, Attributes{
			AttrErrorCode: NewError(CodeUnauthorized),
			AttrRealm:     srv.Realm,
			AttrSoftware:  srv.Software,
		})
		return
	case ErrFormat, ErrIncorrectFingerprint:
		return
	}
	if unk, ok := err.(ErrUnknownAttrs); ok {
		tx.WriteResponse(TypeError, Attributes{
			AttrErrorCode:         NewError(CodeUnknownAttribute),
			AttrUnknownAttributes: unk,
			AttrSoftware:          srv.Software,
		})
		return
	}
	if err != nil {
		log.Printf(">>> %v", err)
	}
	if h := srv.Handler; h != nil {
		h.ServeSTUN(tx)
		return
	}
	switch msg.Method {
	case MethodBinding:
		tx.WriteResponse(TypeResponse, Attributes{
			AttrErrorCode:        NewError(CodeUnknownAttribute),
			AttrXorMappedAddress: conn.RemoteAddr(),
			AttrMappedAddress:    conn.RemoteAddr(),
			AttrResponseOrigin:   conn.LocalAddr(),
			AttrSoftware:         srv.Software,
		})
	}
}

// A Transaction represents an incoming STUN transaction.
type Transaction struct {
	c       transConn
	Message *Message
}

// WriteResponse writes STUN response within the transaction.
func (tx *Transaction) WriteResponse(m uint16, attrs Attributes) error {
	return tx.WriteMessage(&Message{
		Method:     tx.Message.Method | m,
		Attributes: attrs,
	})
}

// WriteMessage writes STUN message within the transaction.
func (tx *Transaction) WriteMessage(msg *Message) error {
	m := tx.Message
	msg.Transaction = m.Transaction
	msg.Key = m.Key
	return tx.c.WriteMessage(msg)
}

// LocalAddr returns the local network address.
func (tx *Transaction) LocalAddr() net.Addr {
	return tx.c.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (tx *Transaction) RemoteAddr() net.Addr {
	return tx.c.RemoteAddr()
}

type transConn interface {
	io.Writer
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	WriteMessage(msg *Message) error
}

type packetWriter struct {
	net.PacketConn
	addr  net.Addr
	codec *MessageCodec
}

func (w *packetWriter) RemoteAddr() net.Addr {
	return w.addr
}

func (w *packetWriter) Write(b []byte) (int, error) {
	return w.WriteTo(b, w.addr)
}

func (w *packetWriter) WriteMessage(msg *Message) error {
	b := make([]byte, bufferSize)
	n, err := w.codec.Encode(msg, b)
	if err != nil {
		return err
	}
	if _, err = w.Write(b[:n]); err != nil {
		return err
	}
	return nil
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (l tcpKeepAliveListener) Accept() (net.Conn, error) {
	c, err := l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	c.SetKeepAlive(true)
	c.SetKeepAlivePeriod(time.Minute)
	return c, nil
}
