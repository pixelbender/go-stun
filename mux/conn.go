package mux

import (
	"io"
	"net"
)

// A Conn is a multiplexed connection over net.Conn interface.
type Transport struct {
	net.Conn
	m *Mux
}

// NewConn creates a multiplexed connection over net.Conn interface.
func NewTransport(inner net.Conn) *Transport {
	return &Transport{Conn: inner, m: &Mux{}}
}

func (t *Transport) Send(enc func(Writer) error) error {
	return encodeAndSend(t.Conn, enc)
}

func (t *Transport) Receive(dec func(Conn, Reader) error) *Handler {
	return t.m.Receive(dec)
}

func (t *Transport) Serve() error {
	if _, udp := t.Conn.(net.PacketConn); udp {
		return t.servePacket()
	}
	return t.serveStream()
}

func (t *Transport) servePacket() error {
	defer t.Close()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	for {
		n, err := t.Read(buf)
		if err != nil {
			return err
		}
		if n > 0 {
			t.m.serve(t, &reader{buf: buf[:n]})
		}
	}
}

func (t *Transport) serveStream() error {
	defer t.Close()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	r := &streamReader{r: t.Conn, pre: buf}
	for {
		err := r.fill()
		if err != nil {
			return err
		}
		for {
			r.changed = false
			if err = t.m.serve(t, r); err != nil {
				return err
			}
			if r.changed {
				continue
			}
			break
		}
		//log.Printf("%v", len(r.Bytes()))
	}
}

type Conn interface {
	io.WriteCloser
}

func encodeAndSend(out io.Writer, enc func(Writer) error) (err error) {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	w := &writer{buf: buf}
	if err = enc(w); err != nil {
		return
	}
	_, err = out.Write(w.Bytes())
	return
}
