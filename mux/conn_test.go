package mux

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func EchoServer(c Conn, r Reader) (err error) {
	n, err := c.Write(r.Bytes())
	r.Next(n)
	if err != nil {
		return err
	}
	return nil
}

func TestPacketConn(t *testing.T) {
	t.Parallel()

	l, _ := net.ListenPacket("udp", "")
	defer l.Close()
	c, _ := net.Dial("udp", l.LocalAddr().String())
	defer c.Close()

	count := 1000
	done := make(chan bool, 100)

	a := &Agent{}
	a.Receive(EchoServer)
	go a.ServePacket(l)

	m := NewTransport(c)
	m.Receive(func(t Conn, r Reader) error {
		b := r.Bytes()
		if len(b) < 4 {
			return io.EOF
		}
		if string(b[:4]) == "ping" {
			r.Next(4)
			done <- true
			return nil
		}
		return ErrFormat
	})
	go m.Serve()

	go func() {
		for i := 0; i < count; i++ {
			m.Send(func(w Writer) error {
				copy(w.Next(4), "ping")
				return nil
			})
		}
	}()

	ok := 0
	for ok < count {
		select {
		case <-done:
			ok++
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
	}
}

func TestConn(t *testing.T) {
	t.Parallel()

	l, _ := net.Listen("tcp", "")
	defer l.Close()
	c, _ := net.Dial("tcp", l.Addr().String())
	defer c.Close()

	count := 1000
	done := make(chan bool, 100)

	a := &Agent{}
	a.Receive(EchoServer)
	go a.Serve(l)

	sent := int64(0)
	recv := int64(0)

	m := NewTransport(c)
	m.Receive(func(t Conn, r Reader) error {
		b := r.Bytes()
		if len(b) < 4 {
			return io.EOF
		}
		if string(b[:4]) == "ping" {
			r.Next(4)
			atomic.AddInt64(&recv, 1)
			done <- true
			return nil
		}
		return ErrFormat
	})
	go m.Serve()

	go func() {
		for i := 0; i < count; i++ {
			m.Write([]byte("ping"))
			atomic.AddInt64(&sent, 1)
		}
	}()

	ok := 0
	for ok < count {
		select {
		case <-done:
			ok++
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}

}
