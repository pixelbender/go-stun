package mux

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

var (
	ping = Raw("ping")
	pong = Raw("pong")
)

func TestPacketConn(t *testing.T) {
	t.Parallel()
	l, _ := net.ListenUDP("udp", nil)
	c, _ := net.DialUDP("udp", nil, l.LocalAddr().(*net.UDPAddr))

	srv := &Server{}
	srv.Handle(pingHandler)
	go srv.ServeUDP(l)

	count := 10
	done := make(chan bool, 1)

	cli := NewConn(c, newPongMux(done))
	go func() {
		for i := 0; i < count; i++ {
			cli.Write(ping)
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

func TestConn(t *testing.T) {
	t.Parallel()
	l, _ := net.ListenTCP("tcp", nil)
	c, _ := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))

	count := 10
	done := make(chan bool, 1)

	srv := &Server{}
	srv.Handle(pingHandler)
	go srv.Serve(l)

	cli := NewConn(c, newPongMux(done))
	go func() {
		for i := 0; i < count; i++ {
			cli.Write(ping)
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

func BenchmarkPacketConnMux(b *testing.B) {
	l, _ := net.ListenUDP("udp", nil)
	c, _ := net.DialUDP("udp", nil, l.LocalAddr().(*net.UDPAddr))

	srv := &Server{}
	srv.Handle(pingHandler)
	go srv.ServeUDP(l)
	go srv.ServeUDP(l)
	go srv.ServeUDP(l)
	go srv.ServeUDP(l)

	done := make(chan bool, 1)
	cli := NewConn(c, newPongMux(done))

	b.ResetTimer()
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		cli.Write(ping)
		<-done
	}
}

func BenchmarkPacketConnRTT(b *testing.B) {
	l, err := net.ListenUDP("udp", nil)
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	c, _ := net.DialUDP("udp", nil, l.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()

	max := 1024
	done := make(chan bool, 1)
	ping = []byte("ping")
	pong = []byte("pong")

	go func() {
		b := make([]byte, max)
		for {
			n, addr, err := l.ReadFrom(b)
			if err != nil {
				return
			}
			if bytes.Equal(b[:n], ping) {
				l.WriteTo(pong, addr)
			}
		}
	}()
	go func() {
		b := make([]byte, max)
		for {
			n, err := c.Read(b)
			if err != nil {
				return
			}
			if bytes.Equal(b[:n], pong) {
				done <- true
			}
		}
	}()

	b.ResetTimer()
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		c.Write(ping)
		<-done
	}
}

func BenchmarkConnMux(b *testing.B) {
	l, _ := net.ListenTCP("tcp", nil)
	c, _ := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))

	srv := &Server{}
	srv.Handle(pingHandler)
	go srv.Serve(l)

	done := make(chan bool, 1)
	cli := NewConn(c, newPongMux(done))

	b.ResetTimer()
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		cli.Write(ping)
		<-done
	}
}

func BenchmarkConn(b *testing.B) {
	l, _ := net.ListenTCP("tcp", nil)
	c, _ := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))

	done := make(chan bool, 1)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				r := bufio.NewReader(c)
				b := make([]byte, 4)
				for {
					n, err := r.Read(b)
					if err != nil {
						return
					}
					if bytes.Equal(b[:n], ping) {
						c.Write(pong)
					}
				}
			}(c)
		}
	}()
	go func() {
		r := bufio.NewReader(c)
		b := make([]byte, 4)
		for {
			n, err := r.Read(b)
			if err != nil {
				return
			}
			if bytes.Equal(b[:n], pong) {
				done <- true
			}
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		c.Write(ping)
		<-done
	}
}

func pingHandler(c Conn, b []byte) (int, error) {
	if len(b) < 4 {
		return 0, io.EOF
	}
	if bytes.Equal(b[:4], ping) {
		_, err := c.Write(pong)
		return 4, err
	}
	return 0, ErrFormat
}

func newPongMux(done chan bool) *Mux {
	m := &Mux{}
	m.Handle(func(c Conn, b []byte) (int, error) {
		if len(b) < 4 {
			return 0, io.EOF
		}
		if bytes.Equal(b[:4], pong) {
			done <- true
			return 4, nil
		}
		return 0, ErrFormat
	})
	return m
}
