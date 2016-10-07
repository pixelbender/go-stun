package mux

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestMux(t *testing.T) {
	t.Parallel()
	for _, it := range []string{"udp", "tcp"} {
		done := make(chan bool)
		mux := &Mux{}
		mux.Handle(func(t Transport, r *Reader) (err error) {
			var b []byte
			if b, err = r.Next(4); err != nil {
				return
			}
			switch string(b) {
			case "ping":
				_, err = t.(io.Writer).Write([]byte("pong"))
			case "pong":
				done <- true
			default:
				err = ErrFormat
			}
			return
		})
		var conn net.Conn
		switch it {
		case "udp":
			l, err := net.ListenPacket("udp", "")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			go mux.ServePacket(l)

			conn, err = net.Dial("udp", l.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			go mux.ServeConn(conn)
		case "tcp":
			l, err := net.Listen("tcp", "")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			go mux.Serve(l)

			conn, err = net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			go mux.ServeConn(conn)
		}
		conn.Write([]byte("ping"))
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fail()
		}
	}
}

func TestConn(t *testing.T) {
	t.Parallel()
	for _, it := range []string{"udp", "tcp"} {
		done := make(chan bool)
		mux := &Mux{}
		mux.Handle(func(t Transport, r *Reader) (err error) {
			var b []byte
			if b, err = r.Next(4); err != nil {
				return
			}
			if string(b) == "ping" {
				_, err = t.(io.Writer).Write([]byte("pong"))
			} else {
				err = ErrFormat
			}
			return
		})
		var conn Conn
		switch it {
		case "udp":
			l, err := net.ListenPacket("udp", "")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			go mux.ServePacket(l)

			c, err := net.Dial("udp", l.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			conn = NewConn(c)
			defer conn.Close()
		case "tcp":
			l, err := net.Listen("tcp", "")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			go mux.Serve(l)

			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			conn = NewConn(c)
			defer conn.Close()
		}
		conn.Handle(func(t Transport, r *Reader) (err error) {
			var b []byte
			if b, err = r.Next(4); err != nil {
				return
			}
			if string(b) == "pong" {
				done <- true
			} else {
				err = ErrFormat
			}
			return
		})
		go conn.Serve()
		conn.Send(func(w *Writer) (err error) {
			_, err = w.Write([]byte("ping"))
			return
		})
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fail()
		}
	}
}
