package mux

import (
	"io"
	"log"
)

type Writer interface {
	io.Writer
	Next(n int) []byte
	Header(n int) Header
	Bytes() []byte
}

type Header interface {
	Payload() int
	Bytes() []byte
}

type writer struct {
	buf []byte
	pos int
}

func NewWriter(b []byte) Writer {
	return &writer{buf: b}
}

func (w *writer) grow(n int) {
	p := w.pos + n
	if p < 1024 {
		p = 1024
	} else if s := len(w.buf) << 1; p < s {
		p = s
	}
	b := make([]byte, p)
	if w.pos > 0 {
		copy(b, w.buf[:w.pos])
	}
	w.buf = b
}

func (w *writer) Next(n int) (b []byte) {
	p := w.pos + n
	if len(w.buf) < p {
		s := p
		if s < 1024 {
			s = 1024
		} else {
			s <<= 1
		}
		log.Printf("expand: %v -> %v", len(w.buf), s)
		b := make([]byte, s)
		if w.pos > 0 {
			copy(b, w.buf[:w.pos])
		}
		w.buf = b
	}
	b, w.pos = w.buf[w.pos:p], p
	return
}

func (w *writer) Header(n int) Header {
	w.Next(n)
	return &header{w, w.pos - n, w.pos}
}

func (w *writer) Write(p []byte) (int, error) {
	return copy(w.Next(len(p)), p), nil
}

func (w *writer) Bytes() []byte {
	return w.buf[:w.pos]
}
