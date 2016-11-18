package mux

import (
	"io"
)

type Reader interface {
	io.Reader
	Next(n int) (b []byte, err error)
	Bytes() []byte
}

type reader struct {
	buf []byte
}

func (r *reader) Next(n int) (b []byte, err error) {
	if len(r.buf) < n {
		err = io.EOF
		return
	}
	b, r.buf = r.buf[:n], r.buf[n:]
	return
}

func (r *reader) Read(p []byte) (n int, err error) {
	var b []byte
	b, err = r.Next(len(p))
	n = copy(p, b)
	return
}

func (r *reader) Bytes() []byte {
	return r.buf
}

type streamReader struct {
	reader
	src io.Reader
	pre []byte
}

func (r *streamReader) Fill() (n int, err error) {
	s := len(r.buf)
	if s == len(r.pre) {
		return 0, ErrBufferOverflow
	}
	if s > 0 {
		copy(r.pre, r.buf)
	}
	n, err = r.src.Read(r.pre[s:])
	r.buf = r.pre[:s+n]
	return
}

func (r *streamReader) Next(n int) ([]byte, error) {
	if len(r.buf) < n {
		r.Fill()
	}
	return r.reader.Next(n)
}

func (r *streamReader) Read(p []byte) (n int, err error) {
	if len(r.buf) < len(p) {
		off := copy(p, r.buf)
		r.buf = nil
		n, err = r.src.Read(p[off:])
		n += off
	} else {
		return r.reader.Read(p)
	}
	return
}
