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

func NewReader(buf []byte) Reader {
	return &reader{buf: buf}
}

func (r *reader) Next(n int) (b []byte, err error) {
	if len(r.buf) < n {
		b, err, r.buf = r.buf, io.EOF, nil
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
	r       io.Reader
	pre     []byte
	changed bool
	z       int64
}

func (r *streamReader) fill() (err error) {
	off := len(r.buf)
	if off > 0 {
		copy(r.pre, r.buf)
	}
	if off == len(r.pre) {
		return ErrBufferOverflow
	}
	var n int
	n, err = r.r.Read(r.pre[off:])
	r.z += int64(n)
	r.buf = r.pre[:off+n]
	return
}

func (r *streamReader) Next(n int) (b []byte, err error) {
	if len(r.buf) < n {
		err = r.fill()
		if len(r.buf) < n {
			if err == nil {
				err = io.EOF
			}
			b, r.buf = r.buf, nil
			if len(b) > 0 {
				r.changed = true
			}
			return
		}
	}
	b, r.buf = r.buf[:n], r.buf[n:]
	if len(b) > 0 {
		r.changed = true
	}
	return
}

func (r *streamReader) Read(p []byte) (n int, err error) {
	b := r.Bytes()
	if len(p) > len(b) {
		off := copy(p, b)
		r.buf = nil
		n, err = r.r.Read(p[off:])
		n += off
	} else {
		b, err = r.Next(len(p))
		n = copy(p, b)
	}
	if n > 0 {
		r.changed = true
	}
	return
}

func (r *streamReader) Bytes() []byte {
	return r.buf
}

type header struct {
	*writer
	from, to int
}

func (h *header) Payload() int {
	return h.pos - h.to
}

func (h *header) Bytes() []byte {
	return h.buf[h.from:h.to]
}
