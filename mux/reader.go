package mux

import (
	"io"
)

// Reader represents a buffered reader.
type Reader struct {
	buf     []byte
	pos     int
	counter int64
	fill    func([]byte) (int, error)
}

func NewReader(b []byte) *Reader {
	return &Reader{buf: b}
}


// Peek returns the next n bytes without advancing the reader.
// The bytes stop being valid at the next read call.
func (r *Reader) Peek(n int) (b []byte, err error) {
	p := r.pos + n
	if len(r.buf) < p {
		if r.fill != nil {
			b := r.buf
			off, m := len(b), 0
			if r.pos < off {
				off = copy(b, b[r.pos:])
			}
			m, err = r.fill(b[off:cap(b)])
			if m > 0 {
				off += m
			}
			r.buf, r.pos = b[:off], 0
			if off < n {
				p = off
				if err == nil {
					err = io.EOF
				}
			} else {
				p = n
			}
		} else {
			p = len(r.buf)
			err = io.EOF
		}
	}
	b = r.buf[r.pos:p]
	return
}

func (r *Reader) Payload(n int) (s *Reader, err error) {
	var b []byte
	if b, err = r.Next(n); err != nil {
		return
	}
	s = &Reader{buf: b}
	return
}

func (r *Reader) Next(n int) (b []byte, err error) {
	b, err = r.Peek(n)
	r.pos += len(b)
	r.counter += int64(len(b))
	return
}

func (r *Reader) Read(p []byte) (n int, err error) {
	var b []byte
	b, err = r.Next(len(p))
	n = copy(p, b)
	return
}

func (r *Reader) Buffered() int {
	return len(r.buf) - r.pos
}

func (r *Reader) Bytes() []byte {
	return r.buf[r.pos:]
}
