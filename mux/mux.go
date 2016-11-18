package mux

import (
	"errors"
	"io"
	"sync"
	"time"
)

var ErrFormat = errors.New("format error")
var ErrBufferOverflow = errors.New("buffer overflow")
var ErrCancelled = errors.New("canceled")
var ErrTimeout = errors.New("i/o timeout")

type Raw []byte

func (p Raw) Marshal(b []byte) []byte {
	return append(b, p...)
}

func (p Raw) Unmarshal(b []byte) (int, error) {
	return copy(p, b), nil
}

type Mux struct {
	sync.RWMutex
	closed bool
	h      []Handler
	r      []*receiver
}

func (m *Mux) Handle(h Handler) {
	m.Lock()
	m.h = append(m.h, h)
	m.Unlock()
}

func (m *Mux) Receive(u Unmarshal, t time.Duration) (err error) {
	m.Lock()
	if m.closed {
		err = ErrCancelled
		m.Unlock()
		return
	}
	r := &receiver{u, make(chan error, 1)}
	m.r = append(m.r, r)
	m.Unlock()
	time.AfterFunc(t, r.expire)
	defer m.remove(r)
	err, _ = <-r.ch
	return
}

func (m *Mux) clone() *Mux {
	r := &Mux{}
	m.RLock()
	r.h = append(r.h, m.h...)
	m.RUnlock()
	return r
}

func (m *Mux) remove(r *receiver) {
	m.Lock()
	n := 0
	for _, it := range m.r {
		if it != r {
			m.r[n] = it
			n++
		}
	}
	m.r = m.r[:n]
	m.Unlock()
}

func (m *Mux) handle(c Conn, b []byte) (int, error) {
	m.RLock()
	defer m.RUnlock()

	for _, it := range m.r {
		n, err := it.handle(b)
		if err == nil {
			return n, err
		}
		if err != io.EOF {
			return 0, err
		}
	}

	for _, it := range m.h {
		n, err := it(c, b)
		if err == nil {
			return n, err
		}
		if err != io.EOF {
			return 0, err
		}
	}

	return 0, nil
}

func (m *Mux) Close() {
	m.Lock()
	// FIXME: close channels...
	m.Unlock()
}

type Handler func(c Conn, b []byte) (int, error)

type receiver struct {
	Unmarshal
	ch chan error
}

func (r *receiver) handle(b []byte) (int, error) {
	n, err := r.Unmarshal(b)
	switch err {
	case nil:
		r.ch <- nil
		return n, nil
	case io.EOF:
		return 0, nil
	default:
		r.ch <- err
		return n, nil
	}
}

func (r *receiver) expire() {
	r.ch <- ErrTimeout
}
