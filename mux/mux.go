package mux

import (
	"errors"
	"io"
	"sync"
)

var ErrFormat = errors.New("format error")
var ErrBufferOverflow = errors.New("buffer overflow")

type Mux struct {
	sync.RWMutex
	h []*Handler
}

func (m *Mux) Receive(h func(Conn, Reader) error) *Handler {
	r := &Handler{m, h}
	m.add(r)
	return r
}

func (m *Mux) add(h *Handler) {
	m.Lock()
	m.h = append(m.h, h)
	m.Unlock()
}

func (m *Mux) remove(h *Handler) {
	m.Lock()
	defer m.Unlock()
	n := 0
	for _, it := range m.h {
		if it != h {
			m.h[n] = it
			n++
		}
	}
	m.h = m.h[:n]
}

func (m *Mux) serve(c Conn, r Reader) (err error) {
	m.RLock()
	defer m.RUnlock()
	failed := 0
	for _, it := range m.h {
		err = it.serve(c, r)
		if err != nil {
			switch err {
			case io.EOF:
				err = nil
			case ErrFormat:
				failed++
			default:
				return
			}
		} else {
			return
		}
	}
	if failed == len(m.h) {
		err = ErrFormat
	}
	return
}

type Handler struct {
	m     *Mux
	serve func(Conn, Reader) error
}

func (h *Handler) Close() {
	h.m.remove(h)
}
