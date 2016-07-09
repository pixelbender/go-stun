package stun

import (
	"bufio"
	"io"
)

// A Decoder reads and decodes STUN message from an input stream.
type Decoder struct {
	buf *bufio.Reader
}

// NewDecoder returns a new decoder that reads from r.
func NewDecoder(r io.Reader) *Decoder {
	if buf, ok := r.(*bufio.Reader); ok {
		return &Decoder{buf}
	}
	return &Decoder{bufio.NewReaderSize(r, bufferSize)}
}

// Decode reads STUN message from the stream.
func (dec *Decoder) Decode() (*Message, error) {
	b, err := dec.buf.Peek(20)
	if err != nil {
		return nil, err
	}
	n := getInt16(b[2:]) + 20
	if b, err = dec.buf.Peek(n); err != nil {
		return nil, err
	}
	msg, err := ReadMessage(b)
	if err != nil {
		return nil, err
	}
	dec.buf.Discard(n)
	return msg, err
}
