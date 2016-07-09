package stun

import (
	"io"
)

// An Encoder encodes and writes STUN message to an output stream.
type Encoder struct {
	w   io.Writer
	buf []byte
}

// NewEncoder returns a new encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// Encode writes STUN message to the stream.
func (enc *Encoder) Encode(msg *Message) error {
	if enc.buf == nil {
		enc.buf = make([]byte, bufferSize)
	}
	n, err := msg.Encode(enc.buf)
	if err != nil {
		return err
	}
	_, err = enc.w.Write(enc.buf[:n])
	if err != nil {
		return err
	}
	return nil
}
