package stun

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
)

// A Conn represents the STUN connection and implements the STUN protocol over net.Conn interface.
type Conn struct {
	net.Conn
	dec decoder
	key []byte
}

// NewConn creates a Conn connection on the given net.Conn
func NewConn(inner net.Conn) *Conn {
	if _, ok := inner.(net.PacketConn); ok {
		return &Conn{inner, newPacketDecoder(inner)}
	}
	return &Conn{inner, newStreamDecoder(inner)}
}

// ReadMessage reads STUN messages from the connection.
func (conn *Conn) ReadMessage() (*Message, error) {
	return conn.dec.Decode()
}

// WriteMessage writes STUN messages to the connection.
func (conn *Conn) WriteMessage(msg *Message) error {
	// TODO: use buffer pool

	buf := make([]byte, bufferSize)
	n, err := msg.Encode(buf)
	if err != nil {
		return err
	}
	_, err = conn.Write(buf[:n])
	if err != nil {
		return err
	}
	return nil
}

// Exchange sends STUN request and returns STUN response or error.
func (conn *Conn) Exchange(req *Message) (*Message, error) {
	// TODO: retransmissions for packet-oriented network
	err := conn.WriteMessage(req)
	if err != nil {
		return nil, err
	}
	res, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(req.Transaction, res.Transaction) {
		log.Printf("REQ: %s", hex.EncodeToString(req.Transaction))
		log.Printf("RES: %s", hex.EncodeToString(res.Transaction))
		return nil, fmt.Errorf("stun: transaction error")
	}
	return res, nil
}

type decoder interface {
	Decode() (*Message, error)
}

// streamDecoder reads STUN message from the buffered reader.
type streamDecoder struct {
	*bufio.Reader
}

func newStreamDecoder(r io.Reader) *streamDecoder {
	buf, ok := r.(*bufio.Reader)
	if !ok {
		buf = bufio.NewReaderSize(r, bufferSize)
	}
	return &streamDecoder{buf}
}

func (dec *streamDecoder) Decode() (*Message, error) {
	b, err := dec.Peek(20)
	if err != nil {
		return nil, err
	}
	n := getInt16(b[2:]) + 20
	if b, err = dec.Peek(n); err != nil {
		return nil, err
	}
	msg, err := DecodeMessage(b)
	if err != nil {
		return nil, err
	}
	dec.Discard(n)
	return msg, err
}

// packetDecoder reads STUN message from the packet-oriented network.
type packetDecoder struct {
	io.Reader
	buf [bufferSize]byte
}

func newPacketDecoder(r io.Reader) *packetDecoder {
	return &packetDecoder{Reader: r}
}

func (dec *packetDecoder) Decode() (*Message, error) {
	n, err := dec.Read(dec.buf[:])
	if err != nil {
		return nil, err
	}
	return DecodeMessage(dec.buf[:n])
}
