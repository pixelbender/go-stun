package stun

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"net"
)

var bufferSize = 1400

// A Conn represents the STUN connection and implements the STUN protocol over net.Conn interface.
type Conn struct {
	conn
	Codec *MessageCodec
}

// NewConn creates a Conn connection on the given net.Conn and uses codec to encode/decode STUN messages
func NewConn(inner net.Conn, codec *MessageCodec) *Conn {
	return &Conn{newConn(inner), codec}
}

// ReadMessage reads STUN messages from the connection.
func (c *Conn) ReadMessage() (*Message, error) {
	b, err := c.PeekMessage()
	if err != nil {
		return nil, err
	}
	return c.Codec.Decode(b)
}

// WriteMessage writes the STUN message to the connection.
func (c *Conn) WriteMessage(msg *Message) error {
	b := make([]byte, bufferSize)
	n, err := c.Codec.Encode(msg, b)
	if err != nil {
		return err
	}
	if _, err = c.Write(b[:n]); err != nil {
		return err
	}
	return nil
}

// Exchange sends STUN request and returns STUN response or error.
func (c *Conn) Exchange(req *Message) (*Message, error) {
	// TODO: retransmissions for packet-oriented network
	err := c.WriteMessage(req)
	if err != nil {
		return nil, err
	}
	res, err := c.ReadMessage()
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

type conn interface {
	net.Conn
	PeekMessage() ([]byte, error)
}

func newConn(inner net.Conn) conn {
	if _, ok := inner.(net.PacketConn); ok {
		return &packetConn{inner, make([]byte, bufferSize)}
	}
	return &streamConn{inner, bufio.NewReaderSize(inner, bufferSize), nil}
}

// streamConn implements a STUN message framing over stream-oriented network.
type streamConn struct {
	net.Conn
	buf  *bufio.Reader
	peek []byte
}

func (c *streamConn) discard() error {
	if c.peek != nil {
		if _, err := c.buf.Discard(len(c.peek)); err != nil {
			return err
		}
		c.peek = nil
	}
	return nil
}

func (c *streamConn) Read(p []byte) (int, error) {
	if err := c.discard(); err != nil {
		return 0, err
	}
	return c.buf.Read(p)
}

func (c *streamConn) PeekMessage() (b []byte, err error) {
	if err = c.discard(); err != nil {
		return
	}
	if b, err = c.buf.Peek(20); err != nil {
		return
	}
	b, err = c.buf.Peek(getInt16(b[2:]) + 20)
	if err != nil {
		return
	}
	c.peek = b
	return
}

// packetConn implements a STUN message framing over packet-oriented network.
type packetConn struct {
	net.Conn
	read []byte
}

func (c *packetConn) PeekMessage() ([]byte, error) {
	n, err := c.Read(c.read)
	if err != nil {
		return nil, err
	}
	return c.read[:n], nil
}
