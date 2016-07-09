package stun

import (
	"bytes"
	"fmt"
	"net"
)

// A Conn represents the STUN agent and implements the STUN protocol over net.Conn interface.
type Conn struct {
	net.Conn
	enc *Encoder
	dec *Decoder
}

// NewConn creates a Conn connection on the given net.Conn
func NewConn(inner net.Conn) *Conn {
	return &Conn{
		inner,
		NewEncoder(inner),
		NewDecoder(inner),
	}
}

// ReadMessage reads STUN messages from the connection.
func (conn *Conn) ReadMessage() (*Message, error) {
	return conn.dec.Decode()
}

// WriteMessage writes STUN messages to the connection.
func (conn *Conn) WriteMessage(msg *Message) error {
	return conn.enc.Encode(msg)
}

// Exchange sends STUN request and returns STUN response or error.
func (conn *Conn) Exchange(req *Message) (*Message, error) {
	err := conn.WriteMessage(req)
	if err != nil {
		return nil, err
	}
	res, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(req.Transaction, res.Transaction) {
		return nil, fmt.Errorf("stun: transaction error")
	}
	return res, nil
}
