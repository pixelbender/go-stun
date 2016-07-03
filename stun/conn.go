package stun

import "net"

// A Conn represents the STUN agent and implements the STUN protocol over net.Conn interface.
type Conn struct {
	net.Conn
}

// NewConn creates a Conn connection on the given net.Conn
func NewConn(inner net.Conn) *Conn {
	return &Conn{inner}
}
