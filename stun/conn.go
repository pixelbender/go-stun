package stun

import "net"

type Conn struct {
	net.Conn
}

func NewConn(inner net.Conn) *Conn {
	return &Conn{inner}
}
