package stun

import "net"

// Dial connects to the given network address using net.Dial, returning the STUN connection
func Dial(network, address string) (*Conn, error) {
	c, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return NewConn(c), err
}
