package stun

import (
	"fmt"
	"net"
)

// Dial connects to the given network address using net.Dial, returning the STUN connection
func Dial(network, address string) (*Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		c, err := net.Dial(network, address)
		if err != nil {
			return nil, err
		}
		return NewConn(c), err
	}
	return nil, fmt.Errorf("stun: dial unsupported network %v", network)
}

// ListenAndServe listens on the network address and calls handler to serve requests.
func ListenAndServe(network, addr string, handler Handler) error {
	srv := &Server{Handler: handler}
	return srv.ListenAndServe(network, addr)
}

// ServePacket accepts incoming STUN requests on the packet-oriented network listener and calls handler to serve requests.
func ServePacket(l net.PacketConn, handler Handler) error {
	srv := &Server{Handler: handler}
	return srv.ServePacket(l)
}

// Serve accepts incoming STUN requests on the listener and calls handler to serve requests.
func Serve(l net.Listener, handler Handler) error {
	srv := &Server{Handler: handler}
	return srv.Serve(l)
}
