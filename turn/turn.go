package turn

import (
	"crypto/tls"
	"errors"
	"github.com/pixelbender/go-stun/stun"
	"net"
	"net/url"
	"strings"
)

// Allocate connects to the given TURN URI and makes the TURN allocation request.
// Returns the relayed transport address.
func Allocate(uri, username, password string) (*Conn, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	p := u.Query()

	var conn net.Conn
	switch strings.ToLower(u.Scheme) {
	case "turn":
		network := "udp"
		if p.Get("transport") == "tcp" {
			network = "tcp"
		}
		conn, err = net.Dial(network, getServerAddress(u.Opaque, false))
	case "turns":
		conn, err = tls.Dial("tcp", getServerAddress(u.Opaque, true), nil)
	default:
		err = errUnsupportedScheme
	}
	if err != nil {
		return nil, err
	}
	config := new(Config)
	config.GetAuthKey = stun.LongTermAuthKey(username, password)

	c, err := NewConn(conn, config)
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// ListenAndServe listens on the network address and calls handler to serve requests.
func ListenAndServe(network, addr string, handler stun.Handler) error {
	srv := NewServer()
	srv.Handler = handler
	return srv.ListenAndServe(network, addr)
}

// ListenAndServeTLS listens on the network address secured by TLS and calls handler to serve requests.
func ListenAndServeTLS(network, addr string, certFile, keyFile string, handler stun.Handler) error {
	srv := NewServer()
	srv.Handler = handler
	return srv.ListenAndServeTLS(network, addr, certFile, keyFile)
}

var errUnsupportedScheme = errors.New("turn: unsupported scheme")

func getServerAddress(hostport string, secure bool) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if port == "" {
		if secure {
			port = "5478"
		} else {
			port = "3478"
		}
	}
	return net.JoinHostPort(host, port)
}
