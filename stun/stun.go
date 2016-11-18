// Package stun provides a interface for STUN protocol.
package stun

import (
	"crypto/md5"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strings"
)

// Dial connects to the given STUN URI.
func Dial(uri string, config *Config) (conn *Conn, err error) {
	u, err := url.Parse(uri)
	if err != nil {
		return
	}
	var c net.Conn
	host, port, err := net.SplitHostPort(u.Opaque)
	if err != nil {
		host = u.Opaque
	}
	switch strings.ToLower(u.Scheme) {
	case "stun":
		if port == "" {
			port = "3478"
		}
		c, err = net.Dial("udp", net.JoinHostPort(host, port))
	case "stuns":
		if port == "" {
			port = "5478"
		}
		c, err = tls.Dial("tcp", net.JoinHostPort(host, port), nil)
	default:
		err = errors.New("stun: unsupported scheme: " + u.Scheme)
	}
	if err != nil {
		return
	}
	return NewConn(c, config), nil
}

// Discover connects to the given STUN URI and sends the STUN binding request.
// Returns the discovered server reflexive transport address.
func Discover(uri string) (*Addr, error) {
	c, err := Dial(uri, nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Discover()
}

/*

// ListenAndServe listens on the network address and calls handler to serve requests.
func ListenAndServe(network, addr string, handler Handler) error {
	srv := &Server{Config: DefaultConfig, Handler: handler}
	return srv.ListenAndServe(network, addr)
}

// ListenAndServeTLS listens on the network address secured by TLS and calls handler to serve requests.
func ListenAndServeTLS(network, addr string, certFile, keyFile string, handler Handler) error {
	srv := &Server{Config: DefaultConfig, Handler: handler}
	return srv.ListenAndServeTLS(network, addr, certFile, keyFile)
}
*/

type AuthMethod func(m *Message) ([]byte, error)

func LongTermAuthMethod(username, password string) AuthMethod {
	return func(m *Message) ([]byte, error) {
		h := md5.New()
		h.Write([]byte(username + ":" + m.GetString(AttrRealm) + ":" + password))
		return h.Sum(nil), nil
	}
}

func ShotTermAuthMethod(key string) AuthMethod {
	b := []byte(key)
	return func(m *Message) ([]byte, error) {
		return b, nil
	}
}
