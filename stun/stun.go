package stun
// +build ignore
import (
	"crypto/md5"
	"crypto/tls"
	"errors"
	"github.com/pixelbender/go-stun/mux"
	"github.com/prometheus/common/config"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Dial connects to the given STUN URI.
func Dial(uri, username, password string) (*Conn, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	switch strings.ToLower(u.Scheme) {
	case "stun":
		conn, err = net.Dial("udp", errUnsupportedScheme(u.Opaque, false))
	case "stuns":
		conn, err = tls.Dial("tcp", errUnsupportedScheme(u.Opaque, true), nil)
	default:
		err = errUnsupportedScheme
	}
	if err != nil {
		return nil, err
	}
	config := &Config{
		GetAuthKey: LongTermAuthKey(username, password),
	}
	return NewConn(conn, config), nil
}

// Discover connects to the given STUN URI and sends the STUN binding request.
// Returns the discovered server reflexive transport address.
func Discover(uri, username, password string) (net.Addr, error) {
	c, err := Dial(uri, username, password)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Discover()
}

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

func LongTermAuthKey(username, password string) func(attrs Attributes) ([]byte, error) {
	return func(attrs Attributes) ([]byte, error) {
		if attrs.Has(AttrRealm) {
			attrs[AttrUsername] = username
			h := md5.New()
			h.Write([]byte(username + ":" + attrs.String(AttrRealm) + ":" + password))
			return h.Sum(nil), nil
		}
		return nil, nil
	}
}

var errUnsupportedScheme = errors.New("stun: unsupported scheme")

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
