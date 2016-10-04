package stun

import (
	"crypto/md5"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
	"github.com/prometheus/common/config"
	"github.com/pixelbender/go-stun/mux"
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
		GetAuthKey:LongTermAuthKey(username, password),
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

// Config represents a STUN connection configuration.
type Config struct {
	// GetAuthKey returns a key for a MESSAGE-INTEGRITY attribute generation and validation.
	// Key = MD5(username ":" realm ":" SASLprep(password)) for long-term credentials.
	// Key = SASLprep(password) for short-term credentials.
	// SASLprep is defined in RFC 4013.
	// The Username and Password fields are ignored if GetAuthKey is defined.
	GetAuthKey            func(m *Message) ([]byte, error)

	// GetAttributeCodec returns STUN attribute codec for the specified attribute type.
	// Using stun.GetAttributeCodec if GetAttributeCodec is nil.
	GetAttribute          func(at uint16) Attr

	GetError              func(code int) ErrorCode

	// Retransmission timeout, default is 500ms
	RetransmissionTimeout time.Duration

	// Transaction timeout, default is 39.5 seconds
	TransactionTimeout    time.Duration

	// Fingerprint controls whether a FINGERPRINT attribute will be generated.
	Fingerprint           bool

	// Software is a value for SOFTWARE attribute.
	Software              string
}

func (c *Config) getRetransmissionTimeout() time.Duration {
	if c != nil && c.RetransmissionTimeout > 0 {
		return c.RetransmissionTimeout
	}
	return 500 * time.Millisecond
}

func (c *Config) getTransactionTimeout() time.Duration {
	if c != nil && c.TransactionTimeout > 0 {
		return c.TransactionTimeout
	}
	return 39500 * time.Millisecond
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
