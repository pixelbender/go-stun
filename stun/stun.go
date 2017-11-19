package stun

import (
	"crypto/md5"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strings"
)

// DiscoverConn allows discovery using an existing net.UDPConn, which is
// temporarily hijacked to communicate with the STUN server. The net.UDPConn
// is returned upon completion of the discovery process, or closed if an error
// occurs.
func DiscoverConn(stunAddr string, c *net.UDPConn) (*net.UDPAddr, error) {
	stunUDPAddr, err := net.ResolveUDPAddr("udp", stunAddr)
	if err != nil {
		return nil, err
	}
	conn := NewConn(&packetConn{c, stunUDPAddr}, nil)

	addr, err := conn.Discover()
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.agent.Stop() // stop the agent's read loop, relinquishing the conn
	return addr.(*net.UDPAddr), nil
}

func Discover(uri string) (net.PacketConn, net.Addr, error) {
	conn, err := Dial(uri, nil)
	if err != nil {
		return nil, nil, err
	}
	addr, err := conn.Discover()
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	conn.agent.Stop() // stop the agent's read loop
	return conn.Conn.(net.PacketConn), addr, nil
}

type AuthMethod func(sess *Session) error

// LongTermAuthMethod returns AuthMethod for long-term credentials.
// Key = MD5(username ":" realm ":" SASLprep(password)).
// SASLprep is defined in RFC 4013.
func LongTermAuthMethod(username, password string) AuthMethod {
	return func(sess *Session) error {
		h := md5.New()
		h.Write([]byte(username + ":" + sess.Realm + ":" + password))
		sess.Username = username
		sess.Key = h.Sum(nil)
		return nil
	}
}

// ShotTermAuthMethod returns AuthMethod for short-term credentials.
// Key = SASLprep(password).
// SASLprep is defined in RFC 4013.
func ShortTermAuthMethod(password string) AuthMethod {
	key := []byte(password)
	return func(sess *Session) error {
		sess.Key = key
		return nil
	}
}

func Dial(uri string, config *Config) (*Conn, error) {
	secure, network, addr, auth, err := parseURI(uri)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	if secure {
		conn, err = tls.Dial(network, addr, nil)
	} else {
		if strings.HasPrefix(network, "udp") {
			conn, err = dialUDP(network, addr)
		} else {
			conn, err = dialTCP(network, addr)
		}
	}
	if err != nil {
		return nil, err
	}
	if auth != nil {
		config = config.Clone()
		config.AuthMethod = auth
	}
	return NewConn(conn, config), nil
}

func parseURI(uri string) (secure bool, network, addr string, auth AuthMethod, err error) {
	var u *url.URL
	if u, err = url.Parse(uri); err != nil {
		return
	}
	host, port, e := net.SplitHostPort(u.Opaque)
	if e != nil {
		host = u.Opaque
	}
	if a := u.User; a != nil {
		if password, ok := a.Password(); ok {
			auth = LongTermAuthMethod(a.Username(), password)
		} else {
			auth = ShortTermAuthMethod(a.Username())
		}
	}
	network = u.Query().Get("transport")
	if network == "" {
		network = "udp"
	}
	switch u.Scheme {
	case "stun", "turn":
		if port == "" {
			port = "3478"
		}
		switch network {
		case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
		default:
			err = errors.New("stun: unsupported transport: " + network)
		}
	case "stuns", "turns":
		if port == "" {
			port = "5478"
		}
		secure = true
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			err = errors.New("stun: unsupported transport: " + network)
		}
	default:
		err = errors.New("stun: unsupported scheme " + u.Scheme)
	}
	addr = net.JoinHostPort(host, port)
	return
}
