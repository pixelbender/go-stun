package turn

import (
	"crypto/tls"
	"errors"
	"github.com/pixelbender/go-stun/stun"
	"net"
	"net/url"
	"strings"
)

var ErrUnsupportedScheme = errors.New("turn: unsupported scheme")
var ErrNoAllocationResponse = errors.New("turn: no allocated address")

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
		conn, err = net.Dial(network, stun.GetServerAddress(u.Opaque, false))
	case "turns":
		conn, err = tls.Dial("tcp", stun.GetServerAddress(u.Opaque, true), nil)
	default:
		err = ErrUnsupportedScheme
	}
	if err != nil {
		return nil, err
	}
	c := stun.NewClient(conn, &stun.Config{
		GetAuthKey:        stun.LongTermAuthKey(username, password),
		GetAttributeCodec: GetAttributeCodec,
	})

	msg, err := c.RoundTrip(&stun.Message{
		Method: MethodAllocate,
		Attributes: stun.Attributes{
			AttrRequestedTransport: AllocationUDP,
		},
	})
	if err != nil {
		return nil, err
	}
	if addr, ok := msg.Attributes[AttrXorRelayedAddress]; ok {
		return NewConn(c, addr.(*stun.Addr)), nil
	}
	return nil, ErrNoAllocationResponse
}
