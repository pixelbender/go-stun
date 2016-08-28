package turn

import (
	"github.com/pixelbender/go-stun/stun"
)

const (
	AllocationTCP = uint8(6)
	AllocationUDP = uint8(17)
)

type Conn struct {
	*stun.Client
	relayed *stun.Addr
}

func NewConn(inner *stun.Client, addr *stun.Addr) *Conn {
	return &Conn{
		Client:  inner,
		relayed: addr,
	}
}

func (c *Conn) RelayedAddr() *stun.Addr {
	// TODO: replace with net.Addr
	return c.relayed
}
