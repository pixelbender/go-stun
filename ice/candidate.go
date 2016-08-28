package ice

import (
	"github.com/pixelbender/go-stun/stun"
	"net"
)

const (
	TypeHost            = "host"
	TypeServerReflexive = "srflx"
	TypePeerReflexive   = "prflx"
	TypeRelay           = "relay"
)

type Candidate struct {
	Type       string
	Transport  string
	Address    *stun.Addr
	BaseAddr   *stun.Addr
	Priority   uint32
	Foundation int
}

func NewLocalCandidates(transports ...string) ([]*Candidate, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var last error
	r := make([]*Candidate, 0, 10)
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			last = err
			continue
		}
		for _, it := range addrs {
			addr, ok := it.(*net.IPNet)
			if !ok {
				continue
			}
			ip := addr.IP
			if ip == nil || ip.IsLoopback() {
				continue
			}
			for _, t := range transports {
				r = append(r, &Candidate{
					Type:      TypeHost,
					Transport: t,
					Address:   &stun.Addr{IP: ip, Port: 9},
				})
			}
		}
	}
	if len(r) == 0 && last != nil {
		return nil, last
	}
	return r, nil
}
