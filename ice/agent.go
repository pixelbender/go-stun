package ice

import (
	"errors"
	"github.com/pixelbender/go-stun/mux"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"
)

type Config struct {
	// GetPriority returns the candidate priority according preferences.
	// The priority will be used by ICE to determine the order of the
	// connectivity checks and the relative preference for candidates.
	//
	// If not specified, using the recommended formula from RFC 5245 Section 4.1.2.1.
	GetPriority func(c *Candidate) uint32

	// Controlling indicates if agent has the controlling role.
	Controlling bool

	// Lite indicates if an agent uses the lite implementation.
	Lite bool
}

func (config *Config) getPriority(cand *Candidate) (v uint32) {
	if config.GetPriority != nil {
		return config.GetPriority(cand)
	}
	v = cand.getTypePriority() << 24
	v += (cand.getDirectionPreference()<<13 + uint32(cand.Index)) << 8
	v += uint32(256 - cand.Component)
	return
}

// Agent represents an ICE agent.
type Agent struct {
	m mux.Mux

	config *Config

	Component int
	Username  string
	Password  string

	mu     sync.RWMutex
	local  []*Candidate
	remote []*Candidate
}

func NewAgent(config *Config) *Agent {
	return &Agent{config: config}
}

//func (a *Agent) Gather(config *Config) (error) {
//	if config == nil {
//		config = DefaultConfig
//	}
//	a.addHostCandidates(config.Networks)
//	return &Agent{local: local}, nil
//}
//
//func (a *Agent) AddLocalCandidate(cand *Candidate) {
//
//}
//

func (a *Agent) Listen(networks ...string) ([]*Candidate, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []*Candidate
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()

		for _, it := range addrs {
			addr := it.(*net.IPNet)
			if addr == nil {
				continue
			}
			ip := addr.IP
			if ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			if ip.To4() != nil {
				for _, n := range networks {
					switch n {
					case "udp", "udp4":
						if c, err := a.ListenUDP("udp4", &net.UDPAddr{IP: addr.IP}); err == nil {
							result = append(result, c)
						}
					case "tcp", "tcp4":
						if c, err := a.ListenTCP("tcp4", &net.TCPAddr{IP: addr.IP}); err == nil {
							result = append(result, c)
						}
					}
				}
			} else {
				for _, n := range networks {
					switch n {
					case "udp", "udp6":
						if c, err := a.ListenUDP("udp6", &net.UDPAddr{IP: addr.IP, Zone: iface.Name}); err == nil {
							result = append(result, c)
						}
					case "tcp", "tcp6":
						if c, err := a.ListenTCP("tcp6", &net.TCPAddr{IP: addr.IP, Zone: iface.Name}); err == nil {
							result = append(result, c)
						}
					}
				}
			}
		}
	}
	if len(result) == 0 {
		return nil, errors.New("ice: no network address is available")
	}
	return result, nil
}

func (a *Agent) ListenUDP(network string, addr *net.UDPAddr) (*Candidate, error) {
	c, err := net.ListenUDP(network, addr)
	if err != nil {
		return nil, err
	}
	cand := &Candidate{
		Transport: TransportUDP,
		Address:   NewAddr(c.LocalAddr()),
		Type:      TypeHost,
		conn:      c,
	}
	a.AddLocalCandidate(cand)
	go a.m.ServeConn(c)
	return cand, nil
}

func (a *Agent) ListenTCP(network string, addr *net.TCPAddr) (*Candidate, error) {
	l, err := net.ListenTCP(network, addr)
	if err != nil {
		return nil, err
	}
	cand := &Candidate{
		Transport: TransportTCP,
		Address:   NewAddr(l.Addr()),
		Type:      TypeHost,
		conn:      l,
	}
	a.AddLocalCandidate(cand)
	go a.m.Serve(l)
	return cand, nil
}

/*
func (a *Agent) Discover(uri, username, password string) (*Candidate, error) {
	conn, err := stun.Dial(uri, username, password)
	if err != nil {
		return nil, err
	}
	addr, err := conn.Discover()
	if err != nil {
		return nil, err
	}
	cand := &Candidate{
		Transport: TransportUDP,
		Address:   addr,
		Type:      TypeServerReflexive,
	}
	a.addLocalCandidate(cand, &packetConnCandidate{conn: nil})
	return cand, nil
}

func (a *Agent) Allocate(uri, username, password string) (*Candidate, error) {
	conn, err := turn.Allocate(uri, username, password)
	if err != nil {
		return nil, err
	}
	cand := &Candidate{
		Transport: TransportUDP,
		Address:   conn.RelayedAddr(),
		Type:      TypeRelay,
	}
	a.addLocalCandidate(cand, &turnCandidate{conn: nil})
	return cand, nil
}
*/

func (a *Agent) AddLocalCandidate(cand *Candidate) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, it := range a.local {
		if haveSameFoundation(it, cand) {
			cand.Foundation = it.Foundation
			break
		}
	}
	if cand.Foundation == "" {
		cand.Foundation = strconv.Itoa(len(a.local))
	}
	cand.Index = len(a.local)
	cand.Component = a.Component
	cand.Priority = a.config.getPriority(cand)
	a.local = append(a.local, cand)
}

func (a *Agent) AddRemoteCandidate(c *Candidate) {

	return nil
}

// Close stops gathering and selection
// Also closes all the connections made.
func (a *Agent) Close() error {
	return nil
}

const alphadigits = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func genRandom(abc string, n int) string {
	b := make([]byte, n)
	s := len(abc)
	for i := range b {
		b[i] = abc[rnd.Intn(s)]
	}
	return string(b)
}

var rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
