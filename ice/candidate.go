package ice

import (
	"github.com/pixelbender/go-sdp/sdp"
	"net"
	"strconv"
	"strings"
)

const (
	TypeHost            = "host"
	TypeServerReflexive = "srflx"
	TypePeerReflexive   = "prflx"
	TypeRelay           = "relay"
)

const (
	TransportUDP = "UDP"
	TransportTCP = "TCP"
)

type Addr struct {
	IP   net.IP
	Port int
}

func NewAddr(v net.Addr) *Addr {
	switch addr := v.(type) {
	case *net.UDPAddr:
		return &Addr{addr.IP, addr.Port}
	case *net.TCPAddr:
		return &Addr{addr.IP, addr.Port}
	default:
		return nil
	}
}

type Candidate struct {
	Foundation  string
	Component   int
	Transport   string
	Priority    uint32
	Address     *Addr
	Type        string
	BaseAddress *Addr
	Params      map[string]string
}

// ParseCandidate parses an SDP "candidate" attribute value into struct.
// See RFC 5245 Section 15.1
func ParseCandidate(v string) (c *Candidate, err error) {
	v = strings.TrimPrefix(v, "candidate:")
	p := split(v, ' ')
	if len(p) < 6 {
		return nil, &parseError{"candidate", v}
	}
	c = &Candidate{
		Foundation: p[0],
		Transport:  strings.ToUpper(p[2]),
	}
	if c.Component, err = strconv.Atoi(p[1]); err != nil {
		return nil, &parseError{"component", p[1]}
	}
	var prio uint64
	if prio, err = strconv.ParseUint(p[3], 10, 32); err != nil {
		return nil, &parseError{"priority", p[3]}
	}
	c.Priority = uint32(prio)
	ip := net.ParseIP(p[4])
	port, err := strconv.Atoi(p[5])
	if err != nil {
		return nil, &parseError{"port", p[3]}
	}
	c.Address = &Addr{IP: ip, Port: port}
	p = p[6:]
	ip = nil
	for len(p) > 1 {
		switch p[0] {
		case "typ":
			c.Type = p[1]
		case "raddr":
			ip = net.ParseIP(p[1])
		case "rport":
			if port, err = strconv.Atoi(p[1]); err != nil {
				return nil, &parseError{"rport", p[3]}
			}
		default:
			if c.Params == nil {
				c.Params = make(map[string]string)
			}
			c.Params[p[0]] = p[1]
		}
		p = p[2:]
	}
	if ip != nil {
		c.BaseAddress = &Addr{IP: ip, Port: port}
	}
	return
}

// Attribute returns the SDP "candidate" attribute describing the ICE candidate.
func (c *Candidate) Attribute() *sdp.Attribute {
	var w writer
	w.string(c.Foundation)
	w.char(' ')
	w.int(int64(c.Component))
	w.char(' ')
	if c.Transport == "" {
		w.string(TransportUDP)
	} else {
		w.string(c.Transport)
	}
	w.char(' ')
	w.int(int64(c.Priority))
	w.char(' ')
	w.string(c.Address.IP.String())
	w.char(' ')
	w.int(int64(c.Address.Port))
	w.string(" typ ")
	w.string(c.Type)
	if addr := c.BaseAddress; addr != nil {
		w.string(" raddr ")
		w.string(addr.IP.String())
		w.string(" rport ")
		w.int(int64(addr.Port))
	}
	for k, v := range c.Params {
		w.char(' ')
		w.string(k)
		w.char(' ')
		w.string(v)
	}
	return &sdp.Attribute{Name: "candidate", Value: string(w.bytes())}
}

type parseError struct {
	typ string
	val string
}

func (e parseError) Error() string {
	return "invalid " + e.typ + ": " + e.val
}

func split(v string, sep rune) (r []string) {
	off := 0
	for i, it := range v {
		if it == sep {
			r = append(r, v[off:i])
			off = i + 1
		}
	}
	if off < len(v) {
		r = append(r, v[off:])
	}
	return
}

type writer struct {
	buf []byte
	pos int
}

func (w *writer) next(n int) (b []byte) {
	p := w.pos + n
	if len(w.buf) < p {
		b := make([]byte, (1+((p-1)>>8))<<8)
		if w.pos > 0 {
			copy(b, w.buf[:w.pos])
		}
		w.buf = b
	}
	b, w.pos = w.buf[w.pos:p], p
	return
}

func (w *writer) char(v byte) {
	b := w.next(1)
	b[0] = v
}

func (w *writer) int(v int64) {
	b := w.next(20)
	w.pos += len(strconv.AppendInt(b[:0], v, 10)) - len(b)
}

func (w *writer) string(v string) {
	copy(w.next(len(v)), v)
}

func (w *writer) bytes() []byte {
	return w.buf[:w.pos]
}

func sameFoundation(a, b *Candidate) bool {
	if a == b {
		return true
	} else if a == nil || b == nil {
		return false
	}
	return a.Type == b.Type && a.Transport == b.Transport && sameIP(a.Address, b.Address) && sameIP(a.BaseAddress, b.BaseAddress)
}

func sameIP(a, b *Addr) bool {
	if a == b {
		return true
	} else if a == nil || b == nil {
		return false
	}
	return a.IP.Equal(b.IP)
}
