package stun

import (
	"io"
	"net"
	"strconv"
)

// Addr represents a transport address attribute.
type Addr struct {
	IP   net.IP
	Port int
}

// String returns the "host:port" form of the transport address.
func (addr *Addr) String() string {
	return net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))
}

// AddrCodec is the codec for a transport address attribute.
const AddrCodec = addrCodec(false)

// XorAddrCodec is the codec for a XOR-obfuscated transport address attribute.
const XorAddrCodec = addrCodec(true)

type addrCodec bool

func (c addrCodec) Encode(msg *Message, v interface{}, b []byte) (int, error) {
	var ip net.IP
	var port int
	switch a := v.(type) {
	case *net.UDPAddr:
		ip, port = a.IP, a.Port
	case *net.TCPAddr:
		ip, port = a.IP, a.Port
	case *Addr:
		ip, port = a.IP, a.Port
	default:
		return DefaultAttrCodec.Encode(msg, v, b)
	}
	fam, short := byte(0x01), ip.To4()
	if len(short) == 0 {
		fam, short = byte(0x02), ip
	}
	n := 4 + len(ip)
	if len(b) < n {
		return 0, io.ErrUnexpectedEOF
	}
	b[0] = 0
	b[1] = fam
	if c {
		putInt16(b[2:], port^0x2112)
		for i, it := range short {
			b[4+i] = it ^ msg.Transaction[i]
		}
	} else {
		putInt16(b[2:], port)
		copy(b[4:], short)
	}
	return n, nil
}

func (c addrCodec) Decode(msg *Message, b []byte) (interface{}, error) {
	if len(b) < 4 {
		return nil, io.EOF
	}
	n, port := net.IPv4len, getInt16(b[2:])
	if b[1] == 0x02 {
		n = net.IPv6len
	}
	if b = b[4:]; len(b) < n {
		return nil, io.EOF
	}
	ip := make(net.IP, n)
	if c {
		for i, it := range b {
			ip[i] = it ^ msg.Transaction[i]
		}
		return &Addr{IP: ip, Port: port ^ 0x2112}, nil
	}
	copy(ip, b)
	return &Addr{IP: ip, Port: port}, nil
}
