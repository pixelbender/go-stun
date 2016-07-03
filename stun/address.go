package stun

import (
	"io"
	"net"
	"strconv"
)

// Addr represents a transport address attribute.
type Addr struct {
	IP   net.IP
	Port uint16
}

// Encode writes the transport address to the byte array.
func (addr *Addr) Encode(b []byte) (int, error) {
	ip, af := addr.IP.To4(), 0x01
	if len(ip) == 0 {
		ip = addr.IP
		af = 0x02
	}
	n := 4 + len(ip)
	if len(b) < n {
		return 0, io.ErrUnexpectedEOF
	}
	b[0] = 0
	b[1] = byte(af)
	b = b[4:]
	putUint16(b[2:], addr.Port)
	copy(b[8:], ip)
	return n, nil
}

var xorMask = []byte{0x21, 0x12, 0xa4, 0x42}

// Xor obfuscates or deobfuscates transport address using XOR function.
func (addr *Addr) Xor() {
	for i, it := range addr.IP {
		addr.IP[i] = it ^ xorMask[i%4]
	}
	addr.Port ^= 0x2112
}

// String returns the "host:port" form of the transport address.
func (addr *Addr) String() string {
	return net.JoinHostPort(addr.IP.String(), strconv.Itoa(int(addr.Port)))
}

// DecodeAddress reads the transport address from the byte array.
func DecodeAddress(b []byte) (*Addr, error) {
	if len(b) < 4 {
		return nil, io.EOF
	}
	if b[0] != 0 {
		return nil, ErrWrongFormat
	}
	m, port := net.IPv4len, getUint16(b[2:])
	if b[1] == 0x02 {
		m = net.IPv6len
	}
	if b = b[4:]; len(b) < m {
		return nil, io.EOF
	}
	ip := make(net.IP, m)
	copy(ip, b)
	return &Addr{ip, port}, nil
}
