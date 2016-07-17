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

type addressCodec struct {
	xored bool
}

var AddressCodec addressCodec
var XorAddressCodec = addressCodec{true}

// xorMask is used for obfuscation or deobfuscation of the transport address using XOR function.
var xorMask = []byte{0x21, 0x12, 0xa4, 0x42}

func (codec addressCodec) Encode(attr Attribute, b []byte) (int, error) {
	switch c := attr.(type) {
	case *net.UDPAddr:
		return codec.encodeAddress(c.IP, c.Port, b)
	case *net.TCPAddr:
		return codec.encodeAddress(c.IP, c.Port, b)
	case *Addr:
		return codec.encodeAddress(c.IP, c.Port, b)
	}
	return defaultCodec.Encode(attr, b)
}

func (codec addressCodec) encodeAddress(ip net.IP, port int, b []byte) (int, error) {
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
	if codec.xored {
		putInt16(b[2:], port^0x2112)
		b = b[4:]
		for i, it := range short {
			b[i] = it ^ xorMask[i%4]
		}
	} else {
		putInt16(b[2:], port)
		copy(b[4:], short)
	}
	return n, nil
}

func (codec addressCodec) Decode(b []byte) (Attribute, error) {
	if len(b) < 4 {
		return nil, io.EOF
	}
	if b[0] != 0 {
		return nil, ErrBadFormat
	}
	n, port := net.IPv4len, getInt16(b[2:])
	if b[1] == 0x02 {
		n = net.IPv6len
	}
	if b = b[4:]; len(b) < n {
		return nil, io.EOF
	}
	ip := make(net.IP, n)
	if codec.xored {
		for i, it := range b {
			ip[i] = it ^ xorMask[i%4]
		}
		return &Addr{ip, port ^ 0x2112}, nil
	} else {
		copy(ip, b)
	}
	return &Addr{ip, port}, nil
}
