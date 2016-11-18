package stun

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"github.com/pkg/errors"
	"hash/crc32"
	"net"
	"strconv"
)

var ErrFormat = errors.New("format error")
var ErrUnknownAttr = errors.New("unknown attribute")
var ErrFingerprint = errors.New("fingerprint error")

func NewAttr(typ uint16) Attr {
	switch typ {
	case AttrMappedAddress, AttrXorPeerAddress, AttrXorRelayedAddress, AttrXorMappedAddress,
		AttrAlternateServer, AttrResponseOrigin, AttrOtherAddress, AttrResponseAddress,
		AttrSourceAddress, AttrChangedAddress, AttrReflectedFrom:
		return &Addr{AttrType: typ}
	case AttrChangeRequest:
	case AttrUsername, AttrData, AttrRealm, AttrNonce, AttrAccessToken, AttrReservationToken,
		AttrPadding, AttrSoftware, AttrPassword:
		return &Raw{AttrType: typ}
	case AttrMessageIntegrity:
		return &MessageIntegrity{}
	case AttrErrorCode:
		return &Error{}
	case AttrUnknownAttributes:
		return &UnknownAttributes{}
	case AttrChannelNumber:
	case AttrLifetime:
	case AttrRequestedAddressFamily:
	case AttrEvenPort:
	case AttrRequestedTransport:
	case AttrDontFragment, AttrUseCandidate, AttrIceControlled, AttrIceControlling:
		return Flag(typ)
	case AttrPriority:

		return &Raw{AttrType: typ}

	case AttrResponsePort:
	case AttrConnectionID:
	case AttrTransactionTransmitCounter:
	case AttrCacheTimeout:
	case AttrFingerprint:
		return &Fingerprint{}
	case AttrEcnCheck:
	case AttrThirdPartyAuthorization:
	case AttrMobilityTicket:
	case AttrBandwidth:
	case AttrTimerVal:
	}
	return nil
}

func AttrName(typ uint16) string {
	if r, ok := attrNames[typ]; ok {
		return r
	}
	return "UNKNOWN(0x" + strconv.FormatInt(int64(typ), 16) + ")"
}

func ErrorText(code int) string {
	return errorText[code]
}

type Flag uint16

func (attr Flag) Type() uint16 {
	return uint16(attr)
}

func (Flag) Marshal(p []byte) []byte {
	return p
}

func (Flag) Unmarshal(b []byte) error {
	return nil
}

// Error represents the ERROR-CODE attribute.
type Error struct {
	Code   int
	Reason string
}

func NewError(code int) *Error {
	return &Error{code, ErrorText(code)}
}

func (*Error) Type() uint16 {
	return AttrErrorCode
}

func (e *Error) Marshal(p []byte) []byte {
	r, b := grow(p, 4+len(e.Reason))
	b[0] = 0
	b[1] = 0
	b[2] = byte(e.Code / 100)
	b[3] = byte(e.Code % 100)
	copy(b[4:], e.Reason)
	return r
}

func (e *Error) Unmarshal(b []byte) error {
	if len(b) < 4 {
		return ErrFormat
	}
	e.Code = int(b[2])*100 + int(b[3])
	e.Reason = string(b[4:])
	return nil
}

func (e *Error) Error() string {
	return e.Reason
}

func (e *Error) String() string {
	return e.Reason
}

// Raw contains raw attribute data.
type Raw struct {
	AttrType uint16
	Data     []byte
}

func (attr *Raw) Type() uint16 {
	return attr.AttrType
}

func (attr *Raw) Marshal(p []byte) []byte {
	return append(p, attr.Data...)
}

func (attr *Raw) Unmarshal(p []byte) error {
	attr.Data = p
	return nil
}

func (attr *Raw) String() string {
	return string(attr.Data)
}

// StringAttr represents a string attribute.
type String struct {
	AttrType uint16
	Data     string
}

func (attr *String) Type() uint16 {
	return attr.AttrType
}

func (attr *String) Marshal(p []byte) []byte {
	return append(p, attr.Data...)
}

func (attr *String) Unmarshal(p []byte) error {
	attr.Data = string(p)
	return nil
}

func (attr *String) String() string {
	return attr.Data
}

// Addr represents an address attribute.
type Addr struct {
	AttrType uint16
	IP       net.IP
	Port     int
}

func NewAddr(typ uint16, addr net.Addr) (*Addr, error) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return &Addr{typ, a.IP, a.Port}, nil
	case *net.TCPAddr:
		return &Addr{typ, a.IP, a.Port}, nil
	}
	return nil, errors.New("stun: unsupported address type")
}

func (addr *Addr) Type() uint16 {
	return addr.AttrType
}

func (addr *Addr) Xored() bool {
	switch addr.AttrType {
	case AttrXorMappedAddress, AttrXorPeerAddress, AttrXorRelayedAddress:
		return true
	default:
		return false
	}
}

func (addr *Addr) Marshal(p []byte) []byte {
	return addr.MarshalAddress(p, nil)
}

func (addr *Addr) MarshalAddress(p []byte, tx []byte) []byte {
	fam, ip := 1, addr.IP.To4()
	if ip == nil {
		fam, ip = 2, addr.IP
	}
	r, b := grow(p, 4+len(ip))
	b[0] = 0
	b[1] = byte(fam)
	if tx != nil && addr.Xored() {
		be.PutUint16(b[2:], uint16(addr.Port)^0x2112)
		b = b[4:]
		for i, it := range ip {
			b[i] = it ^ tx[i]
		}
	} else {
		be.PutUint16(b[2:], uint16(addr.Port))
		copy(b[4:], ip)
	}
	return r
}

func (addr *Addr) Unmarshal(b []byte) error {
	return addr.UnmarshalAddress(b, nil)
}

func (addr *Addr) UnmarshalAddress(b []byte, tx []byte) error {
	if len(b) < 4 {
		return ErrFormat
	}
	n, port := net.IPv4len, int(be.Uint16(b[2:]))
	if b[1] == 2 {
		n = net.IPv6len
	}
	if b = b[4:]; len(b) < n {
		return ErrFormat
	}
	addr.IP = make(net.IP, n)
	if tx != nil && addr.Xored() {
		for i, it := range b {
			addr.IP[i] = it ^ tx[i]
		}
		addr.Port = port ^ 0x2112
	} else {
		copy(addr.IP, b)
		addr.Port = port
	}
	return nil
}

func (addr *Addr) String() string {
	return net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))
}

// UnknownAttributes represents the UNKNOWN-ATTRIBUTES attribute.
type UnknownAttributes struct {
	Attributes []uint16
}

func (*UnknownAttributes) Type() uint16 {
	return AttrUnknownAttributes
}

func (attr *UnknownAttributes) Marshal(p []byte) []byte {
	r, b := grow(p, len(attr.Attributes)<<1)
	for i, it := range attr.Attributes {
		be.PutUint16(b[i<<1:], it)
	}
	return r
}

func (attr *UnknownAttributes) Unmarshal(b []byte) error {
	u := make([]uint16, 0, len(b)>>1)
	for len(b) > 2 {
		u = append(u, be.Uint16(b))
		b = b[2:]
	}
	attr.Attributes = u
	return nil
}

func NewMessageIntegrity(key []byte) *MessageIntegrity {
	return &MessageIntegrity{key: key}
}

type MessageIntegrity struct {
	key, sum, raw []byte
}

func (*MessageIntegrity) Type() uint16 {
	return AttrMessageIntegrity
}

func (attr *MessageIntegrity) Marshal(p []byte) []byte {
	return append(p, attr.sum...)
}

func (attr *MessageIntegrity) Unmarshal(b []byte) error {
	if len(b) < 20 {
		return ErrFormat
	}
	attr.sum = b
	return nil
}

func (attr *MessageIntegrity) MarshalSum(p []byte, pos int) []byte {
	be.PutUint16(p[pos+2:], uint16(len(p)+20))
	return attr.Sum(attr.key, p[pos:len(p)-4], p)
}

func (attr *MessageIntegrity) UnmarshalSum(p, raw []byte) error {
	attr.raw = raw
	return attr.Unmarshal(p)
}

func (attr *MessageIntegrity) Sum(key, data, p []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(p)
}

func (attr *MessageIntegrity) Check(key []byte) bool {
	r := attr.raw
	if len(r) < 44 {
		return r == nil
	}
	be.PutUint16(r[2:], uint16(len(r)-20))
	h := attr.Sum(key, r[:len(r)-24], nil)
	return bytes.Equal(h, attr.sum)
}

func (attr *MessageIntegrity) String() string {
	return hex.EncodeToString(attr.sum)
}

var DefaultFingerprint *Fingerprint

type Fingerprint struct {
	sum uint32
	raw []byte
}

func (*Fingerprint) Type() uint16 {
	return AttrFingerprint
}

func (attr *Fingerprint) Marshal(p []byte) []byte {
	r, b := grow(p, 4)
	be.PutUint32(b, attr.sum)
	return r
}

func (attr *Fingerprint) Unmarshal(b []byte) error {
	if len(b) < 4 {
		return ErrFormat
	}
	attr.sum = be.Uint32(b)
	return nil
}

func (attr *Fingerprint) MarshalSum(p []byte, pos int) []byte {
	be.PutUint16(p[pos+2:], uint16(len(p)+4))
	v := attr.Sum(p[pos : len(p)-4])
	r, b := grow(p, 4)
	be.PutUint32(b, v)
	return r
}

func (attr *Fingerprint) UnmarshalSum(p, raw []byte) error {
	attr.raw = raw
	return attr.Unmarshal(p)
}

func (attr *Fingerprint) Sum(p []byte) uint32 {
	return crc32.ChecksumIEEE(p) ^ 0x5354554e
}

func (attr *Fingerprint) Check() bool {
	r := attr.raw
	if len(r) < 28 {
		return r == nil
	}
	be.PutUint16(r[2:], uint16(len(r)-20))
	return attr.Sum(r[:len(r)-8]) == attr.sum
}

func (attr *Fingerprint) String() string {
	return "0x" + strconv.FormatInt(int64(attr.sum), 16)
}

func grow(p []byte, n int) (b, a []byte) {
	l := len(p)
	r := l + n
	if r > cap(p) {
		b = make([]byte, (1+((r-1)>>10))<<10)[:r]
		a = b[l:r]
		if l > 0 {
			copy(b, p[:l])
		}
	} else {
		return p[:r], p[l:r]
	}
	return
}

var be = binary.BigEndian

type errAttribute struct {
	error
	AttrType uint16
}

func (err errAttribute) Error() string {
	return "attribute " + AttrName(err.AttrType) + ": " + err.error.Error()
}
