package stun

import (
	"encoding/binary"
	"fmt"
	"github.com/pixelbender/go-stun/mux"
	"net"
	"reflect"
	"strconv"
	"time"
)

const (
	// Attributes introduced by the RFC 5389 Section 18.2.
	AttrMappedAddress     attr = 0x0001
	AttrXorMappedAddress  attr = 0x0020
	AttrUsername          attr = 0x0006
	AttrMessageIntegrity  attr = 0x0008
	AttrErrorCode         attr = 0x0009
	AttrRealm             attr = 0x0014
	AttrNonce             attr = 0x0015
	AttrUnknownAttributes attr = 0x000a
	AttrSoftware          attr = 0x8022
	AttrAlternateServer   attr = 0x8023
	AttrFingerprint       attr = 0x8028

	// Attributes introduced by the RFC 5780 Section 7.
	AttrChangeRequest  attr = 0x0003
	AttrPadding        attr = 0x0026
	AttrResponsePort   attr = 0x0027
	AttrResponseOrigin attr = 0x802b
	AttrOtherAddress   attr = 0x802c

	// Attributes introduced by the RFC 3489 Section 11.2 except listed above.
	AttrResponseAddress attr = 0x0002
	AttrSourceAddress   attr = 0x0004
	AttrChangedAddress  attr = 0x0005
	AttrPassword        attr = 0x0007
	AttrReflectedFrom   attr = 0x000b
)

var attrNames = map[attr]string{
	AttrMappedAddress:     "MAPPED-ADDRESS",
	AttrXorMappedAddress:  "XOR-MAPPED-ADDRESS",
	AttrUsername:          "USERNAME",
	AttrMessageIntegrity:  "MESSAGE-INTEGRITY",
	AttrFingerprint:       "FINGERPRINT",
	AttrErrorCode:         "ERROR-CODE",
	AttrRealm:             "REALM",
	AttrNonce:             "NONCE",
	AttrUnknownAttributes: "UNKNOWN-ATTRIBUTES",
	AttrSoftware:          "SOFTWARE",
	AttrAlternateServer:   "ALTERNATE-SERVER",
	AttrChangeRequest:     "CHANGE-REQUEST",
	AttrPadding:           "PADDING",
	AttrResponsePort:      "RESPONSE-PORT",
	AttrResponseOrigin:    "RESPONSE-ORIGIN",
	AttrOtherAddress:      "OTHER-ADDRESS",
	AttrResponseAddress:   "RESPONSE-ADDRESS",
	AttrSourceAddress:     "SOURCE-ADDRESS",
	AttrChangedAddress:    "CHANGED-ADDRESS",
	AttrPassword:          "PASSWORD",
	AttrReflectedFrom:     "REFLECTED-FROM",
}

var attrRegistry = map[uint16]attr {
}

func RegisterAttribute(at Attr) {
	attrRegistry[at.Type()] = at
}

func GetAttribute(at uint16) Attr {
	return attrRegistry[at]
}

type attr uint16

func (at attr) Type() uint16 {
	return uint16(at)
}

func (at attr) Decode(m *Message, r mux.Reader) (v interface{}, err error) {
	var b []byte
	switch at {
	case AttrMappedAddress, AttrXorMappedAddress, AttrAlternateServer, AttrResponseOrigin, AttrOtherAddress, AttrResponseAddress, AttrSourceAddress, AttrChangedAddress, AttrReflectedFrom:
		if b, err = r.Next(4); err != nil {
			return
		}
		n, port := net.IPv4len, int(be.Uint16(b[2:]))
		if b[1] == 0x02 {
			n = net.IPv6len
		}
		if b, err = r.Next(n); err != nil {
			return
		}
		ip := make([]net.IP, len(b))
		if at == AttrXorMappedAddress {
			for i, it := range b {
				ip[i] = it ^ m.Transaction[i]
			}
			port = port ^ 0x2112
		} else {
			copy(ip, b)
		}
		return &Addr{IP: ip, Port: port}, nil
	case AttrErrorCode:
		if b, err = r.Next(4); err != nil {
			return
		}
		v = &ErrorCode{
			Code:   int(b[2])*100 + int(b[3]),
			Reason: string(r.Bytes()),
		}
	case AttrUnknownAttributes:
		attrs := make(unknownAttributes, 0, r.Buffered()>>1)
		for r.Buffered() > 2 {
			b, _ := r.Next(2)
			attrs = append(attrs, be.Uint16(b))
		}
	case AttrUsername, AttrRealm, AttrNonce, AttrSoftware, AttrPassword:
		v = string(r.Bytes())
	case AttrFingerprint, AttrChangeRequest:
		if b, err = r.Next(4); err != nil {
			return
		}
		v = be.Uint32(b)
	}
	return
}

func (at attr) Encode(m *Message, v interface{}, w mux.Writer) error {
	if raw, ok := v.([]byte); ok {
		copy(w.Next(len(raw)), raw)
	}
	switch at {
	case AttrMappedAddress, AttrXorMappedAddress, AttrAlternateServer, AttrResponseOrigin, AttrOtherAddress, AttrResponseAddress, AttrSourceAddress, AttrChangedAddress, AttrReflectedFrom:
		if addr, ok := v.(*Addr); ok {
			fam, sh := byte(0x01), addr.IP.To4()
			if len(sh) == 0 {
				fam, sh = byte(0x02), addr.IP
			}
			b := w.Next(4 + len(sh))
			b[0] = 0
			b[1] = fam
			if at == AttrXorMappedAddress {
				be.PutUint16(b[2:], uint16(addr.Port)^0x2112)
				b = b[4:]
				for i, it := range sh {
					b[i] = it ^ m.Transaction[i]
				}
			} else {
				be.PutUint16(b[2:], uint16(addr.Port))
				copy(b[4:], sh)
			}
		}
	case AttrErrorCode:
		if err, ok := v.(*ErrorCode); ok {
			b := w.Next(4 + len(err.Reason))
			b[0] = 0
			b[1] = 0
			b[2] = byte(err.Code / 100)
			b[3] = byte(err.Code % 100)
			copy(b[4:], err.Reason)
		}
	case AttrUnknownAttributes:
		if attrs, ok := v.(unknownAttributes); ok {
			b := w.Next(len(attrs) << 1)
			for i, it := range attrs {
				be.PutUint16(b[i<<1:], it)
			}
		}
	case AttrUsername, AttrRealm, AttrNonce, AttrSoftware, AttrPassword:
		if s, ok := v.(string); ok {
			copy(w.Next(len(s)), s)
		}
	case AttrFingerprint, AttrChangeRequest:
		if u, ok := v.(uint32); ok {
			be.PutUint32(w.Next(4), u)
		}
	}
	return nil
}

func (at attr) String() string {
	if v, ok := attrNames[at]; ok {
		return v
	}
	return fmt.Sprintf("0x%4x", at)
}

// ErrorCode represents the ERROR-CODE attribute.
type ErrorCode struct {
	Code   int
	Reason string
}

func (c *ErrorCode) String() string {
	return c.Reason
}

// Addr represents a transport address attribute.
type Addr struct {
	IP   net.IP
	Port int
}

func (addr *Addr) String() string {
	return net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))
}

type unknownAttributes []uint16

const (
	// Error codes introduced by the RFC 5389 Section 15.6
	ErrTryAlternate     code = 300
	ErrBadRequest       code = 400
	ErrUnauthorized     code = 401
	ErrUnknownAttribute code = 420
	ErrStaleNonce       code = 438
	ErrServerError      code = 500

	// Error codes introduced by the RFC 3489 Section 11.2.9 except listed in RFC 5389.
	ErrStaleCredentials      code = 430
	ErrIntegrityCheckFailure code = 431
	ErrMissingUsername       code = 432
	ErrUseTLS                code = 433
	ErrGlobalFailure         code = 600
)

var errorText = map[code]string{
	ErrTryAlternate:          "Try alternate",
	ErrBadRequest:            "Bad request",
	ErrUnauthorized:          "Unauthorized",
	ErrUnknownAttribute:      "Unknown attribute",
	ErrStaleCredentials:      "Stale credentials",
	ErrIntegrityCheckFailure: "Integrity check failure",
	ErrMissingUsername:       "Missing username",
	ErrUseTLS:                "Use TLS",
	ErrStaleNonce:            "Stale nonce",
	ErrServerError:           "Server error",
	ErrGlobalFailure:         "Global failure",
}



type code int

func (c code) Code() int {
	return int(c)
}

func (c code) Error() string {
	return errorText[c]
}

var be = binary.BigEndian


func init() {
	for at := range attrNames {
		RegisterAttribute(at)
	}
}