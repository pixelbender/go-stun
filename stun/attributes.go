package stun

import (
	"fmt"
	"github.com/pixelbender/go-stun/mux"
	"net"
	"sync"
)

const (
	// Attributes introduced by the RFC 5389 Section 18.2.
	AttrMappedAddress attr = 0x0001
	AttrXorMappedAddress attr = 0x0020
	AttrUsername attr = 0x0006
	AttrMessageIntegrity attr = 0x0008
	AttrErrorCode attr = 0x0009
	AttrRealm attr = 0x0014
	AttrNonce attr = 0x0015
	AttrUnknownAttributes attr = 0x000a
	AttrSoftware attr = 0x8022
	AttrAlternateServer attr = 0x8023
	AttrFingerprint attr = 0x8028

	// Attributes introduced by the RFC 5780 Section 7.
	AttrChangeRequest attr = 0x0003
	AttrPadding attr = 0x0026
	AttrResponsePort attr = 0x0027
	AttrResponseOrigin attr = 0x802b
	AttrOtherAddress attr = 0x802c

	// Attributes introduced by the RFC 3489 Section 11.2 except listed above.
	AttrResponseAddress attr = 0x0002
	AttrSourceAddress attr = 0x0004
	AttrChangedAddress attr = 0x0005
	AttrPassword attr = 0x0007
	AttrReflectedFrom attr = 0x000b
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

type attr uint16

func (at attr) Type() uint16 {
	return uint16(at)
}

func (at attr) Decode(p *Packet, r mux.Reader) (v interface{}, err error) {
	var b []byte
	switch at {
	case AttrMappedAddress, AttrXorMappedAddress, AttrAlternateServer,
		AttrResponseOrigin, AttrOtherAddress, AttrResponseAddress,
		AttrSourceAddress, AttrChangedAddress, AttrReflectedFrom:
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
		ip := make([]byte, len(b))
		if at == AttrXorMappedAddress {
			for i, it := range b {
				ip[i] = it ^ p.Transaction[i]
			}
			port = port ^ 0x2112
		} else {
			copy(ip, b)
		}
		return &Addr{IP: net.IP(ip), Port: port}, nil
	case AttrErrorCode:
		if b, err = r.Next(4); err != nil {
			return
		}
		v = &ErrorCode{
			Code:   int(b[2]) * 100 + int(b[3]),
			Reason: string(r.Bytes()),
		}
	case AttrUnknownAttributes:
		b := r.Bytes()
		attrs := make([]uint16, 0, len(b) >> 1)
		for len(b) > 2 {
			attrs = append(attrs, be.Uint16(b))
			b = b[2:]
		}
	case AttrUsername, AttrRealm, AttrNonce, AttrSoftware, AttrPassword:
		v = string(r.Bytes())
	case AttrFingerprint, AttrChangeRequest:
		if b, err = r.Next(4); err != nil {
			return
		}
		v = be.Uint32(b)
	case AttrMessageIntegrity:
		v = r.Bytes()
	}
	return
}

func (at attr) Encode(p *Packet, w mux.Writer, v interface{}) error {
	if raw, ok := v.([]byte); ok {
		copy(w.Next(len(raw)), raw)
	}
	switch at {
	case AttrMappedAddress, AttrXorMappedAddress, AttrAlternateServer,
		AttrResponseOrigin, AttrOtherAddress, AttrResponseAddress,
		AttrSourceAddress, AttrChangedAddress, AttrReflectedFrom:
		if addr, ok := v.(*Addr); ok {
			fam, sh := byte(0x01), addr.IP.To4()
			if len(sh) == 0 {
				fam, sh = byte(0x02), addr.IP
			}
			b := w.Next(4 + len(sh))
			b[0] = 0
			b[1] = fam
			if at == AttrXorMappedAddress {
				be.PutUint16(b[2:], uint16(addr.Port) ^ 0x2112)
				b = b[4:]
				for i, it := range sh {
					b[i] = it ^ p.Transaction[i]
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
		if attrs, ok := v.([]uint16); ok {
			b := w.Next(len(attrs) << 1)
			for i, it := range attrs {
				be.PutUint16(b[i << 1:], it)
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

const (
	// Error codes introduced by the RFC 5389 Section 15.6
	CodeTryAlternate int = 300
	CodeBadRequest int = 400
	CodeUnauthorized int = 401
	CodeUnknownAttribute int = 420
	CodeStaleNonce int = 438
	CodeServerError int = 500

	// Error codes introduced by the RFC 3489 Section 11.2.9 except listed in RFC 5389.
	CodeStaleCredentials int = 430
	CodeIntegrityCheckFailure int = 431
	CodeMissingUsername int = 432
	CodeUseTLS int = 433
	CodeGlobalFailure int = 600
)

var errorText = map[int]string{
	CodeTryAlternate:          "Try alternate",
	CodeBadRequest:            "Bad request",
	CodeUnauthorized:          "Unauthorized",
	CodeUnknownAttribute:      "Unknown attribute",
	CodeStaleCredentials:      "Stale credentials",
	CodeIntegrityCheckFailure: "Integrity check failure",
	CodeMissingUsername:       "Missing username",
	CodeUseTLS:                "Use TLS",
	CodeStaleNonce:            "Stale nonce",
	CodeServerError:           "Server error",
	CodeGlobalFailure:         "Global failure",
}

func ErrorText(code int) string {
	return errorText[code]
}

var (
	mu = sync.Mutex{}
	attributes = map[uint16]Attr{}
)

func RegisterAttribute(at Attr) {
	mu.Lock()
	attributes[at.Type()] = at
	mu.Unlock()
}

func init() {
	for at := range attrNames {
		RegisterAttribute(at)
	}
}
