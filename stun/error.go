package stun

import (
	"errors"
	"fmt"
	"io"
	"strconv"
)

// ErrBadFormat is returned by DecodeMessage.
var ErrBadFormat = errors.New("stun: wrong message format")

// ErrUnauthorized is returned by DecodeMessage when STUN request is not authorized.
var ErrUnauthorized = errors.New("stun: unauthorized")

// ErrUnknownAttributes is returned by DecodeMessage when STUN request is not authorized.
type ErrBadFormat struct {
	code int
}

type ErrUnknownAttributes []uint16

func (err ErrUnknownAttributes) Error() string {
	for _, it := range err {

	}
	return fmt.Sprintf("stun: unknown attributes: %+v", err)
}

// Error codes introduced by the RFC 5389 Section 15.6
const (
	StatusTryAlternate     = 300
	StatusBadRequest       = 400
	StatusUnauthorized     = 401
	StatusUnknownAttribute = 420
	StatusStaleNonce       = 438
	StatusServerErr        = 500
)

// Error codes introduced by the RFC 3489 Section 11.2.9 except listed in RFC 5389.
const (
	StatusStaleCredentials      = 430
	StatusIntegrityCheckFailure = 431
	StatusMissingUsername       = 432
	StatusUseTLS                = 433
	StatusGlobalFailure         = 600
)

var statusText = map[int]string{
	StatusTryAlternate:          "Try Alternate",
	StatusBadRequest:            "Bad Request",
	StatusUnauthorized:          "Unauthorized",
	StatusUnknownAttribute:      "Unknown Attribute",
	StatusStaleCredentials:      "Stale Credentials",
	StatusIntegrityCheckFailure: "Integrity Check Failure",
	StatusMissingUsername:       "Missing Username",
	StatusUseTLS:                "Use TLS",
	StatusStaleNonce:            "Stale Nonce",
	StatusServerErr:             "Server Error",
	StatusGlobalFailure:         "Global Failure",
}

// StatusText returns a reason phrase text for the STUN error code. It returns the empty string if the code is unknown.
func StatusText(code int) string {
	return statusText[code]
}

// Error represents the ERROR-CODE attribute.
type Error struct {
	Code   int
	Reason string
}

func NewError(code int) *Error {
	return &Error{code, StatusText(code)}
}

// String returns the string form of the error attribute.
func (e *Error) String() string {
	return strconv.Itoa(e.Code) + " " + e.Reason
}

var defaultErrorCodec errorCodec

type errorCodec struct{}

func (codec errorCodec) Encode(attr Attribute, b []byte) (int, error) {
	switch c := attr.(type) {
	case int:
		return codec.encodeError(c, ErrorText(c), b)
	case Error:
		return codec.encodeError(c.Code, c.Reason, b)
	case error:
		return codec.encodeError(ErrServerErr, c.Error(), b)
	}
	return defaultCodec.Encode(attr, b)
}

func (codec errorCodec) encodeError(code int, reason string, b []byte) (int, error) {
	n := 4 + len(reason)
	if len(b) < n {
		return 0, io.ErrUnexpectedEOF
	}
	b[0] = 0
	b[1] = 0
	b[2] = byte(code / 100)
	b[3] = byte(code % 100)
	copy(b[4:], reason)
	return n, nil
}

func (codec errorCodec) Decode(b []byte) (Attribute, error) {
	if len(b) < 4 {
		return nil, io.EOF
	}
	if b[0] != 0 || b[1] != 0 {
		return nil, ErrWrongFormat
	}
	code := int(b[2])*100 + int(b[3])
	return &Error{code, string(b[4:])}, nil
}
