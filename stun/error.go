package stun

import (
	"io"
	"strconv"
)

// RFC 5389 Section 15.6
const (
	ErrTryAlternate     = 300
	ErrBadRequest       = 400
	ErrUnauthorized     = 401
	ErrUnknownAttribute = 420
	ErrStaleNonce       = 438
	ErrServerErr        = 500
)

// RFC 3489 Section 11.2.9
const (
	ErrStaleCredentials      = 430
	ErrIntegrityCheckFailure = 431
	ErrMissingUsername       = 432
	ErrUseTLS                = 433
	ErrGlobalFailure         = 600
)

var errorText = map[int]string{
	ErrTryAlternate:          "Try Alternate",
	ErrBadRequest:            "Bad Request",
	ErrUnauthorized:          "Unauthorized",
	ErrUnknownAttribute:      "Unknown Attribute",
	ErrStaleCredentials:      "Stale Credentials",
	ErrIntegrityCheckFailure: "Integrity Check Failure",
	ErrMissingUsername:       "Missing Username",
	ErrUseTLS:                "Use TLS",
	ErrStaleNonce:            "Stale Nonce",
	ErrServerErr:             "Server Error",
	ErrGlobalFailure:         "Global Failure",
}

func ErrorText(code int) string {
	return errorText[code]
}

type Error struct {
	Code   int
	Reason string
}

func (e *Error) Encode(b []byte) (int, error) {
	n := 4 + len(e.Reason)
	if len(b) < n {
		return 0, io.EOF
	}
	b[0] = 0
	b[1] = 0
	b[2] = byte(e.Code / 100)
	b[3] = byte(e.Code % 100)
	copy(b[4:], e.Reason)
	return n, nil
}

func (e *Error) String() string {
	return strconv.Itoa(e.Code) + " " + e.Reason
}

func DecodeError(b []byte) (*Error, error) {
	if len(b) < 4 {
		return nil, io.EOF
	}
	code := int(b[2])*100 + int(b[3])
	return &Error{code, string(b[4:])}, nil
}
