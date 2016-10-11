package stun

const (
	// Error codes introduced by the RFC 5389 Section 15.6
	CodeTryAlternate     int = 300
	CodeBadRequest       int = 400
	CodeUnauthorized     int = 401
	CodeUnknownAttribute int = 420
	CodeStaleNonce       int = 438
	CodeServerError      int = 500

	// Error codes introduced by the RFC 3489 Section 11.2.9 except listed in RFC 5389.
	CodeStaleCredentials      int = 430
	CodeIntegrityCheckFailure int = 431
	CodeMissingUsername       int = 432
	CodeUseTLS                int = 433
	CodeGlobalFailure         int = 600
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

// ErrorCode represents the ERROR-CODE attribute.
type ErrorCode struct {
	Code   int
	Reason string
}
