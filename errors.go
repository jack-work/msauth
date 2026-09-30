package msauth

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrorCode is stable across the Go and JSON APIs.
type ErrorCode string

const (
	CodeInvalidRequest    ErrorCode = "invalid_request"
	CodeAcquisitionFailed ErrorCode = "acquisition_failed"
	CodeWAMUnavailable    ErrorCode = "wam_unavailable"
	CodeWAMFailed         ErrorCode = "wam_failed"

	// The two broker codes separate an environment fault from a sign-in fault.
	// broker_unavailable means nothing could load the broker at all;
	// broker_assembly_mismatch means an Az.Accounts is installed but its MSAL
	// assembly set is internally inconsistent and would throw
	// ReflectionTypeLoadException. Both are fixed by installing a current
	// Az.Accounts, and neither means the user is signed out, so a caller must
	// be able to tell them from wam_failed without parsing prose.
	CodeBrokerUnavailable      ErrorCode = "broker_unavailable"
	CodeBrokerAssemblyMismatch ErrorCode = "broker_assembly_mismatch"
	CodeAzureCLIFailed         ErrorCode = "azure_cli_failed"
	CodeProtectFailed          ErrorCode = "protect_failed"
	CodeNotFound               ErrorCode = "not_found"
	CodeInternal               ErrorCode = "internal_error"

	// The WSL codes mirror the WAM pair for the same reason it exists: an
	// environment fault and a sign-in fault have different remedies and must be
	// distinguishable without parsing prose.
	//
	// wsl_proxy_unavailable means the bridge to the Windows broker could not be
	// located at all. Historically this was overwhelmingly a PATH fault,
	// because wslinfo lives in /bin and /bin is absent from the PATH of
	// D-Bus-activated and systemd-managed processes; that one masqueraded as a
	// network failure and cost an afternoon before it was named, which is why
	// it gets its own code. The PATH fault no longer reaches here -- resolution
	// falls back to wslInfoFallbacks -- so this code now means wslinfo is
	// genuinely absent, or answered and gave nothing usable.
	//
	// wsl_broker_failed means the bridge worked and the broker declined: no
	// account for the tenant, a refused request, or an unusable response.
	CodeWSLProxyUnavailable ErrorCode = "wsl_proxy_unavailable"
	CodeWSLBrokerFailed     ErrorCode = "wsl_broker_failed"

	// CodeNotAToken means the caller supplied a value that is not a JWT. It is
	// deliberately distinct from invalid_request: "your request is malformed"
	// and "your request is fine and the credential you are holding is not a
	// token" have different remedies, and the second one is the interesting
	// case. It is what a stored container -- a cache file whose JSON wraps a
	// bearer -- reports, which is the fault icy shipped and could not name.
	CodeNotAToken ErrorCode = "not_a_token"

	// The three codes below mean "this build does not understand you", which is
	// a different fault from a request this build understands and rejects. A
	// client that receives one of them should probe capabilities and tell its
	// user to upgrade msauth rather than reporting a malformed request.
	CodeUnsupportedVersion   ErrorCode = "unsupported_version"
	CodeUnsupportedOperation ErrorCode = "unsupported_operation"
	CodeUnsupportedField     ErrorCode = "unsupported_field"
)

// UnsupportedCodes are the codes that indicate a client/binary version skew
// rather than a genuinely bad request.
func UnsupportedCodes() []ErrorCode {
	return []ErrorCode{CodeUnsupportedVersion, CodeUnsupportedOperation, CodeUnsupportedField}
}

// Attempt is a sanitized diagnostic for one credential source.
type Attempt struct {
	Source  string    `json:"source"`
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

// AuthError has a deterministic code and contains no credential material.
type AuthError struct {
	Code     ErrorCode `json:"code"`
	Message  string    `json:"message"`
	Attempts []Attempt `json:"attempts,omitempty"`
}

func (e *AuthError) Error() string {
	return string(e.Code) + ": " + e.Message
}

func newRequestError(format string, args ...any) *AuthError {
	return &AuthError{Code: CodeInvalidRequest, Message: fmt.Sprintf(format, args...)}
}

// Each unsupported-* message names the offending input, the build that
// rejected it, and what that build does support, so the diagnostic is
// actionable without a second round trip.

func newUnsupportedVersionError(version int) *AuthError {
	return &AuthError{
		Code: CodeUnsupportedVersion,
		Message: fmt.Sprintf("protocol version %d is not supported by msauth %s, which speaks protocol version %d",
			version, Version(), ProtocolVersion),
	}
}

func newUnsupportedOperationError(operation string) *AuthError {
	return &AuthError{
		Code: CodeUnsupportedOperation,
		Message: fmt.Sprintf("operation %q is not supported by msauth %s; supported operations are %s",
			operation, Version(), strings.Join(Operations(), ", ")),
	}
}

// UnsupportedFieldError reports a request field this build does not decode.
// It is exported because the JSON decoder that discovers the unknown field
// lives in the command, not in the protocol executor.
func UnsupportedFieldError(field string) *AuthError {
	return &AuthError{
		Code: CodeUnsupportedField,
		Message: fmt.Sprintf("request field %q is not supported by msauth %s; supported fields are %s",
			field, Version(), strings.Join(RequestFields(), ", ")),
	}
}

func acquisitionError(attempts []Attempt) *AuthError {
	return &AuthError{
		Code:     CodeAcquisitionFailed,
		Message:  "no configured credential source could satisfy the token request",
		Attempts: attempts,
	}
}

// attemptFromError records one credential source's failure. A source that
// already produced a deterministic AuthError keeps its own code, so an
// environment fault such as broker_assembly_mismatch is not flattened into the
// generic per-source code and can still be recognized by a client.
func attemptFromError(source string, code ErrorCode, err error) Attempt {
	var authErr *AuthError
	if errors.As(err, &authErr) && authErr.Code != "" {
		return Attempt{Source: source, Code: authErr.Code, Message: sanitizeDiagnostic(authErr.Message)}
	}
	return Attempt{Source: source, Code: code, Message: sanitizeDiagnostic(err.Error())}
}

var (
	jwtPattern    = regexp.MustCompile(`[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}`)
	bearerPattern = regexp.MustCompile(`(?i)(bearer\s+)[^\s,;"']+`)
	// The leading word boundary matters: without it, an assembly identity's
	// PublicKeyToken is redacted, which destroys exactly the evidence a broker
	// diagnostic exists to carry. An assembly public key token is not a secret.
	jsonTokenPattern = regexp.MustCompile(`(?i)("?\b(?:access_?token|refresh_?token|id_?token|token)"?\s*[:=]\s*"?)[^\s,"'}]+`)
	spacePattern     = regexp.MustCompile(`\s+`)
)

// SanitizeDiagnostic removes credential material from text that is about to be
// quoted in an error or a log line, then collapses whitespace and bounds the
// result. It is exported because adapters quote SERVICE responses, which this
// package never sees: goop quotes a SharePoint body, icy quotes an IcM body,
// tomb quotes an authsvc body. Each of those had its own regexp set, so a
// pattern added here reached one caller and not the others -- the id_token
// case was in exactly one of the four. Sanitizing is a property of diagnostics,
// not of any one service, so there is one implementation and it is this one.
//
// It is a defense in depth, not a license: text known to contain a credential
// must not be quoted at all.
//
// Empty input returns empty. The internal sanitizer substitutes a sentence
// about a credential source failing without diagnostics, which is true of the
// per-attempt diagnostics it was written for and FALSE of an adapter quoting a
// bodiless HTTP response: goop found that a 429 with no body would have printed
// "HTTP 429: credential source failed without diagnostics" and sent a reader
// hunting an auth failure that never happened.
func SanitizeDiagnostic(message string) string {
	if strings.TrimSpace(message) == "" {
		return ""
	}
	return sanitizeDiagnostic(message)
}

func sanitizeDiagnostic(message string) string {
	message = jwtPattern.ReplaceAllString(message, "[REDACTED]")
	message = bearerPattern.ReplaceAllString(message, "${1}[REDACTED]")
	message = jsonTokenPattern.ReplaceAllString(message, "${1}[REDACTED]")
	message = strings.TrimSpace(spacePattern.ReplaceAllString(message, " "))
	const limit = 500
	if len(message) > limit {
		message = message[:limit] + "…"
	}
	if message == "" {
		return "credential source failed without diagnostics"
	}
	return message
}
