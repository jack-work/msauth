package msauth

import (
	"errors"
	"fmt"
	"strings"
)

// Rendering an *AuthError was the fleet's most-copied function: jacques had
// auth.FormatError, divest had newAuthError, goop had Error.Error, and icy had
// _msauth_failure_text. All four printed the same three facts -- code, message,
// per-source attempts -- in four layouts, so a support answer written against
// one of them did not match what any other tool printed. The layout is now
// here, once, and each adapter supplies only the headline that says what IT was
// doing when acquisition failed.

// FormatError renders err as the fleet's single auth diagnostic. The headline
// names the caller's operation and may be empty. The rendered form is:
//
//	<headline> [<code>]: <message>
//	  <source> [<code>]: <message>
//
// An error that is not an *AuthError renders as the headline and the error's
// own text, so a caller can route every failure through this function without
// first classifying it. Every rendered field has passed through
// SanitizeDiagnostic: the AuthError's own fields on the way in, and an
// unclassified error's text on the way out, here.
func FormatError(headline string, err error) string {
	return formatError(headline, err, "\n  ")
}

// FormatErrorLine renders err as one line, joining the attempts with "; ":
//
//	<headline> [<code>]: <message>; <source> [<code>]: <message>
//
// It exists because FormatError's indented form cannot be used where a newline
// changes the meaning of the surrounding format. tomb puts this diagnostic in
// four slog attribute values and one span error, and an embedded newline there
// breaks line-oriented log consumption, so tomb kept the fleet's last private
// renderer rather than degrade its logs. A structured-log consumer needs a
// single-line rendering; it does not need a rendering of its own.
//
// The result is guaranteed free of newlines even when err is not an *AuthError
// and carries multi-line text of its own: an unclassified wrapped error is
// exactly the value most likely to arrive with a stack trace in it, and a
// "single-line" renderer that emits three lines for that one input is worse
// than none, because the caller stops checking.
func FormatErrorLine(headline string, err error) string {
	return strings.TrimSpace(spacePattern.ReplaceAllString(formatError(headline, err, "; "), " "))
}

// Both renderings read the same fields in the same order and differ only in
// the separator, so a change to WHAT is rendered cannot reach one form and miss
// the other. That is the whole reason the line form lives here rather than in
// the client that needs it.
func formatError(headline string, err error, separator string) string {
	if err == nil {
		return ""
	}
	headline = strings.TrimSpace(headline)
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		// An UNCLASSIFIED error is the one value in this function that no part
		// of this package wrote, and therefore the one most likely to carry a
		// URL with a token in it, a raw service body, or a stack trace. It was
		// quoted verbatim until tomb declined to adopt this renderer without
		// wrapping it in tomb's own sanitizer -- correctly, and that refusal is
		// the evidence the guarantee belonged here. A shared renderer that is
		// safe only for the errors it built itself is not a shared renderer;
		// every adapter would keep exactly one wrapper, which is what this
		// package exists to delete.
		text := SanitizeDiagnostic(err.Error())
		if headline == "" {
			return text
		}
		return headline + ": " + text
	}
	var b strings.Builder
	if headline != "" {
		b.WriteString(headline)
		b.WriteString(" ")
	}
	fmt.Fprintf(&b, "[%s]: %s", authErr.Code, authErr.Message)
	for _, attempt := range authErr.Attempts {
		fmt.Fprintf(&b, "%s%s [%s]: %s", separator, attempt.Source, attempt.Code, attempt.Message)
	}
	return b.String()
}

// Hint returns the one action that fixes err, or "" when this package cannot
// name one. It is derived from the stable codes rather than from prose, and it
// considers the per-source attempts because the top-level code of a failed
// wam-first acquisition is acquisition_failed while the actionable fault is
// recorded underneath it.
//
// The hints are deliberately few. A hint that is wrong is worse than none: it
// sends a signed-in user to re-run a login that was never the problem.
func Hint(err error) string {
	if err == nil {
		return ""
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		return ""
	}
	codes := map[ErrorCode]bool{authErr.Code: true}
	for _, attempt := range authErr.Attempts {
		codes[attempt.Code] = true
	}
	// A broken broker environment outranks a cold Azure CLI: it is the fault
	// that a signed-in user cannot diagnose, and msauth doctor is the only
	// command that explains it.
	if codes[CodeBrokerUnavailable] || codes[CodeBrokerAssemblyMismatch] {
		return "Run: msauth doctor"
	}
	if codes[CodeAzureCLIFailed] {
		return "Run: az login"
	}
	return ""
}
