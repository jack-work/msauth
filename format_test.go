package msauth

import (
	"errors"
	"strings"
	"testing"
)

func TestFormatErrorRendersCodeMessageAndAttempts(t *testing.T) {
	err := &AuthError{
		Code:    CodeAcquisitionFailed,
		Message: "no configured credential source could satisfy the token request",
		Attempts: []Attempt{
			{Source: "wam", Code: CodeBrokerAssemblyMismatch, Message: "Az.Accounts assembly set is inconsistent"},
			{Source: "azure-cli", Code: CodeAzureCLIFailed, Message: "az account get-access-token failed"},
		},
	}

	got := FormatError("teams auth failed", err)
	want := "teams auth failed [acquisition_failed]: no configured credential source could satisfy the token request" +
		"\n  wam [broker_assembly_mismatch]: Az.Accounts assembly set is inconsistent" +
		"\n  azure-cli [azure_cli_failed]: az account get-access-token failed"
	if got != want {
		t.Fatalf("rendered form drifted:\ngot  %q\nwant %q", got, want)
	}
}

func TestFormatErrorWithoutHeadline(t *testing.T) {
	err := &AuthError{Code: CodeNotFound, Message: "no protected secret is stored at the requested path"}
	got := FormatError("", err)
	want := "[not_found]: no protected secret is stored at the requested path"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := FormatError("   ", err); got != want {
		t.Fatalf("blank headline: got %q want %q", got, want)
	}
}

// A caller must be able to route every failure through FormatError without
// classifying it first, or the four hand-rolled renderers come back as four
// hand-rolled type switches.
func TestFormatErrorPassesThroughForeignErrors(t *testing.T) {
	err := errors.New("connection refused")
	if got := FormatError("kusto query failed", err); got != "kusto query failed: connection refused" {
		t.Fatalf("got %q", got)
	}
	if got := FormatError("", err); got != "connection refused" {
		t.Fatalf("got %q", got)
	}
	if got := FormatError("anything", nil); got != "" {
		t.Fatalf("nil error rendered %q", got)
	}
}

// An *AuthError reached through wrapping must render as one, because that is
// how every adapter's own error type carries it.
func TestFormatErrorUnwraps(t *testing.T) {
	wrapped := &wrappedAuthError{cause: &AuthError{Code: CodeWAMFailed, Message: "interaction required"}}
	got := FormatError("goop", wrapped)
	if !strings.Contains(got, "[wam_failed]: interaction required") {
		t.Fatalf("wrapped AuthError was not unwrapped: %q", got)
	}
}

type wrappedAuthError struct{ cause error }

func (e *wrappedAuthError) Error() string { return "wrapped: " + e.cause.Error() }
func (e *wrappedAuthError) Unwrap() error { return e.cause }

// The actionable fault of a failed wam-first acquisition is recorded in an
// attempt, not in the top-level code, so a hint derived only from the top-level
// code would be silent exactly when it is needed.
func TestHintReadsAttemptCodes(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{
			name: "broker fault under a generic failure",
			err: &AuthError{Code: CodeAcquisitionFailed, Attempts: []Attempt{
				{Source: "wam", Code: CodeBrokerUnavailable},
				{Source: "azure-cli", Code: CodeAzureCLIFailed},
			}},
			want: "Run: msauth doctor",
		},
		{
			name: "assembly mismatch outranks a cold CLI",
			err: &AuthError{Code: CodeAcquisitionFailed, Attempts: []Attempt{
				{Source: "wam", Code: CodeBrokerAssemblyMismatch},
				{Source: "azure-cli", Code: CodeAzureCLIFailed},
			}},
			want: "Run: msauth doctor",
		},
		{
			name: "cold Azure CLI only",
			err: &AuthError{Code: CodeAcquisitionFailed, Attempts: []Attempt{
				{Source: "azure-cli", Code: CodeAzureCLIFailed},
			}},
			want: "Run: az login",
		},
		{
			name: "a request this build rejects has no login hint",
			err:  &AuthError{Code: CodeInvalidRequest, Message: "exactly one of scope or audience is required"},
			want: "",
		},
		{
			name: "a version skew is not fixed by signing in",
			err:  &AuthError{Code: CodeUnsupportedOperation},
			want: "",
		},
		{"foreign error", errors.New("boom"), ""},
		{"nil", nil, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := Hint(test.err); got != test.want {
				t.Fatalf("got %q want %q", got, test.want)
			}
		})
	}
}

// SanitizeDiagnostic is exported for adapters that quote service responses.
// The id_token case existed in exactly one of the four private copies this
// replaced, so it is pinned here.
func TestSanitizeDiagnosticIsExportedAndCoversTokenFields(t *testing.T) {
	body := `{"id_token":"aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccc","access_token":"secret-value"}`
	got := SanitizeDiagnostic(body)
	for _, leaked := range []string{"secret-value", "cccccccccc"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("sanitized text still contains %q: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("nothing was redacted: %s", got)
	}
	// Empty input must stay empty. The internal sanitizer names a credential
	// failure, which is false when an adapter is quoting a bodiless HTTP
	// response, and that false accusation is what this wrapper exists to avoid.
	for _, empty := range []string{"", "   ", "\n\t"} {
		if got := SanitizeDiagnostic(empty); got != "" {
			t.Fatalf("SanitizeDiagnostic(%q) = %q, want empty", empty, got)
		}
	}
	// Negative control: an assembly identity's PublicKeyToken is evidence, not
	// a secret, and must survive.
	identity := "Microsoft.Identity.Client, Version=4.61.3.0, PublicKeyToken=0a613f4dd989e8ae"
	if got := SanitizeDiagnostic(identity); got != identity {
		t.Fatalf("assembly identity was mangled: %q", got)
	}
}

func TestFormatErrorLineRendersOnOneLine(t *testing.T) {
	err := &AuthError{
		Code:    CodeAcquisitionFailed,
		Message: "no configured credential source could satisfy the token request",
		Attempts: []Attempt{
			{Source: "wam", Code: CodeBrokerAssemblyMismatch, Message: "Az.Accounts assembly set is inconsistent"},
			{Source: "azure-cli", Code: CodeAzureCLIFailed, Message: "az account get-access-token failed"},
		},
	}

	got := FormatErrorLine("teams auth failed", err)
	want := "teams auth failed [acquisition_failed]: no configured credential source could satisfy the token request" +
		"; wam [broker_assembly_mismatch]: Az.Accounts assembly set is inconsistent" +
		"; azure-cli [azure_cli_failed]: az account get-access-token failed"
	if got != want {
		t.Fatalf("line form drifted:\ngot  %q\nwant %q", got, want)
	}
}

// The two renderings must differ ONLY in the separator. This is the assertion
// that keeps the line form from becoming a second layout: a field added to one
// and not the other fails here rather than in whichever client noticed first.
func TestFormatErrorLineIsTheSameFieldsAsFormatError(t *testing.T) {
	cases := []error{
		&AuthError{Code: CodeNotFound, Message: "no protected secret is stored at the requested path"},
		&AuthError{
			Code:    CodeAcquisitionFailed,
			Message: "no configured credential source could satisfy the token request",
			Attempts: []Attempt{
				{Source: "wam", Code: CodeBrokerUnavailable, Message: "no PowerShell host could load the broker"},
			},
		},
		&wrappedAuthError{cause: &AuthError{Code: CodeWAMFailed, Message: "interaction required"}},
	}
	for _, headline := range []string{"", "tomb graph auth failed"} {
		for _, err := range cases {
			multi := FormatError(headline, err)
			line := FormatErrorLine(headline, err)
			if want := strings.ReplaceAll(multi, "\n  ", "; "); line != want {
				t.Fatalf("headline %q: line form is not the multi-line form with a separator swap:\ngot  %q\nwant %q",
					headline, line, want)
			}
		}
	}
}

// The single guarantee a structured-log consumer actually depends on. A
// foreign error carrying its own newlines is the input that breaks it, so it
// is the input the test uses.
func TestFormatErrorLineNeverContainsANewline(t *testing.T) {
	inputs := []error{
		errors.New("dial tcp: lookup login.microsoftonline.com\n\tno such host\n"),
		&AuthError{Code: CodeInternal, Message: "first line\nsecond line"},
		&AuthError{
			Code:     CodeAcquisitionFailed,
			Message:  "no configured credential source could satisfy the token request",
			Attempts: []Attempt{{Source: "wam", Code: CodeWAMFailed, Message: "System.Exception:\n   at Foo()\r\n   at Bar()"}},
		},
	}
	for _, err := range inputs {
		got := FormatErrorLine("tomb", err)
		if strings.ContainsAny(got, "\n\r") {
			t.Fatalf("FormatErrorLine emitted a line break: %q", got)
		}
		if strings.Contains(got, "  ") {
			t.Fatalf("FormatErrorLine emitted a run of spaces: %q", got)
		}
	}
	if got := FormatErrorLine("anything", nil); got != "" {
		t.Fatalf("nil error rendered %q", got)
	}
}

// The renderer's promise has to cover the errors it did NOT build, or every
// adapter keeps a wrapper for exactly this case -- which is what tomb did, and
// was right to do, until this guarantee existed.
func TestFormatErrorSanitizesUnclassifiedErrors(t *testing.T) {
	leaky := errors.New(`GET https://example.invalid/api failed: {"access_token":"abc.def.ghi","trace":"eyJhbGciOiJSUzI1NiJ9.eyJ1cG4iOiJ1c2VyIn0.c2lnbmF0dXJl"}`)
	for _, rendered := range []string{
		FormatError("teams auth failed", leaky),
		FormatErrorLine("teams auth failed", leaky),
		FormatError("", leaky),
		FormatErrorLine("", leaky),
	} {
		if strings.Contains(rendered, "abc.def.ghi") {
			t.Fatalf("access_token survived the renderer: %q", rendered)
		}
		if strings.Contains(rendered, "eyJhbGciOiJSUzI1NiJ9.eyJ1cG4iOiJ1c2VyIn0.c2lnbmF0dXJl") {
			t.Fatalf("JWT survived the renderer: %q", rendered)
		}
		if !strings.Contains(rendered, "[REDACTED]") {
			t.Fatalf("nothing was redacted, so the input never reached the sanitizer: %q", rendered)
		}
		if !strings.Contains(rendered, "example.invalid") {
			t.Fatalf("sanitizing destroyed the diagnostic itself: %q", rendered)
		}
	}
	// Ordinary text must survive untouched, or callers learn to route around
	// the renderer to read their own errors.
	if got := FormatError("kusto query failed", errors.New("connection refused")); got != "kusto query failed: connection refused" {
		t.Fatalf("clean text was altered: %q", got)
	}
}
