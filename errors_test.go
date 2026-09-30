package msauth

import (
	"errors"
	"strings"
	"testing"
)

func TestSanitizeDiagnostic(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJleHAiOjE5OTk5OTk5OTl9.signaturevalue"
	input := "Authorization: Bearer " + jwt + " access_token=" + jwt + "\nfailed"
	got := sanitizeDiagnostic(input)
	if strings.Contains(got, jwt) || strings.Contains(got, "\n") {
		t.Fatalf("diagnostic was not sanitized: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("missing redaction marker: %q", got)
	}
}

func TestResourceFromScope(t *testing.T) {
	for scope, want := range map[string]string{
		"https://graph.microsoft.com/.default":                 "https://graph.microsoft.com",
		"https://cluster.kusto.windows.net/user_impersonation": "https://cluster.kusto.windows.net",
		"api://example/custom":                                 "api://example/custom",
	} {
		if got := resourceFromScope(scope); got != want {
			t.Errorf("resourceFromScope(%q)=%q want=%q", scope, got, want)
		}
	}
}

// A source that already produced a deterministic code must keep it. Flattening
// broker_assembly_mismatch into wam_failed is what forced a caller to read a
// PowerShell stack trace to learn that its Az.Accounts, not its sign-in, was
// the problem.
func TestAttemptPreservesADeterministicSourceCode(t *testing.T) {
	brokerErr := &AuthError{Code: CodeBrokerAssemblyMismatch, Message: "Az.Accounts 3.0.4 ships X but binds to Y"}
	attempt := attemptFromError("wam", CodeWAMFailed, brokerErr)
	if attempt.Code != CodeBrokerAssemblyMismatch {
		t.Fatalf("code = %q, want %q", attempt.Code, CodeBrokerAssemblyMismatch)
	}
	if attempt.Source != "wam" || !strings.Contains(attempt.Message, "Az.Accounts") {
		t.Fatalf("attempt lost context: %+v", attempt)
	}

	plain := attemptFromError("azure-cli", CodeAzureCLIFailed, errors.New("az failed"))
	if plain.Code != CodeAzureCLIFailed {
		t.Fatalf("code = %q, want %q", plain.Code, CodeAzureCLIFailed)
	}
}

// A broker LoaderException names assembly identities, including PublicKeyToken.
// That is evidence, not a credential, and redacting it would blind the very
// diagnostic that explains an assembly-version mismatch.
func TestSanitizeKeepsAssemblyIdentities(t *testing.T) {
	message := "Could not load file or assembly 'Microsoft.Identity.Client.NativeInterop, " +
		"Version=0.16.1.0, Culture=neutral, PublicKeyToken=0a613f4dd989e8ae'"
	got := sanitizeDiagnostic(message)
	if !strings.Contains(got, "0a613f4dd989e8ae") {
		t.Fatalf("assembly identity was redacted: %q", got)
	}
	if !strings.Contains(got, "0.16.1.0") {
		t.Fatalf("assembly version was lost: %q", got)
	}
	if redacted := sanitizeDiagnostic(`{"access_token":"abcdef123456"}`); strings.Contains(redacted, "abcdef123456") {
		t.Fatalf("a real token survived sanitization: %q", redacted)
	}
	if redacted := sanitizeDiagnostic("token=abcdef123456"); strings.Contains(redacted, "abcdef123456") {
		t.Fatalf("a bare token assignment survived sanitization: %q", redacted)
	}
}
