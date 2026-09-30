package msauth

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The protected-secret facility exists so adapters stop persisting
// service-issued bearers as plaintext JSON. These tests pin its contract; on
// Windows they also prove a real DPAPI round trip.

func TestProtectSecretRoundTrip(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected storage is available only on Windows")
	}
	path := filepath.Join(t.TempDir(), "nested", "icm.json")
	secret := []byte(`{"token":"header.payload.signature"}`)

	if err := ProtectSecret(path, secret); err != nil {
		t.Fatalf("ProtectSecret: %v", err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sealed file: %v", err)
	}
	if strings.Contains(string(stored), "header.payload.signature") {
		t.Fatal("sealed file still contains the plaintext secret")
	}

	opened, err := OpenSecret(path)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	if string(opened) != string(secret) {
		t.Fatalf("round trip mismatch: got %q", opened)
	}
}

func TestOpenSecretMissingIsNotFound(t *testing.T) {
	_, err := OpenSecret(filepath.Join(t.TempDir(), "absent.json"))
	assertCode(t, err, CodeNotFound)
}

// A cold cache and a legacy plaintext file must both look like a miss so the
// adapter re-acquires instead of inheriting unprotected credential material.
func TestOpenSecretRetiresLegacyPlaintext(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("legacy retirement is exercised through the Windows reader")
	}
	path := filepath.Join(t.TempDir(), "icm_token.json")
	if err := os.WriteFile(path, []byte(`{"token":"header.payload.signature"}`), 0o600); err != nil {
		t.Fatalf("seed legacy cache: %v", err)
	}

	_, err := OpenSecret(path)
	assertCode(t, err, CodeNotFound)
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("legacy plaintext file was not removed")
	}
}

func TestProtectSecretRejectsInvalidRequests(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		secret []byte
	}{
		{"empty path", "", []byte("x")},
		{"relative path", filepath.Join("relative", "icm.json"), []byte("x")},
		{"empty secret", filepath.Join(t.TempDir(), "icm.json"), nil},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			assertCode(t, ProtectSecret(testCase.path, testCase.secret), CodeInvalidRequest)
		})
	}
}

func TestProtocolProtectedSecretRoundTrip(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected storage is available only on Windows")
	}
	path := filepath.Join(t.TempDir(), "icm.json")
	secret := []byte(`{"token":"header.payload.signature"}`)

	sealed := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version:   ProtocolVersion,
		Operation: OperationProtectSecret,
		Path:      path,
		Secret:    base64.StdEncoding.EncodeToString(secret),
	})
	if !sealed.OK || sealed.Secret == nil {
		t.Fatalf("protectSecret failed: %+v", sealed.Error)
	}
	if sealed.Secret.Secret != "" {
		t.Fatal("protectSecret must not echo the secret back")
	}
	if sealed.Secret.Bytes != len(secret) {
		t.Fatalf("byte count = %d, want %d", sealed.Secret.Bytes, len(secret))
	}

	opened := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version:   ProtocolVersion,
		Operation: OperationOpenSecret,
		Path:      path,
	})
	if !opened.OK || opened.Secret == nil {
		t.Fatalf("openSecret failed: %+v", opened.Error)
	}
	decoded, err := base64.StdEncoding.DecodeString(opened.Secret.Secret)
	if err != nil {
		t.Fatalf("decode returned secret: %v", err)
	}
	if string(decoded) != string(secret) {
		t.Fatalf("protocol round trip mismatch: got %q", decoded)
	}
}

func TestProtocolSecretOperationsRejectMixedRequests(t *testing.T) {
	path := filepath.Join(t.TempDir(), "icm.json")
	cases := []struct {
		name    string
		request ProtocolRequest
	}{
		{"acquire with path", ProtocolRequest{
			Version: ProtocolVersion, Operation: OperationAcquireToken,
			Client: "teams", Audience: "https://graph.microsoft.com", Path: path,
		}},
		{"protect with client", ProtocolRequest{
			Version: ProtocolVersion, Operation: OperationProtectSecret,
			Client: "teams", Path: path, Secret: base64.StdEncoding.EncodeToString([]byte("x")),
		}},
		{"protect with policy", ProtocolRequest{
			Version: ProtocolVersion, Operation: OperationProtectSecret,
			Policy: PolicyWAMOnly, Path: path, Secret: base64.StdEncoding.EncodeToString([]byte("x")),
		}},
		{"open with secret", ProtocolRequest{
			Version: ProtocolVersion, Operation: OperationOpenSecret,
			Path: path, Secret: base64.StdEncoding.EncodeToString([]byte("x")),
		}},
		{"protect with invalid base64", ProtocolRequest{
			Version: ProtocolVersion, Operation: OperationProtectSecret,
			Path: path, Secret: "not base64!!",
		}},
		{"protect with relative path", ProtocolRequest{
			Version: ProtocolVersion, Operation: OperationProtectSecret,
			Path: "icm.json", Secret: base64.StdEncoding.EncodeToString([]byte("x")),
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			response := ExecuteProtocol(context.Background(), testCase.request)
			if response.OK {
				t.Fatal("expected the request to be rejected")
			}
			if response.Error.Code != CodeInvalidRequest {
				t.Fatalf("code = %q, want %q", response.Error.Code, CodeInvalidRequest)
			}
		})
	}
}

func TestProtocolOpenSecretMissingReportsNotFound(t *testing.T) {
	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version:   ProtocolVersion,
		Operation: OperationOpenSecret,
		Path:      filepath.Join(t.TempDir(), "absent.json"),
	})
	if response.OK {
		t.Fatal("expected a miss to be reported as an error")
	}
	if response.Error.Code != CodeNotFound {
		t.Fatalf("code = %q, want %q", response.Error.Code, CodeNotFound)
	}
}

func assertCode(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error %v is not an *AuthError", err)
	}
	if authErr.Code != want {
		t.Fatalf("code = %q, want %q", authErr.Code, want)
	}
}

// openSecret dates a sealed JWT so a non-Go adapter never maintains a refresh
// skew of its own. The three cases below are the whole contract: a fresh JWT
// is dated and not stale, a nearly-expired one is dated and stale, and an
// opaque secret is not dated at all -- which a caller must read as "unknown",
// never as "fresh".
func TestOpenSecretReportsJWTExpiry(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("protected storage is available only on Windows")
	}
	fresh := time.Now().Add(time.Hour).Truncate(time.Second)
	nearly := time.Now().Add(DefaultMinValidity / 2).Truncate(time.Second)

	for _, test := range []struct {
		name      string
		secret    string
		wantDated bool
		wantStale bool
		wantAt    time.Time
	}{
		{"fresh JWT", jwt(t, map[string]any{"exp": fresh.Unix()}), true, false, fresh},
		{"nearly expired JWT", jwt(t, map[string]any{"exp": nearly.Unix()}), true, true, nearly},
		{"expired JWT", jwt(t, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}), true, true, time.Time{}},
		{"opaque bearer", "an-opaque-service-issued-bearer", false, false, time.Time{}},
		{"JWT without exp", jwt(t, map[string]any{"upn": "user@contoso.com"}), false, false, time.Time{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret.bin")
			if err := ProtectSecret(path, []byte(test.secret)); err != nil {
				t.Fatalf("ProtectSecret: %v", err)
			}
			response := ExecuteProtocol(context.Background(), ProtocolRequest{
				Version: ProtocolVersion, Operation: OperationOpenSecret, Path: path,
			})
			if !response.OK || response.Secret == nil {
				t.Fatalf("openSecret failed: %+v", response.Error)
			}
			if dated := response.Secret.ExpiresAt != ""; dated != test.wantDated {
				t.Fatalf("expiresAt %q: dated=%t want %t", response.Secret.ExpiresAt, dated, test.wantDated)
			}
			if response.Secret.Stale != test.wantStale {
				t.Fatalf("stale=%t want %t (expiresAt %q)", response.Secret.Stale, test.wantStale, response.Secret.ExpiresAt)
			}
			if !test.wantAt.IsZero() {
				parsed, err := time.Parse(time.RFC3339, response.Secret.ExpiresAt)
				if err != nil {
					t.Fatalf("expiresAt is not RFC 3339: %q", response.Secret.ExpiresAt)
				}
				if !parsed.Equal(test.wantAt) {
					t.Fatalf("expiresAt %s want %s", parsed, test.wantAt)
				}
			}
			// The secret itself must still be returned verbatim: dating it is
			// additive and must not change what the adapter gets back.
			decoded, err := base64.StdEncoding.DecodeString(response.Secret.Secret)
			if err != nil || string(decoded) != test.secret {
				t.Fatalf("secret round trip broke: %v %q", err, decoded)
			}
		})
	}
}
