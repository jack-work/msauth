package msauth

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestResolveRequest(t *testing.T) {
	tests := []struct {
		name    string
		request TokenRequest
		scope   string
		policy  Policy
		wantErr bool
	}{
		{name: "audience", request: TokenRequest{Audience: "https://graph.microsoft.com/"}, scope: "https://graph.microsoft.com/.default", policy: PolicyWAMFirst},
		{name: "scope", request: TokenRequest{Scope: "api://example/access_as_user", Policy: PolicyWAMOnly}, scope: "api://example/access_as_user", policy: PolicyWAMOnly},
		{name: "missing", request: TokenRequest{}, wantErr: true},
		{name: "both", request: TokenRequest{Scope: "a", Audience: "b"}, wantErr: true},
		{name: "audience suffix", request: TokenRequest{Audience: "api://example/.default"}, wantErr: true},
		{name: "multiple scopes", request: TokenRequest{Scope: "a b"}, wantErr: true},
		{name: "bad policy", request: TokenRequest{Scope: "a", Policy: "surprise"}, wantErr: true},
		{name: "negative validity", request: TokenRequest{Scope: "a", MinValidity: -time.Second}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := resolveRequest(test.request)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if resolved.scope != test.scope || resolved.policy != test.policy {
				t.Fatalf("got scope=%q policy=%q", resolved.scope, resolved.policy)
			}
		})
	}
}

func TestAcquireWAMFirstFallbackAndCache(t *testing.T) {
	now := time.Date(2026, 7, 25, 3, 0, 0, 0, time.UTC)
	var calls []string
	provider := testProvider(now)
	provider.wam = func(context.Context, string) (cachedToken, error) {
		calls = append(calls, "wam")
		return cachedToken{}, errors.New("broker unavailable")
	}
	provider.azure = func(_ context.Context, scope string) (cachedToken, error) {
		calls = append(calls, "azure:"+scope)
		return cachedToken{AccessToken: "secret", ExpiresAt: now.Add(time.Hour), Source: "azure-cli"}, nil
	}

	result, err := provider.Acquire(context.Background(), TokenRequest{Audience: "https://graph.microsoft.com"})
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken != "secret" || result.Source != "azure-cli" || result.Cached {
		t.Fatalf("unexpected result: %+v", result)
	}
	if want := []string{"wam", "azure:https://graph.microsoft.com/.default"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v want=%v", calls, want)
	}

	cached, err := provider.Acquire(context.Background(), TokenRequest{Audience: "https://graph.microsoft.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !cached.Cached || len(calls) != 2 {
		t.Fatalf("cache miss: result=%+v calls=%v", cached, calls)
	}
}

func TestPolicyConstrainsCachedSource(t *testing.T) {
	now := time.Now()
	provider := testProvider(now)
	provider.cache = map[string]map[string]cachedToken{
		"": {"resource/.default": {AccessToken: "azure-token", ExpiresAt: now.Add(time.Hour), Source: "azure-cli"}},
	}
	wamCalls := 0
	provider.wam = func(context.Context, string) (cachedToken, error) {
		wamCalls++
		return cachedToken{AccessToken: "wam-token", ExpiresAt: now.Add(time.Hour), Source: "wam"}, nil
	}
	result, err := provider.Acquire(context.Background(), TokenRequest{Audience: "resource", Policy: PolicyWAMOnly})
	if err != nil {
		t.Fatal(err)
	}
	if wamCalls != 1 || result.AccessToken != "wam-token" || result.Cached {
		t.Fatalf("policy reused wrong source: result=%+v wamCalls=%d", result, wamCalls)
	}
}

func TestAzureCLIClientDefaultsToAzureOnly(t *testing.T) {
	provider, err := NewForClient("azure-cli")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	provider.goos = "windows"
	provider.now = func() time.Time { return now }
	provider.load = func(string) map[string]cachedToken { return map[string]cachedToken{} }
	provider.save = func(string, map[string]cachedToken) error { return nil }
	provider.wam = func(context.Context, string) (cachedToken, error) {
		t.Fatal("azure-cli client attempted WAM")
		return cachedToken{}, nil
	}
	provider.azure = func(context.Context, string) (cachedToken, error) {
		return cachedToken{AccessToken: "azure-token", ExpiresAt: now.Add(time.Hour), Source: "azure-cli"}, nil
	}
	result, err := provider.Acquire(context.Background(), TokenRequest{Audience: "resource"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Source != "azure-cli" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestAcquireWAMOnlyDoesNotFallBack(t *testing.T) {
	now := time.Now()
	provider := testProvider(now)
	azureCalled := false
	provider.wam = func(context.Context, string) (cachedToken, error) { return cachedToken{}, errors.New("no account") }
	provider.azure = func(context.Context, string) (cachedToken, error) {
		azureCalled = true
		return cachedToken{}, nil
	}
	_, err := provider.Acquire(context.Background(), TokenRequest{Audience: "11111111-2222-3333-4444-666666666666", Policy: PolicyWAMOnly})
	if err == nil {
		t.Fatal("expected an acquisition error")
	}
	if azureCalled {
		t.Fatal("WAM-only request reached Azure CLI")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) || authErr.Code != CodeAcquisitionFailed || len(authErr.Attempts) != 1 {
		t.Fatalf("unexpected error: %#v", err)
	}
}

func TestAcquireRefreshRules(t *testing.T) {
	now := time.Date(2026, 7, 25, 3, 0, 0, 0, time.UTC)
	tests := []struct {
		name         string
		expires      time.Time
		force        bool
		wantAcquires int
	}{
		{name: "reusable", expires: now.Add(DefaultMinValidity + time.Second), wantAcquires: 0},
		{name: "near expiry", expires: now.Add(DefaultMinValidity), wantAcquires: 1},
		{name: "forced", expires: now.Add(time.Hour), force: true, wantAcquires: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := testProvider(now)
			provider.cache = map[string]map[string]cachedToken{
				"": {"resource/.default": {AccessToken: "old", ExpiresAt: test.expires, Source: "wam"}},
			}
			acquires := 0
			provider.wam = func(context.Context, string) (cachedToken, error) {
				acquires++
				return cachedToken{AccessToken: "new", ExpiresAt: now.Add(time.Hour), Source: "wam"}, nil
			}
			_, err := provider.Acquire(context.Background(), TokenRequest{Audience: "resource", ForceRefresh: test.force})
			if err != nil {
				t.Fatal(err)
			}
			if acquires != test.wantAcquires {
				t.Fatalf("acquires=%d want=%d", acquires, test.wantAcquires)
			}
		})
	}
}

func testProvider(now time.Time) *Provider {
	return &Provider{
		ClientID: OfficeClientID,
		TenantID: MicrosoftTenantID,
		goos:     "windows",
		now:      func() time.Time { return now },
		load:     func(string) map[string]cachedToken { return map[string]cachedToken{} },
		save:     func(string, map[string]cachedToken) error { return nil },
	}
}

// A wam-only caller has no second credential source, so the one attempt it
// records is the whole diagnosis. It must carry the source's own code.
func TestWAMOnlyFailureCarriesTheBrokerCode(t *testing.T) {
	provider := &Provider{
		ClientID: TeamsClientID, TenantID: MicrosoftTenantID, goos: "windows",
		now: time.Now,
		wam: func(context.Context, string) (cachedToken, error) {
			return cachedToken{}, &AuthError{Code: CodeBrokerAssemblyMismatch, Message: "Az.Accounts 3.0.4 is unusable"}
		},
		load: func(string) map[string]cachedToken { return map[string]cachedToken{} },
		save: func(string, map[string]cachedToken) error { return nil },
	}
	_, err := provider.Acquire(context.Background(), TokenRequest{Audience: "https://icm.example", Policy: PolicyWAMOnly})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("error = %v, want *AuthError", err)
	}
	if authErr.Code != CodeAcquisitionFailed || len(authErr.Attempts) != 1 {
		t.Fatalf("unexpected error: %+v", authErr)
	}
	if authErr.Attempts[0].Code != CodeBrokerAssemblyMismatch {
		t.Fatalf("attempt code = %q, want %q", authErr.Attempts[0].Code, CodeBrokerAssemblyMismatch)
	}
}

// TestFallbackReportsTheAttemptItRescuedYouFrom pins the contract that a
// SUCCESSFUL acquisition still reports the sources that failed first.
//
// The bug this guards against is silent and was expensive: on 2026-09-22 the
// WSL broker failed, the Azure CLI succeeded, and the caller received an
// ordinary-looking success. The Azure CLI token was then refused by the Teams
// auth service with `410 ApiRestricted`, because that service pins a client id.
// Nothing in the success mentioned the broker, so the visible failure was three
// layers away from the fault. A fallback that hides what it rescued you from
// turns a diagnosable error into a mystery.
func TestFallbackReportsTheAttemptItRescuedYouFrom(t *testing.T) {
	now := time.Date(2026, 9, 22, 18, 0, 0, 0, time.UTC)
	provider := testProvider(now)
	provider.wam = func(context.Context, string) (cachedToken, error) {
		return cachedToken{}, errors.New("the Windows MSAL proxy did not answer")
	}
	provider.azure = func(context.Context, string) (cachedToken, error) {
		return cachedToken{AccessToken: "secret", ExpiresAt: now.Add(time.Hour), Source: "azure-cli"}, nil
	}

	result, err := provider.Acquire(context.Background(), TokenRequest{Audience: "https://graph.microsoft.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Degraded) != 1 {
		t.Fatalf("a rescued acquisition must name its failed attempt, got Degraded=%+v", result.Degraded)
	}
	if result.Degraded[0].Source != "wam" {
		t.Fatalf("Degraded[0].Source=%q want %q", result.Degraded[0].Source, "wam")
	}
	if result.Degraded[0].Message == "" {
		t.Fatal("a degraded attempt with no message is not actionable")
	}
	if result.Source != "azure-cli" {
		t.Fatalf("Source=%q want azure-cli", result.Source)
	}
}

// TestUndegradedSuccessReportsNothing is the other half: the happy path must
// stay silent, or every caller learns to ignore the field.
func TestUndegradedSuccessReportsNothing(t *testing.T) {
	now := time.Date(2026, 9, 22, 18, 0, 0, 0, time.UTC)
	provider := testProvider(now)
	provider.wam = func(context.Context, string) (cachedToken, error) {
		return cachedToken{AccessToken: "secret", ExpiresAt: now.Add(time.Hour), Source: "wam"}, nil
	}
	provider.azure = func(context.Context, string) (cachedToken, error) {
		t.Fatal("the Azure CLI must not be reached when the broker succeeds")
		return cachedToken{}, nil
	}

	result, err := provider.Acquire(context.Background(), TokenRequest{Audience: "https://graph.microsoft.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Degraded) != 0 {
		t.Fatalf("an undegraded success must report nothing, got %+v", result.Degraded)
	}
}
