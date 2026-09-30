package msauth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A caller that holds two signed-in identities for the same client, tenant, and
// scope must be able to keep their caches apart. Without a discriminator the
// second identity is served the first identity's token inside the validity
// window, which is a silent cross-identity credential leak.
func TestCacheNamespaceIsolatesIdentities(t *testing.T) {
	now := time.Date(2026, 7, 29, 3, 0, 0, 0, time.UTC)
	stored := map[string]map[string]cachedToken{}
	provider := testProvider(now)
	provider.load = func(namespace string) map[string]cachedToken {
		out := map[string]cachedToken{}
		for scope, token := range stored[namespace] {
			out[scope] = token
		}
		return out
	}
	provider.save = func(namespace string, tokens map[string]cachedToken) error {
		copied := map[string]cachedToken{}
		for scope, token := range tokens {
			copied[scope] = token
		}
		stored[namespace] = copied
		return nil
	}

	issued := 0
	provider.wam = func(_ context.Context, scope string) (cachedToken, error) {
		issued++
		return cachedToken{AccessToken: "token-" + itoa(issued), ExpiresAt: now.Add(time.Hour), Source: "wam"}, nil
	}

	request := func(namespace string) TokenResult {
		t.Helper()
		result, err := provider.Acquire(context.Background(), TokenRequest{
			Audience: "https://graph.microsoft.com", CacheNamespace: namespace,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}

	first := request("profile-a")
	second := request("profile-b")
	if first.AccessToken == second.AccessToken {
		t.Fatalf("namespaces shared a token: %q", first.AccessToken)
	}
	if issued != 2 {
		t.Fatalf("acquisitions=%d want 2", issued)
	}

	// Caching must survive isolation; that is the point of an explicit
	// namespace rather than forcing every such caller to refresh.
	again := request("profile-a")
	if !again.Cached || again.AccessToken != first.AccessToken || issued != 2 {
		t.Fatalf("namespaced cache miss: %+v acquisitions=%d", again, issued)
	}

	if _, ok := stored["profile-a"]; !ok {
		t.Fatal("profile-a cache was not persisted under its namespace")
	}
	if _, ok := stored[""]; ok {
		t.Fatal("a namespaced request wrote the shared default cache")
	}
}

// The default namespace must keep its historical cache file so converging on
// namespaces does not orphan a protected cache that nothing will clean up.
func TestDefaultCacheNamespaceKeepsHistoricalPath(t *testing.T) {
	provider := &Provider{ClientID: OfficeClientID, TenantID: MicrosoftTenantID}
	shared := provider.cachePath("")
	scoped := provider.cachePath("profile-a")
	if shared == scoped {
		t.Fatal("a namespaced cache shares the default file")
	}
	// Golden filename for the office client in the corporate tenant. It is the
	// path the shared default cache has always used, and a protected cache
	// already exists there.
	if want := "tokens-CvMe6Dnq0djS.json"; shared[len(shared)-len(want):] != want {
		t.Fatalf("default cache filename changed: %q", shared)
	}
}

func TestResolveRequestRejectsUnusableNamespaces(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
	}{
		{name: "control character", namespace: "profile\x00a"},
		{name: "newline", namespace: "profile\na"},
		{name: "too long", namespace: repeat("a", cacheNamespaceLimit+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := resolveRequest(TokenRequest{Audience: "resource", CacheNamespace: test.namespace})
			var authErr *AuthError
			if !errors.As(err, &authErr) || authErr.Code != CodeInvalidRequest {
				t.Fatalf("unexpected error: %#v", err)
			}
		})
	}
}

func TestResolveRequestTrimsNamespace(t *testing.T) {
	resolved, err := resolveRequest(TokenRequest{Audience: "resource", CacheNamespace: "  profile-a  "})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.namespace != "profile-a" {
		t.Fatalf("namespace=%q", resolved.namespace)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for range n {
		out = append(out, s...)
	}
	return string(out)
}
