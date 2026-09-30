package msauth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// jwt builds an unsigned token whose payload is the given claims. The
// signature segment is deliberately junk: nothing in this package verifies a
// signature, and a test that supplied a real one would imply otherwise.
func jwt(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".not-a-signature"
}

func TestTokenClaimsReadsRegisteredClaims(t *testing.T) {
	expires := time.Now().Add(42 * time.Minute).Truncate(time.Second)
	issued := expires.Add(-time.Hour)
	token := jwt(t, map[string]any{
		"sub":             "subject-value",
		"upn":             "user@contoso.com",
		"oid":             "object-id",
		"tid":             "tenant-id",
		"appid":           "client-id",
		"app_displayname": "Microsoft Office",
		"name":            "Ada Lovelace",
		"aud":             "https://icm.example/",
		"iat":             issued.Unix(),
		"exp":             expires.Unix(),
	})

	claims, ok := TokenClaims(token)
	if !ok {
		t.Fatal("TokenClaims rejected a well-formed JWT")
	}
	if claims.Subject != "subject-value" || claims.UserPrincipalName != "user@contoso.com" ||
		claims.ObjectID != "object-id" || claims.TenantID != "tenant-id" ||
		claims.AppID != "client-id" || claims.Audience != "https://icm.example/" ||
		claims.AppDisplayName != "Microsoft Office" || claims.Name != "Ada Lovelace" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
	if !claims.ExpiresAt.Equal(expires) {
		t.Fatalf("expiry mismatch: got %s want %s", claims.ExpiresAt, expires)
	}
	if !claims.IssuedAt.Equal(issued) {
		t.Fatalf("issued-at mismatch: got %s want %s", claims.IssuedAt, issued)
	}
}

// The three name claims are a precedence, not a set: a token that carries both
// upn and email must report the upn, or two clients reading the same token
// disagree about who is signed in.
func TestTokenClaimsNamePrecedence(t *testing.T) {
	for _, test := range []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"upn wins", map[string]any{"upn": "a@x", "unique_name": "b@x", "email": "c@x"}, "a@x"},
		{"unique_name next", map[string]any{"unique_name": "b@x", "email": "c@x"}, "b@x"},
		{"email last", map[string]any{"email": "c@x"}, "c@x"},
		{"none is empty", map[string]any{"sub": "s"}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims, ok := TokenClaims(jwt(t, test.claims))
			if !ok {
				t.Fatal("TokenClaims rejected a well-formed JWT")
			}
			if claims.UserPrincipalName != test.want {
				t.Fatalf("got %q want %q", claims.UserPrincipalName, test.want)
			}
		})
	}
}

// aud is legally either a string or an array. The array form is the input that
// silently emptied the claim in every hand-rolled decoder this replaced.
func TestTokenClaimsAcceptsAudienceArray(t *testing.T) {
	claims, ok := TokenClaims(jwt(t, map[string]any{"aud": []any{"https://first/", "https://second/"}}))
	if !ok {
		t.Fatal("TokenClaims rejected a JWT with an array audience")
	}
	if claims.Audience != "https://first/" {
		t.Fatalf("audience: got %q want %q", claims.Audience, "https://first/")
	}
}

// Every input below fooled at least one of the decoders this function
// replaces, so the replacement is tested against them rather than against
// well-formed input only.
func TestTokenClaimsRejectsNonTokens(t *testing.T) {
	padded := jwt(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()})
	for _, test := range []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no segments", "opaque-service-bearer"},
		{"one segment", "header."},
		{"payload is not base64url", "header.!!!!.signature"},
		{"payload is not JSON", "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".signature"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := TokenClaims(test.token); ok {
				t.Fatalf("TokenClaims accepted %q", test.token)
			}
			if expiry := TokenExpiry(test.token); !expiry.IsZero() {
				t.Fatalf("TokenExpiry dated %q as %s", test.token, expiry)
			}
		})
	}
	// Negative control: the same assertions must pass on a real token, or the
	// test above would also pass against a function that always reports false.
	if _, ok := TokenClaims(padded); !ok {
		t.Fatal("control JWT was rejected")
	}
}

// A JWT with no exp is not an expired token and not a fresh one: it is a token
// this package cannot date, and the zero time is how a caller learns that.
func TestTokenExpiryDistinguishesAbsentFromPast(t *testing.T) {
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	if got := TokenExpiry(jwt(t, map[string]any{"exp": past.Unix()})); !got.Equal(past) {
		t.Fatalf("past expiry: got %s want %s", got, past)
	}
	if got := TokenExpiry(jwt(t, map[string]any{"upn": "user@contoso.com"})); !got.IsZero() {
		t.Fatalf("missing exp reported an expiry: %s", got)
	}
}

// The token must never appear in a value built for logging.
func TestClaimsCarryNoCredentialMaterial(t *testing.T) {
	token := jwt(t, map[string]any{"upn": "user@contoso.com", "exp": time.Now().Add(time.Hour).Unix()})
	claims, ok := TokenClaims(token)
	if !ok {
		t.Fatal("TokenClaims rejected a well-formed JWT")
	}
	rendered, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	for _, segment := range []string{token, "not-a-signature"} {
		if contains(string(rendered), segment) {
			t.Fatalf("rendered claims contain token material: %s", rendered)
		}
	}
}

// Padding on the payload segment is not canonical JWT encoding, but it is
// decodable and at least one producer in this fleet emitted it. Accepting it
// is deliberate; the test exists so nobody "fixes" it back into a rejection
// without noticing that a stored credential stops being readable.
func TestTokenClaimsAcceptsPaddedPayloadSegment(t *testing.T) {
	padded := "header." + base64.StdEncoding.EncodeToString([]byte(`{"exp":1735689600}`)) + "=.sig"
	claims, ok := TokenClaims(padded)
	if !ok {
		t.Fatalf("padded payload segment was rejected: %q", padded)
	}
	if claims.ExpiresAt.Unix() != 1735689600 {
		t.Fatalf("expiry: got %s", claims.ExpiresAt)
	}
}

// The input that made this check necessary: a CONTAINER wrapping a JWT. icy's
// retired cache file was {"token":"<jwt>"}, which splits on "." into three
// parts whose middle element is the real payload, so a decoder that inspects
// only parts[1] dates the envelope as though it were the token. Accepting it
// would have made icy send `Authorization: Bearer {"token": ...}` to
// production IcM on the first command on every machine holding an old cache.
func TestTokenClaimsRejectsAContainerWrappingAToken(t *testing.T) {
	inner := jwt(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "upn": "user@contoso.com"})
	for _, test := range []struct {
		name  string
		token string
	}{
		{"json envelope", `{"token":"` + inner + `"}`},
		{"quoted", `"` + inner + `"`},
		{"leading whitespace", " " + inner},
		{"embedded in prose", "bearer " + inner},
		{"empty middle segment", "aGVhZGVy..c2ln"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if claims, ok := TokenClaims(test.token); ok {
				t.Fatalf("accepted a container as a token: %+v", claims)
			}
			if expiry := TokenExpiry(test.token); !expiry.IsZero() {
				t.Fatalf("dated a container as %s", expiry)
			}
		})
	}
	// Negative control: the token the containers wrap must still be accepted,
	// or this test would pass against a TokenClaims that rejects everything.
	if _, ok := TokenClaims(inner); !ok {
		t.Fatal("control JWT was rejected")
	}
}
