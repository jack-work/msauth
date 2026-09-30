package msauth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// This file exists because four clients independently wrote the same twelve
// lines: split a JWT on ".", base64url-decode the middle segment, and read a
// claim. icy read exp to decide whether its cached IcM bearer was still good,
// goop read upn to label a signed-in user, and this package read exp twice to
// date a broker or Azure CLI token. A JWT is a standard format, not a service
// semantic, so reading one belongs in the shared foundation; what each claim
// MEANS to a service still belongs to that service's adapter.

// Claims are the registered, non-secret claims of a JWT. Every field is
// descriptive metadata about a credential; none of them is credential material,
// so a Claims value is safe to log, print, and put in a diagnostic. The access
// token itself is deliberately not a field: nothing that renders claims should
// be one refactor away from rendering the token.
type Claims struct {
	// Subject is the "sub" claim: an opaque, pairwise identifier for the
	// principal. It is not a user name and is not comparable across clients.
	Subject string `json:"subject,omitempty"`

	// UserPrincipalName is the human-facing sign-in name, taken from the first
	// of "upn", "unique_name", or "email" that is present. Tokens for a
	// resource that suppresses upn legitimately have none.
	UserPrincipalName string `json:"userPrincipalName,omitempty"`

	// ObjectID ("oid") and TenantID ("tid") are the stable directory
	// identifiers, and are what to compare when deciding whether two tokens
	// belong to the same identity.
	ObjectID string `json:"objectId,omitempty"`
	TenantID string `json:"tenantId,omitempty"`

	// AppID ("appid") is the client this token was issued to, and
	// AppDisplayName ("app_displayname") is its friendly name.
	AppID          string `json:"appId,omitempty"`
	AppDisplayName string `json:"appDisplayName,omitempty"`

	// Name ("name") is the directory display name. It is not a sign-in name
	// and must not be compared with UserPrincipalName; it exists because a
	// tool that shows a user who they are signed in as shows both, and goop
	// kept a third JWT decoder alive solely to read this one claim.
	Name string `json:"name,omitempty"`

	// Audience is the resource the token is for. A token whose "aud" is a JSON
	// array reports the FIRST entry, which is lossy and is the reason a client
	// that must show a user every audience should read the inspectToken
	// operation's rawClaims instead. Measured 2026-08-02 on a live IcM STS
	// bearer, whose aud is a two-element array: this field reports the client
	// GUID and silently drops "https://prod.microsofticm.com". Reporting one
	// audience is right for the cache-lifetime and display uses this struct
	// exists for, and wrong for "tell me everything about this token".
	Audience string `json:"audience,omitempty"`

	IssuedAt  time.Time `json:"issuedAt,omitzero"`
	ExpiresAt time.Time `json:"expiresAt,omitzero"`
}

// TokenClaims reads the non-secret claims of a JWT. It reports false when the
// value is not a decodable JWT at all, which is the only signal a caller gets
// about the input's shape.
//
// The signature is NOT verified and cannot be: a public client holds no key
// for the issuer, and every caller here is reading a token a trusted service
// just handed it. These claims are therefore usable for cache lifetime,
// diagnostics, and display, and are NOT usable as an authorization decision.
// If you are about to branch on Claims to grant something, you are holding the
// wrong tool.
func TokenClaims(token string) (Claims, bool) {
	payload, ok := tokenPayload(token)
	if !ok {
		return Claims{}, false
	}
	var raw struct {
		Subject string `json:"sub"`
		UPN     string `json:"upn"`
		Unique  string `json:"unique_name"`
		Email   string `json:"email"`
		OID     string `json:"oid"`
		TID     string `json:"tid"`
		AppID   string `json:"appid"`
		AppName string `json:"app_displayname"`
		Name    string `json:"name"`
		Aud     any    `json:"aud"`
		Iat     int64  `json:"iat"`
		Exp     int64  `json:"exp"`
	}
	if json.Unmarshal(payload, &raw) != nil {
		return Claims{}, false
	}
	claims := Claims{
		Subject:           raw.Subject,
		UserPrincipalName: firstNonEmpty(raw.UPN, raw.Unique, raw.Email),
		ObjectID:          raw.OID,
		TenantID:          raw.TID,
		AppID:             raw.AppID,
		AppDisplayName:    raw.AppName,
		Name:              raw.Name,
		Audience:          audience(raw.Aud),
	}
	if raw.Iat != 0 {
		claims.IssuedAt = time.Unix(raw.Iat, 0)
	}
	if raw.Exp != 0 {
		claims.ExpiresAt = time.Unix(raw.Exp, 0)
	}
	return claims, true
}

// TokenPayload reports every claim in a JWT, including the ones Claims does
// not model, each still encoded exactly as the issuer wrote it.
//
// Claims is deliberately a fixed set of registered claims; a tool that shows a
// user the WHOLE payload -- icy's "token --decode" is the reference case --
// cannot be served by it and will keep a private decoder forever unless the
// foundation answers this question too. Values are json.RawMessage rather than
// any so that re-encoding is byte-exact: decoding a large "exp" through a Go
// map turns it into a float64, and a claim that a tool prints back to a human
// must not change on the way through.
//
// A payload is metadata, not credential material: it is the unsigned middle
// segment of a token the caller already holds. The signature is neither
// returned nor verified, for the reasons TokenClaims documents.
func TokenPayload(token string) (map[string]json.RawMessage, bool) {
	payload, ok := tokenPayload(token)
	if !ok {
		return nil, false
	}
	claims := map[string]json.RawMessage{}
	if json.Unmarshal(payload, &claims) != nil {
		return nil, false
	}
	return claims, true
}

// tokenPayload is the one place that decides whether a string is a JWT. Both
// readers go through it so a container can never be accepted by one and
// rejected by the other.
func tokenPayload(token string) ([]byte, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, false
	}
	// Every segment must be base64url, not merely the one being decoded. A
	// container that WRAPS a JWT splits into segments that happen to put the
	// payload in the middle: icy's retired cache file {"token":"hdr.BODY.sig"}
	// splits into ['{"token":"hdr', 'BODY', 'sig"}'], element 1 is the real
	// payload, and a decoder that looks only there dates the whole envelope as
	// if it were the token. That is not hypothetical: it would have made icy
	// send `Authorization: Bearer {"token": ...}` to production IcM on the
	// first command on every machine holding an old cache. Checking the
	// segments the caller did NOT ask about is what distinguishes a token from
	// something with a token inside it.
	for _, part := range parts {
		if !isBase64URL(part) {
			return nil, false
		}
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, false
	}
	return payload, true
}

// TokenExpiry reports when a JWT expires. A value that is not a JWT, or a JWT
// with no "exp", reports the zero time: absence is distinguishable from an
// expiry in the past, and a caller that cannot date a credential must treat it
// as unusable rather than as fresh.
func TokenExpiry(token string) time.Time {
	claims, ok := TokenClaims(token)
	if !ok {
		return time.Time{}
	}
	return claims.ExpiresAt
}

// isBase64URL reports whether a JWT segment is entirely base64url. Trailing
// padding is tolerated because at least one producer in this fleet emits it;
// an empty segment is not, because "a..b" is not a token.
func isBase64URL(segment string) bool {
	segment = strings.TrimRight(segment, "=")
	if segment == "" {
		return false
	}
	for _, r := range segment {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// aud is a string in every token this fleet handles, but the JWT specification
// allows an array, and a decoder that panics or drops the claim on the legal
// form is a bug waiting for one issuer to change.
func audience(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		for _, entry := range typed {
			if text, ok := entry.(string); ok && text != "" {
				return text
			}
		}
	}
	return ""
}
