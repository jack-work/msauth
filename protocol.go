package msauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const ProtocolVersion = 1

const (
	OperationCapabilities  = "capabilities"
	OperationAcquireToken  = "acquireToken"
	OperationProtectSecret = "protectSecret"
	OperationOpenSecret    = "openSecret"
	// OperationDiagnose reports the auth environment without authenticating.
	// Non-Go clients get the same evidence a Go caller has, so an adapter can
	// explain a broker fault instead of relaying a PowerShell stack trace.
	OperationDiagnose = "diagnose"
	// OperationInspectToken reads the claims of a JWT the caller already holds.
	// It authenticates nothing and acquires nothing: the tokens it describes are
	// typically SERVICE bearers an adapter obtained by exchanging an Entra
	// token, which no acquisition result can describe. Without it, a non-Go
	// client that shows a user which identity a credential carries has to decode
	// the JWT itself, which is how three private base64 decoders survived a
	// convergence whose whole point was that a JWT is a standard format rather
	// than a service semantic.
	OperationInspectToken = "inspectToken"
	// OperationAuditArtifact reports which installed binaries carry a current
	// auth foundation. It authenticates nothing, reads the named files without
	// executing them, and exists on the wire for the same reason inspectToken
	// does: the answer is not a service semantic, and a non-Go client that has
	// to compute it will grow a second implementation of the one check whose
	// whole purpose is to be identical everywhere. The rebuild list it returns
	// is the delivery step this estate never had.
	OperationAuditArtifact = "auditArtifact"
)

// ProtocolRequest is the stable stdin JSON contract for non-Go clients.
type ProtocolRequest struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
	Client    string `json:"client,omitempty"`
	Tenant    string `json:"tenant,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Audience  string `json:"audience,omitempty"`
	Policy    Policy `json:"policy,omitempty"`
	Refresh   bool   `json:"refresh,omitempty"`

	// CacheNamespace isolates the token cache for callers that hold more than
	// one signed-in identity for the same client, tenant, and scope.
	CacheNamespace string `json:"cacheNamespace,omitempty"`

	// Protected-secret operations. Adapters that exchange an Entra token for a
	// service-issued bearer use these to store it with the same protection as
	// msauth's own cache, without reimplementing DPAPI.
	Path   string `json:"path,omitempty"`
	Secret string `json:"secret,omitempty"`

	// Artifacts, Required and Foundation belong to auditArtifact. Artifacts are
	// filesystem paths to Go binaries, read but never run. Required is the
	// foundation revision those artifacts must carry; an empty Required audits
	// provenance only, which still fails an unlinked, unstamped or dirty
	// artifact. Foundation is an optional path to the foundation's own git
	// worktree, which turns Required into a FLOOR: an artifact carrying a newer
	// revision then passes instead of reading as stale. Without it the
	// comparison is exact equality, which is the stricter answer.
	Artifacts  []string `json:"artifacts,omitempty"`
	Required   string   `json:"required,omitempty"`
	Foundation string   `json:"foundation,omitempty"`

	// Token is the JWT an inspectToken request describes. It arrives on stdin,
	// like every other field, and must never be passed as an argument: argv is
	// readable by any process on the machine, and this is the one field whose
	// value is credential material. It is never logged, never echoed, and never
	// quoted in an error message.
	Token string `json:"token,omitempty"`
}

// ProtocolResponse is always emitted for a syntactically valid request path.
type ProtocolResponse struct {
	Version      int              `json:"version"`
	OK           bool             `json:"ok"`
	Result       *TokenResult     `json:"result,omitempty"`
	Secret       *ProtectedSecret `json:"secret,omitempty"`
	Capabilities *Capabilities    `json:"capabilities,omitempty"`
	Diagnostics  *Diagnostics     `json:"diagnostics,omitempty"`
	Inspection   *TokenInspection `json:"inspection,omitempty"`
	Audit        *AuditReport     `json:"audit,omitempty"`
	Error        *AuthError       `json:"error,omitempty"`

	// Display and Hint carry the Go API's FormatError and Hint across the wire.
	// Without them a non-Go client cannot reach either function -- they are
	// ordinary Go calls with no operation of their own -- so the reference
	// non-Go client ended up rendering code, message and attempts itself and
	// deciding its own remediation text. That is one more copy of the layout
	// this package exists to own, and it is the copy no Go refactor can find.
	//
	// Display is the canonical rendering of Error with no headline; a client
	// SHOULD print it, optionally prefixed with what it was doing, rather than
	// composing its own from the parts. Hint is the single remediation the
	// codes imply, or absent when they imply none. Both are present only on a
	// failure response, and Error stays populated so a client that needs to
	// branch on a code still can.
	Display string `json:"display,omitempty"`
	Hint    string `json:"hint,omitempty"`
}

// ProtectedSecret reports the outcome of a protected-secret operation. Secret
// is standard base64 and is populated only by openSecret.
type ProtectedSecret struct {
	Path   string `json:"path"`
	Bytes  int    `json:"bytes"`
	Secret string `json:"secret,omitempty"`

	// ExpiresAt and Stale exist so a non-Go adapter never has to decode a JWT
	// or maintain a refresh skew of its own. icy kept both: a base64 decoder
	// and a 120-second skew that governed the same chain as this package's
	// DefaultMinValidity and agreed with it only by coincidence.
	//
	// ExpiresAt is RFC 3339 and is present ONLY when the sealed bytes are a JWT
	// carrying an "exp" claim. Its ABSENCE means this build could not date the
	// secret -- never that the secret is fresh -- so an adapter that requires an
	// expiry must treat a missing ExpiresAt as unusable. Reading the standard
	// exp claim of a JWT is not service semantics; what the bearer authorizes
	// still belongs entirely to the adapter that stored it.
	ExpiresAt string `json:"expiresAt,omitempty"`

	// Stale is true when ExpiresAt is known and is within DefaultMinValidity of
	// now, including already past. It is omitted otherwise, so "stale": true is
	// the only assertion this field ever makes and its absence asserts nothing.
	Stale bool `json:"stale,omitempty"`
}

// TokenInspection reports what a JWT the caller already holds says about
// itself. Nothing here is credential material: Claims are registered claims,
// and Claims carries the payload's remaining claims verbatim. The token is not
// echoed back -- the caller sent it and already has it, and a response that
// repeats a credential is a credential in one more place.
type TokenInspection struct {
	Claims Claims `json:"claims"`

	// Claims models the registered claims every client needs; RawClaims is the
	// whole payload for the client that shows a user everything. Both are
	// present because carrying only the typed subset is what leaves a decoder
	// alive in the adapter, and carrying only the map makes every client parse
	// dates and audience arrays for itself.
	RawClaims map[string]json.RawMessage `json:"rawClaims,omitempty"`

	// Stale is true when the token carries an "exp" that is within
	// DefaultMinValidity of now, including already past. It is the same verdict,
	// from the same skew, that openSecret reports for a sealed bearer, so an
	// adapter never has to maintain a refresh margin of its own. Its absence
	// asserts nothing: a token with no "exp" cannot be dated by this build, and
	// the caller must treat that as unusable rather than as fresh.
	Stale bool `json:"stale,omitempty"`
}

// ExecuteProtocol validates and executes one protocol request.
func ExecuteProtocol(ctx context.Context, request ProtocolRequest) ProtocolResponse {
	// Capability discovery answers at any requested version. That is the whole
	// point of negotiation: a client built against a later protocol must still
	// be able to ask this build what it actually speaks.
	if request.Operation == OperationCapabilities {
		return executeCapabilities(request)
	}
	if request.Version != ProtocolVersion {
		return protocolFailure(newUnsupportedVersionError(request.Version))
	}
	switch request.Operation {
	case OperationAcquireToken:
		return executeAcquireToken(ctx, request)
	case OperationProtectSecret:
		return executeProtectSecret(request)
	case OperationOpenSecret:
		return executeOpenSecret(request)
	case OperationDiagnose:
		return executeDiagnose(ctx, request)
	case OperationInspectToken:
		return executeInspectToken(request)
	case OperationAuditArtifact:
		return executeAuditArtifact(request)
	default:
		return protocolFailure(newUnsupportedOperationError(request.Operation))
	}
}

func executeCapabilities(request ProtocolRequest) ProtocolResponse {
	if err := requireNoFieldsBeyond(request); err != nil {
		return protocolFailure(err)
	}
	capabilities := Describe()
	return ProtocolResponse{Version: ProtocolVersion, OK: true, Capabilities: &capabilities}
}

func executeAcquireToken(ctx context.Context, request ProtocolRequest) ProtocolResponse {
	// The wire protocol requires an explicit client even though the Go API
	// accepts an empty name. A request that crosses a process boundary without
	// naming its client is far more likely to be a bug than an intent to use
	// whatever this host happens to be configured with, and authenticating as
	// an unintended client is the one mistake this package must not make
	// silently. capabilities reports defaultClient, so a caller that genuinely
	// wants the configured default can send it explicitly.
	if request.Client == "" {
		return protocolFailure(newRequestError("client is required; this build's configured default is %q, which a request must name explicitly",
			effectiveConfig().DefaultClient))
	}
	if err := requireNoFieldsBeyond(request, "client", "tenant", "scope", "audience", "policy", "refresh", "cacheNamespace"); err != nil {
		return protocolFailure(err)
	}

	provider, err := NewForClient(request.Client)
	if err != nil {
		return protocolFailure(err)
	}
	if request.Tenant != "" {
		provider.TenantID = request.Tenant
	}
	result, err := provider.Acquire(ctx, TokenRequest{
		Scope:          request.Scope,
		Audience:       request.Audience,
		Policy:         request.Policy,
		ForceRefresh:   request.Refresh,
		CacheNamespace: request.CacheNamespace,
	})
	if err != nil {
		return protocolFailure(err)
	}
	return ProtocolResponse{Version: ProtocolVersion, OK: true, Result: &result}
}

func executeDiagnose(ctx context.Context, request ProtocolRequest) ProtocolResponse {
	if err := requireNoFieldsBeyond(request); err != nil {
		return protocolFailure(err)
	}
	diagnostics := Diagnose(ctx)
	// A diagnosis always succeeds: reporting that the environment is broken is
	// the successful outcome. Health is a field, not an exit status, so a
	// caller never has to distinguish "could not diagnose" from "diagnosed as
	// unhealthy" by parsing an error.
	return ProtocolResponse{Version: ProtocolVersion, OK: true, Diagnostics: &diagnostics}
}

func executeProtectSecret(request ProtocolRequest) ProtocolResponse {
	if err := rejectTokenFields(request); err != nil {
		return protocolFailure(err)
	}
	secret, err := decodeSecret(request.Secret)
	if err != nil {
		return protocolFailure(err)
	}
	if err := ProtectSecret(request.Path, secret); err != nil {
		return protocolFailure(err)
	}
	return ProtocolResponse{
		Version: ProtocolVersion,
		OK:      true,
		Secret:  &ProtectedSecret{Path: request.Path, Bytes: len(secret)},
	}
}

func executeOpenSecret(request ProtocolRequest) ProtocolResponse {
	if err := rejectTokenFields(request); err != nil {
		return protocolFailure(err)
	}
	if request.Secret != "" {
		return protocolFailure(newRequestError("secret is not part of an openSecret request"))
	}
	secret, err := OpenSecret(request.Path)
	if err != nil {
		return protocolFailure(err)
	}
	opened := &ProtectedSecret{
		Path:   request.Path,
		Bytes:  len(secret),
		Secret: base64.StdEncoding.EncodeToString(secret),
	}
	if expiry := TokenExpiry(string(secret)); !expiry.IsZero() {
		opened.ExpiresAt = expiry.UTC().Format(time.RFC3339)
		opened.Stale = time.Until(expiry) <= DefaultMinValidity
	}
	return ProtocolResponse{Version: ProtocolVersion, OK: true, Secret: opened}
}

// executeInspectToken describes a token the caller supplied. It never
// acquires, never caches, and never writes: the request is answered entirely
// from the bytes on stdin, so an adapter can label an identity while the
// broker is broken.
func executeInspectToken(request ProtocolRequest) ProtocolResponse {
	if err := requireNoFieldsBeyond(request, "token"); err != nil {
		return protocolFailure(err)
	}
	if request.Token == "" {
		return protocolFailure(newRequestError("token is required for an inspectToken request"))
	}
	claims, ok := TokenClaims(request.Token)
	if !ok {
		// The rejected value is NOT quoted back. It is the one field of this
		// protocol that may be a live credential, and the commonest reason to
		// land here is that a caller passed a cache FILE whose JSON wraps a
		// token -- so the text that would be "helpfully" echoed is precisely the
		// text that must not be. The code says which fault this is; the caller
		// still holds the input and needs no copy of it.
		return protocolFailure(&AuthError{
			Code:    CodeNotAToken,
			Message: "the supplied value is not a JWT; a container that wraps one is not a token",
		})
	}
	inspection := &TokenInspection{Claims: claims}
	inspection.RawClaims, _ = TokenPayload(request.Token)
	if !claims.ExpiresAt.IsZero() {
		inspection.Stale = time.Until(claims.ExpiresAt) <= DefaultMinValidity
	}
	return ProtocolResponse{Version: ProtocolVersion, OK: true, Inspection: inspection}
}

// executeAuditArtifact answers the delivery question for a non-Go caller. Like
// diagnose, it SUCCEEDS while reporting failure: "these three artifacts are
// stale" is the answer working correctly, so the verdict is a field and never
// an error. A caller that wants an exit status reads audit.ok.
func executeAuditArtifact(request ProtocolRequest) ProtocolResponse {
	if err := requireNoFieldsBeyond(request, "artifacts", "required", "foundation"); err != nil {
		return protocolFailure(err)
	}
	if len(request.Artifacts) == 0 {
		return protocolFailure(newRequestError("artifacts is required for an auditArtifact request: name at least one installed binary"))
	}
	var order Ordering
	if request.Foundation != "" {
		order = GitAncestry(request.Foundation)
	}
	report := AuditArtifactsAtLeast(request.Artifacts, request.Required, order)
	return ProtocolResponse{Version: ProtocolVersion, OK: true, Audit: &report}
}

// A protected-secret request carries no acquisition semantics. Rejecting the
// token fields keeps each operation's contract unambiguous.
func rejectTokenFields(request ProtocolRequest) error {
	return requireNoFieldsBeyond(request, "path", "secret")
}

// requireNoFieldsBeyond rejects any field the named operation does not use.
//
// It replaced five hand-written condition chains, each of which had to be
// edited when a field was added. The failure mode of missing one is silent and
// wrong in the dangerous direction: an operation that ignores a field a caller
// set does something other than what the caller asked, and "inspectToken also
// accepted a cacheNamespace" is indistinguishable from "the namespace was
// honoured". setRequestFields below is the single list, and a test asserts it
// covers every JSON field this build decodes.
func requireNoFieldsBeyond(request ProtocolRequest, allowed ...string) error {
	permitted := make(map[string]bool, len(allowed))
	for _, field := range allowed {
		permitted[field] = true
	}
	var extra []string
	for _, field := range setRequestFields(request) {
		if !permitted[field] {
			extra = append(extra, field)
		}
	}
	if len(extra) == 0 {
		return nil
	}
	operation := request.Operation
	if len(allowed) == 0 {
		return newRequestError("a %s request carries no other fields; remove %s", operation, strings.Join(extra, ", "))
	}
	return newRequestError("%s is not part of a %s request, which uses %s",
		strings.Join(extra, ", "), operation, strings.Join(allowed, ", "))
}

// setRequestFields names every field of request that carries a value, using
// the field's JSON name. version and operation are excluded because they are
// part of every request.
func setRequestFields(request ProtocolRequest) []string {
	var names []string
	appendIf := func(set bool, name string) {
		if set {
			names = append(names, name)
		}
	}
	appendIf(request.Client != "", "client")
	appendIf(request.Tenant != "", "tenant")
	appendIf(request.Scope != "", "scope")
	appendIf(request.Audience != "", "audience")
	appendIf(request.Policy != "", "policy")
	appendIf(request.Refresh, "refresh")
	appendIf(request.CacheNamespace != "", "cacheNamespace")
	appendIf(request.Path != "", "path")
	appendIf(request.Secret != "", "secret")
	appendIf(request.Token != "", "token")
	appendIf(len(request.Artifacts) > 0, "artifacts")
	appendIf(request.Required != "", "required")
	appendIf(request.Foundation != "", "foundation")
	return names
}

// FailureResponse builds the one failure shape this protocol has. It is
// exported because the command decodes stdin before the protocol executor ever
// sees it, so a malformed request and an unknown field are answered outside
// ExecuteProtocol. When those answers were assembled by hand they carried no
// display and no hint, which made "the response has no display" mean either
// "this msauth predates 96c5fba" or "a current msauth rejected your JSON" --
// two conditions with opposite remedies, told apart by nothing. There is one
// constructor now, and every failure that reaches a client came out of it.
func FailureResponse(err error) ProtocolResponse {
	return protocolFailure(err)
}

func protocolFailure(err error) ProtocolResponse {
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		authErr = &AuthError{Code: CodeInternal, Message: "authentication failed unexpectedly"}
	}
	return ProtocolResponse{
		Version: ProtocolVersion,
		OK:      false,
		Error:   authErr,
		Display: FormatError("", authErr),
		Hint:    Hint(authErr),
	}
}
