package msauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const DefaultMinValidity = 2 * time.Minute

// Policy controls which credential source may satisfy a token request.
type Policy string

const (
	PolicyWAMFirst     Policy = "wam-first"
	PolicyWAMOnly      Policy = "wam-only"
	PolicyAzureCLIOnly Policy = "azure-cli-only"
)

// TokenRequest is the single acquisition model used by the Go and JSON APIs.
// Exactly one of Scope or Audience must be set. Audience is shorthand for its
// resource-wide /.default scope.
type TokenRequest struct {
	Scope        string        `json:"scope,omitempty"`
	Audience     string        `json:"audience,omitempty"`
	Policy       Policy        `json:"policy,omitempty"`
	ForceRefresh bool          `json:"refresh,omitempty"`
	MinValidity  time.Duration `json:"-"`

	// CacheNamespace is an opaque, caller-chosen identity discriminator. The
	// cache is otherwise keyed by client, tenant, and scope, which cannot
	// distinguish two signed-in identities that legitimately request the same
	// triple -- for example a caller that pins a separate Azure CLI login per
	// profile through AZURE_CONFIG_DIR. Such a caller must pass a namespace, or
	// one identity's token can be served to another inside the validity window.
	// The empty namespace is the shared default and keeps the default cache
	// file unchanged.
	CacheNamespace string `json:"cacheNamespace,omitempty"`
}

// TokenResult contains the credential and non-secret acquisition metadata.
type TokenResult struct {
	AccessToken string    `json:"accessToken,omitempty"`
	ClientID    string    `json:"clientId"`
	TenantID    string    `json:"tenantId"`
	Scope       string    `json:"scope"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Source      string    `json:"source"`
	Cached      bool      `json:"cached"`

	// Degraded carries the attempts that FAILED before the one that succeeded.
	// It is empty on the happy path and non-empty exactly when a fallback
	// rescued the acquisition.
	//
	// WHY A SUCCESSFUL ACQUISITION REPORTS FAILURES.
	// Before this field, a broker failure followed by an Azure CLI success was
	// indistinguishable from an ordinary success: the attempts slice was built,
	// then dropped on the floor at the return. Measured consequence, 2026-09-22:
	// the WSL broker failed, the Azure CLI succeeded, and the Azure CLI's token
	// was refused by the downstream Teams auth service with `410 ApiRestricted`
	// -- a message that names neither the broker nor the fallback. The operator
	// sees a failure three layers from the fault and no thread back to it.
	//
	// A fallback that hides what it rescued you from is a silent downgrade, and
	// the token it hands back is not equivalent: a service that pins a client id
	// will reject it. Callers should surface this whenever it is non-empty --
	// it costs one log line on a path that is, by construction, already unusual.
	Degraded []Attempt `json:"degraded,omitempty"`
}

// Provider acquires tokens for one Entra public client and tenant.
type Provider struct {
	ClientID string
	TenantID string

	mu sync.Mutex
	// cache is namespace -> scope -> token. Each namespace is a separate
	// protected file, so one identity's cache can be discarded on its own.
	cache map[string]map[string]cachedToken

	// Test seams remain private so production callers cannot replace security
	// boundaries accidentally.
	goos          string
	now           func() time.Time
	defaultPolicy Policy
	wam           acquireFunc
	azure         acquireFunc
	// wsl reaches the WINDOWS broker from inside a WSL distro. See
	// wslbroker.go: a broker is a platform concept, not a Windows one, so
	// PolicyWAMFirst and PolicyWAMOnly are satisfied by WAM on Windows and by
	// this bridge under WSL.
	wsl acquireFunc
	// wslEnv is the filesystem/process seam wslbroker.go uses. Zero value means
	// "wire the real one"; tests substitute it so no test spawns a Windows
	// binary, reaches a network, or touches a credential.
	wslEnv wslEnvironment
	load   func(namespace string) map[string]cachedToken
	save   func(namespace string, tokens map[string]cachedToken) error
}

type acquireFunc func(context.Context, string) (cachedToken, error)

type cachedToken struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	Source      string    `json:"source"`
}

// NewForClient builds a provider for a client resolved from the effective
// configuration. An empty name selects the configured default client, and a
// bare application ID names a client this build does not ship with.
func NewForClient(name string) (*Provider, error) {
	config, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	return config.NewProvider(name)
}

// Acquire returns a token according to request semantics and refresh policy.
func (p *Provider) Acquire(ctx context.Context, request TokenRequest) (TokenResult, error) {
	p.defaults()
	if request.Policy == "" && p.defaultPolicy != "" {
		request.Policy = p.defaultPolicy
	}
	resolved, err := resolveRequest(request)
	if err != nil {
		return TokenResult{}, err
	}
	scope, policy := resolved.scope, resolved.policy

	p.mu.Lock()
	defer p.mu.Unlock()

	tokens := p.namespaceCache(resolved.namespace)
	if token, ok := tokens[scope]; ok && !request.ForceRefresh && sourceAllowed(policy, token.Source) && token.ExpiresAt.Sub(p.now()) > resolved.minValidity {
		return p.result(scope, token, true), nil
	}

	var attempts []Attempt
	if policy == PolicyWAMFirst || policy == PolicyWAMOnly {
		// Which broker implements this policy is a property of the PLATFORM.
		// Windows has WAM; a WSL distro has no WAM but can reach the host's
		// broker over interop, which is the same credential by different
		// machinery; bare Linux has neither. Before the WSL branch existed this
		// was a flat "not Windows means no broker", which stranded every WSL
		// caller whose account uses a platform authenticator -- Windows Hello
		// cannot be satisfied by a Linux browser, and a WSL VM has no USB for a
		// security key, so there was no reachable credential at all.
		switch {
		case p.goos == "windows":
			token, acquireErr := p.wam(ctx, scope)
			if acquireErr == nil {
				return p.finish(resolved.namespace, scope, token, attempts)
			}
			attempts = append(attempts, attemptFromError("wam", CodeWAMFailed, acquireErr))
		case p.wslEnvironmentOrDefault().runningUnderWSL():
			token, acquireErr := p.wsl(ctx, scope)
			if acquireErr == nil {
				return p.finish(resolved.namespace, scope, token, attempts)
			}
			attempts = append(attempts, attemptFromError(sourceWSLBroker, CodeWSLBrokerFailed, acquireErr))
		default:
			attempts = append(attempts, Attempt{
				Source:  "wam",
				Code:    CodeWAMUnavailable,
				Message: "WAM is available only on Windows, and no WSL bridge to a Windows broker was detected",
			})
		}
		if policy == PolicyWAMOnly {
			return TokenResult{}, acquisitionError(attempts)
		}
	}

	if policy == PolicyWAMFirst || policy == PolicyAzureCLIOnly {
		token, acquireErr := p.azure(ctx, scope)
		if acquireErr == nil {
			return p.finish(resolved.namespace, scope, token, attempts)
		}
		attempts = append(attempts, attemptFromError("azure-cli", CodeAzureCLIFailed, acquireErr))
	}

	return TokenResult{}, acquisitionError(attempts)
}

// namespaceCache returns the in-memory cache for one namespace, loading it
// from protected storage on first use. The caller must hold p.mu.
func (p *Provider) namespaceCache(namespace string) map[string]cachedToken {
	if p.cache == nil {
		p.cache = map[string]map[string]cachedToken{}
	}
	tokens, ok := p.cache[namespace]
	if !ok {
		tokens = p.load(namespace)
		if tokens == nil {
			tokens = map[string]cachedToken{}
		}
		p.cache[namespace] = tokens
	}
	return tokens
}

func sourceAllowed(policy Policy, source string) bool {
	switch policy {
	case PolicyWAMOnly:
		// A cached wsl-broker token satisfies a broker-only policy because it
		// IS a broker token: the same host credential, fetched over interop
		// instead of in-process. Omitting it here would be a silent correctness
		// bug rather than a loud one -- the token would be re-acquired on every
		// call, and the cache would appear to work while never being read.
		return source == "wam" || source == sourceWSLBroker
	case PolicyAzureCLIOnly:
		return source == "azure-cli"
	default:
		return source == "wam" || source == sourceWSLBroker || source == "azure-cli"
	}
}

func (p *Provider) finish(namespace, scope string, token cachedToken, degraded []Attempt) (TokenResult, error) {
	tokens := p.namespaceCache(namespace)
	tokens[scope] = token
	// A cache write failure must not discard a valid freshly acquired token.
	// The next process may need to acquire again, but callers can continue safely.
	_ = p.save(namespace, tokens)
	result := p.result(scope, token, false)
	// Only a source that lost to a later one is a degradation. An empty slice
	// stays nil so the JSON field is omitted on the happy path.
	if len(degraded) > 0 {
		result.Degraded = append([]Attempt(nil), degraded...)
	}
	return result, nil
}

func (p *Provider) result(scope string, token cachedToken, cached bool) TokenResult {
	return TokenResult{
		AccessToken: token.AccessToken,
		ClientID:    p.ClientID,
		TenantID:    p.TenantID,
		Scope:       scope,
		ExpiresAt:   token.ExpiresAt,
		Source:      token.Source,
		Cached:      cached,
	}
}

func (p *Provider) defaults() {
	if p.ClientID == "" {
		p.ClientID = OfficeClientID
	}
	if p.TenantID == "" {
		p.TenantID = MicrosoftTenantID
	}
	if p.goos == "" {
		p.goos = runtime.GOOS
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.wam == nil {
		p.wam = p.acquireWAM
	}
	if p.azure == nil {
		p.azure = p.acquireAzureCLI
	}
	if p.wsl == nil {
		p.wsl = p.acquireWSLBroker
	}
	if p.load == nil {
		p.load = p.loadCache
	}
	if p.save == nil {
		p.save = p.saveCache
	}
}

// wslEnvironmentOrDefault returns the injected WSL seam, or the real one.
//
// A single accessor rather than a defaults() assignment, because the zero
// wslEnvironment is a legitimate value a test may set field-by-field, and
// "is it nil" is not answerable on a struct. Keyed on run, which every path
// needs and which no useful stub omits.
func (p *Provider) wslEnvironmentOrDefault() wslEnvironment {
	if p.wslEnv.run == nil {
		return defaultWSLEnvironment()
	}
	return p.wslEnv
}

// resolvedRequest is the validated, canonical form of a TokenRequest.
type resolvedRequest struct {
	scope       string
	policy      Policy
	minValidity time.Duration
	namespace   string
}

// cacheNamespaceLimit keeps a caller-supplied discriminator short enough to
// stay a label rather than becoming a place to smuggle data.
const cacheNamespaceLimit = 128

func resolveRequest(request TokenRequest) (resolvedRequest, error) {
	var resolved resolvedRequest
	scope := strings.TrimSpace(request.Scope)
	audience := strings.TrimSpace(request.Audience)
	if (scope == "") == (audience == "") {
		return resolved, newRequestError("exactly one of scope or audience is required")
	}
	if audience != "" {
		if strings.ContainsAny(audience, " \t\r\n") || strings.HasSuffix(strings.ToLower(audience), "/.default") {
			return resolved, newRequestError("audience must be a resource identifier without a scope suffix")
		}
		scope = strings.TrimRight(audience, "/") + "/.default"
	}
	if strings.ContainsAny(scope, " \t\r\n") {
		return resolved, newRequestError("exactly one scope is supported per request")
	}

	policy := request.Policy
	if policy == "" {
		policy = PolicyWAMFirst
	}
	switch policy {
	case PolicyWAMFirst, PolicyWAMOnly, PolicyAzureCLIOnly:
	default:
		return resolved, newRequestError("unknown policy %q", policy)
	}

	minValidity := request.MinValidity
	if minValidity == 0 {
		minValidity = DefaultMinValidity
	}
	if minValidity < 0 {
		return resolved, newRequestError("minimum validity cannot be negative")
	}

	namespace := strings.TrimSpace(request.CacheNamespace)
	if len(namespace) > cacheNamespaceLimit {
		return resolved, newRequestError("cache namespace must be at most %d bytes", cacheNamespaceLimit)
	}
	if strings.ContainsFunc(namespace, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return resolved, newRequestError("cache namespace must not contain control characters")
	}

	return resolvedRequest{scope: scope, policy: policy, minValidity: minValidity, namespace: namespace}, nil
}

type brokerResult struct {
	AccessToken string `json:"accessToken"`
	ExpiresOn   string `json:"expiresOn"`
}

func (p *Provider) acquireWAM(ctx context.Context, scope string) (cachedToken, error) {
	// Resolve the assembly set before spawning the broker. A machine whose
	// Az.Accounts cannot load must fail with a stable code that names the fix,
	// not with a PowerShell type-load stack trace.
	selection, brokerErr := resolveBroker(ctx)
	if brokerErr != nil {
		return cachedToken{}, brokerErr
	}
	cmd := exec.CommandContext(ctx, selection.Host, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", wamScript)
	cmd.Env = append(os.Environ(),
		"MSAUTH_BROKER_CLIENT_ID="+p.ClientID,
		"MSAUTH_BROKER_TENANT_ID="+p.TenantID,
		"MSAUTH_BROKER_SCOPE="+scope,
		"MSAUTH_BROKER_DIR="+selection.Module.Directory,
		// Never inherit diagnostic mode into a real acquisition.
		"MSAUTH_BROKER_LOAD_ONLY=0",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return cachedToken{}, fmt.Errorf("broker command failed: %w: %s", err, sanitizeDiagnostic(stderr.String()))
	}
	var result brokerResult
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &result); err != nil {
		return cachedToken{}, fmt.Errorf("broker returned invalid JSON: %w", err)
	}
	if result.AccessToken == "" {
		return cachedToken{}, errors.New("broker returned an empty token")
	}
	expiry, _ := time.Parse(time.RFC3339Nano, result.ExpiresOn)
	if expiry.IsZero() {
		expiry = TokenExpiry(result.AccessToken)
	}
	if expiry.IsZero() {
		return cachedToken{}, errors.New("broker token has no usable expiry")
	}
	return cachedToken{AccessToken: result.AccessToken, ExpiresAt: expiry, Source: "wam"}, nil
}

type azResult struct {
	AccessToken string `json:"accessToken"`
	ExpiresOn   string `json:"expiresOn"`
	ExpiresUnix int64  `json:"expires_on"`
}

func (p *Provider) acquireAzureCLI(ctx context.Context, scope string) (cachedToken, error) {
	resource := resourceFromScope(scope)
	cmd := exec.CommandContext(ctx, "az", "account", "get-access-token", "--resource", resource, "--tenant", p.TenantID, "--output", "json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return cachedToken{}, fmt.Errorf("Azure CLI command failed: %w: %s", err, sanitizeDiagnostic(string(out)))
	}
	var result azResult
	if err := json.Unmarshal(out, &result); err != nil {
		return cachedToken{}, fmt.Errorf("Azure CLI returned invalid JSON: %w", err)
	}
	if result.AccessToken == "" {
		return cachedToken{}, errors.New("Azure CLI returned an empty token")
	}
	expiry := time.Time{}
	if result.ExpiresUnix != 0 {
		expiry = time.Unix(result.ExpiresUnix, 0)
	}
	if expiry.IsZero() && result.ExpiresOn != "" {
		expiry, _ = time.Parse(time.RFC3339Nano, result.ExpiresOn)
	}
	if expiry.IsZero() {
		expiry = TokenExpiry(result.AccessToken)
	}
	if expiry.IsZero() {
		return cachedToken{}, errors.New("Azure CLI token has no usable expiry")
	}
	return cachedToken{AccessToken: result.AccessToken, ExpiresAt: expiry, Source: "azure-cli"}, nil
}

func resourceFromScope(scope string) string {
	for _, suffix := range []string{"/.default", "/user_impersonation"} {
		if strings.HasSuffix(strings.ToLower(scope), strings.ToLower(suffix)) {
			return scope[:len(scope)-len(suffix)]
		}
	}
	return scope
}

func configDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "msauth")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "msauth")
}

// cachePath returns the protected cache file for one namespace. The empty
// namespace keeps its historical filename so the shared default cache is not
// orphaned, and a namespaced cache is a separate file so it can be discarded
// independently.
func (p *Provider) cachePath(namespace string) string {
	key := p.ClientID + "|" + p.TenantID
	if namespace != "" {
		key += "|" + namespace
	}
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(configDir(), "tokens-"+base64.RawURLEncoding.EncodeToString(sum[:9])+".json")
}

func (p *Provider) loadCache(namespace string) map[string]cachedToken {
	result := map[string]cachedToken{}
	data, err := readProtected(p.cachePath(namespace))
	if err == nil {
		_ = json.Unmarshal(data, &result)
	}
	return result
}

func (p *Provider) saveCache(namespace string, tokens map[string]cachedToken) error {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(tokens)
	if err != nil {
		return err
	}
	return writeProtected(p.cachePath(namespace), data)
}
