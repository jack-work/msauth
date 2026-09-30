package msauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// The WSL branch: reaching the WINDOWS broker from inside a Linux distro.
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS
// ---------------------------------------------------------------------------
// Before this file, msauth on Linux had exactly one credential source, the
// Azure CLI, because WAM is a Windows API and wam_other.go is a stub. Inside
// WSL that produced a dead end with no way out: an account whose passkey is
// Windows Hello cannot be satisfied by a Linux browser, which has no platform
// authenticator and can only offer a roaming CTAP2 key over USB HID -- and a
// WSL VM has no USB at all. The user is asked to touch a key that cannot exist.
//
// But the Windows broker is RIGHT THERE, one interop hop away, already holding
// the signed-in account. Microsoft ships the bridge: MSAL detects the WSL
// context and proxies acquisition to the host through an executable it locates
// with `wslinfo --msal-proxy-path`. This file is msauth speaking that protocol
// directly instead of leaving Linux callers stranded.
//
// Measured on 2026-08-27 before any of this was written: the proxy returned the
// real host-side accounts, and a silent acquisition produced a live Kusto token
// (2324 characters, grantedScopes "https://help.kusto.windows.net/user_impersonation
// https://help.kusto.windows.net/.default") with no browser, no passkey prompt
// and no device enrolment.
//
// ---------------------------------------------------------------------------
// WHAT THIS MEANS FOR POLICY
// ---------------------------------------------------------------------------
// A broker is now a PLATFORM CONCEPT rather than a Windows one: WAM on Windows,
// this proxy under WSL, nothing on bare Linux. PolicyWAMFirst and PolicyWAMOnly
// therefore mean "use the platform broker", and they now do something useful on
// two platforms instead of one. Bare Linux still degrades to the Azure CLI, and
// Windows behaviour is untouched.
//
// The source is reported as "wsl-broker" and NOT as "wam", deliberately. They
// are the same credential reached by different machinery, and an operator
// reading a diagnostic needs to know which hop was involved -- a proxy failure
// and a WAM failure have different remedies.

// sourceWSLBroker names this credential source in TokenResult.Source, in
// Attempt.Source, and in the cache, so a cached token can be gated by policy
// exactly like any other.
const sourceWSLBroker = "wsl-broker"

// wslBrokerProtocolVersion is the --bversion the proxy is invoked with.
//
// Pinned, not discovered. The request body below is the shape version 3
// accepts; a future version may accept a different one, and silently sending a
// v3 body under a v4 banner would be worse than refusing. Bump both together.
const wslBrokerProtocolVersion = "3"

// wslBrokerRedirectURI is the redirect a public client presents to the broker.
//
// The native-client value is what the proxy accepted in testing. It is not a
// live endpoint and nothing is ever redirected to it: a brokered acquisition
// never leaves the machine, and this exists only because the request schema
// requires the field.
const wslBrokerRedirectURI = "https://login.microsoftonline.com/common/oauth2/nativeclient"

// wslProxyTimeout bounds one proxy invocation.
//
// It exists because the proxy is a WINDOWS process reached over interop: if
// that channel is wedged, the child can hang rather than fail, and a hung
// acquisition is indistinguishable from a slow one to every caller above. A
// bounded failure is always better than an unbounded wait.
//
// 90 SECONDS WAS TOO SHORT, AND THE COST WAS A DESTROYED DIAGNOSIS.
// Measured 2026-09-22 on this box: a `getAccounts` call answered after **175
// seconds** with a real, specific error --
//
//	aad WAM FindAllAccountsAsync failed with status: 3 (errorCode 0xcaad0009,
//	tag 576582538)
//
// Under the old bound msauth never saw that. It reported "the Windows MSAL
// proxy did not answer within 1m30s" on every attempt, which says the channel
// is wedged when in fact the channel was fine and the BROKER was failing. The
// caller then fell through to the Azure CLI, whose token the downstream
// service rejected, and the operator was left debugging a 410 three layers
// away from the fault.
//
// So this bound is not about patience. A timeout that fires before the
// underlying call can report its own failure converts a diagnosable error into
// an undiagnosable one, which is strictly worse than waiting. 300s is ~1.7x the
// measured worst case; revisit with a measurement, never with a guess.
const wslProxyTimeout = 300 * time.Second

// wslEnvironment is the seam every test substitutes. Production wires it to the
// real filesystem and process table; no test spawns a Windows binary, reaches a
// network, or touches a credential.
type wslEnvironment struct {
	// goos is runtime.GOOS, injectable so the platform gate itself is testable
	// from any machine.
	goos string
	// readFile reads /proc/sys/kernel/osrelease. A function, not a constant, so
	// the detector can be exercised with kernel strings from other machines.
	readFile func(string) ([]byte, error)
	// lookPath resolves wslinfo.
	lookPath func(string) (string, error)
	// run executes a command and returns its stdout.
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func defaultWSLEnvironment() wslEnvironment {
	return wslEnvironment{
		goos:     runtime.GOOS,
		readFile: os.ReadFile,
		lookPath: exec.LookPath,
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			// Stdout only. The proxy writes diagnostics to stderr and its JSON
			// to stdout, and mixing them would corrupt the parse.
			return cmd.Output()
		},
	}
}

// runningUnderWSL reports whether this process is inside a WSL distro.
//
// The kernel release string is the check, because it is the one signal that
// cannot be inherited, forwarded or faked by a shell: WSL kernels carry
// "microsoft" or "WSL" in /proc/sys/kernel/osrelease. WSL_DISTRO_NAME is
// deliberately NOT used -- it is an ordinary environment variable, so it
// survives into containers, ssh sessions and sudo invocations that are not
// WSL at all, and a false positive here sends a Linux user down a branch whose
// every error message talks about Windows.
func (e wslEnvironment) runningUnderWSL() bool {
	if e.goos != "linux" {
		return false
	}
	release, err := e.readFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}
	lowered := strings.ToLower(string(release))
	return strings.Contains(lowered, "microsoft") || strings.Contains(lowered, "wsl")
}

// msalProxyPath asks WSL where the host-side MSAL proxy lives.
//
// It is always asked rather than hardcoded. The answer observed on one machine
// is "/mnt/c/Program Files/WSL/msal.wsl.proxy.exe", but that is an
// installation detail of the Windows WSL package: it moves with the install
// location, and a committed path would be both wrong elsewhere and a claim
// about someone's filesystem layout.
//
// THE FAILURE THIS GUARDS IS NOT HYPOTHETICAL. wslinfo is /bin/wslinfo -> /init,
// the interop shim, and /bin is absent from the PATH of a D-Bus-activated or
// systemd-managed process even though a login shell has it. A service that
// cannot see wslinfo gets an empty answer and reports a network problem. So a
// missing wslinfo is reported as its own code, naming PATH.
func (e wslEnvironment) msalProxyPath(ctx context.Context) (string, *AuthError) {
	if _, err := e.lookPath("wslinfo"); err != nil {
		return "", &AuthError{
			Code: CodeWSLProxyUnavailable,
			Message: "wslinfo is not on PATH, so the Windows MSAL proxy cannot be located; " +
				"note that /bin is missing from the PATH of D-Bus-activated and systemd-managed " +
				"processes even when a login shell has it",
		}
	}
	out, err := e.run(ctx, "wslinfo", "--msal-proxy-path")
	if err != nil {
		return "", &AuthError{
			Code:    CodeWSLProxyUnavailable,
			Message: fmt.Sprintf("wslinfo --msal-proxy-path failed: %v", sanitizeDiagnostic(err.Error())),
		}
	}
	// The value is a path that legitimately contains spaces ("Program Files"),
	// so only surrounding whitespace and the trailing newline may be trimmed.
	path := strings.TrimSpace(string(out))
	if path == "" {
		return "", &AuthError{
			Code:    CodeWSLProxyUnavailable,
			Message: "wslinfo reported no MSAL proxy path; the Windows WSL package may predate broker support",
		}
	}
	return path, nil
}

// newCorrelationID mints the --cid every proxy invocation carries.
//
// Written here rather than pulled in as a dependency: this module has one
// indirect requirement and adding a uuid package to format 16 random bytes
// would be a poor trade. The value is a correlation identifier in Microsoft
// telemetry, so it must be unique per call and must not encode anything about
// this machine -- crypto/rand with the version and variant bits set is exactly
// a v4 UUID and nothing more.
func newCorrelationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Unreachable in practice; a correlation id is a diagnostic aid, and
		// failing an acquisition because one could not be minted would trade a
		// working credential for a logging nicety.
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// wslAccount is one host-side account as the proxy reports it.
//
// The whole object is round-tripped back into the token request unmodified,
// which is why it is captured as raw JSON as well as decoded: the broker
// matches on fields this struct does not name, and re-serialising only the
// fields Go happens to model would silently drop them. That is the classic
// lossy-default fault, and here it would present as "account not found" on a
// machine where the account plainly exists.
type wslAccount struct {
	raw json.RawMessage

	HomeAccountID string `json:"homeAccountId"`
	Username      string `json:"username"`
	Realm         string `json:"realm"`
	Environment   string `json:"environment"`
}

func (a *wslAccount) UnmarshalJSON(data []byte) error {
	type plain wslAccount
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*a = wslAccount(decoded)
	a.raw = append(json.RawMessage(nil), data...)
	return nil
}

// wslBrokerResponse is the proxy's reply. Only non-secret fields are named
// beyond the token itself; nothing here is ever logged.
type wslBrokerResponse struct {
	BrokerTokenResponse struct {
		AccessToken   string          `json:"accessToken"`
		GrantedScopes string          `json:"grantedScopes"`
		ExpiresOn     json.Number     `json:"expiresOn"`
		Error         *wslBrokerError `json:"error"`
	} `json:"brokerTokenResponse"`
}

type wslBrokerError struct {
	Context   string `json:"context"`
	ErrorCode int    `json:"errorCode"`
	Status    int    `json:"status"`
	SubStatus int    `json:"subStatus"`
	Tag       int64  `json:"tag"`
}

func (e *wslBrokerError) String() string {
	if e == nil {
		return ""
	}
	// The tag is a stable Microsoft-side identifier and is worth carrying: it
	// is the only part of this that a Microsoft engineer can look up.
	return fmt.Sprintf("%s (errorCode %d, status %d, subStatus %d, tag %d)",
		e.Context, e.ErrorCode, e.Status, e.SubStatus, e.Tag)
}

// callProxy invokes one proxy method and decodes its JSON reply.
func (e wslEnvironment) callProxy(ctx context.Context, proxy, method string, request any) ([]byte, *AuthError) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, &AuthError{Code: CodeInternal, Message: fmt.Sprintf("encoding %s request: %v", method, err)}
	}

	ctx, cancel := context.WithTimeout(ctx, wslProxyTimeout)
	defer cancel()

	out, runErr := e.run(ctx, proxy,
		"--method", method,
		"--bversion", wslBrokerProtocolVersion,
		"--cid", newCorrelationID(),
		"--requestJson", string(body),
	)
	if runErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, &AuthError{
				Code:    CodeWSLBrokerFailed,
				Message: fmt.Sprintf("the Windows MSAL proxy did not answer within %s", wslProxyTimeout),
			}
		}
		return nil, &AuthError{
			Code:    CodeWSLBrokerFailed,
			Message: fmt.Sprintf("invoking the Windows MSAL proxy: %v", sanitizeDiagnostic(runErr.Error())),
		}
	}

	// The proxy is a Windows console program: its stdout carries CRLF line
	// endings and can carry NUL padding. Both are invisible in a terminal and
	// both break encoding/json, so they are stripped here rather than being
	// discovered later as an unintelligible parse error.
	cleaned := strings.NewReplacer("\x00", "", "\r", "").Replace(string(out))
	trimmed := []byte(strings.TrimSpace(cleaned))

	// A FAILED CALL IS A 200 WITH AN ERROR OBJECT, AND IT MUST NOT DECODE AS
	// AN EMPTY SUCCESS.
	//
	// The proxy reports method failure as a top-level `{"error":{...}}` and
	// exits 0. Every per-method decoder here unmarshals into a struct shaped
	// for the HAPPY path, and that struct accepts such a payload silently: no
	// matching keys, no error, a zero value. `getAccounts` therefore turned
	//
	//	{"error":{"context":"aad WAM FindAllAccountsAsync failed with status: 3"}}
	//
	// into "the Windows broker holds no accounts; sign in on the Windows host
	// first" -- advice that is wrong, unfollowable, and points away from a
	// broker that was failing for an entirely different reason (measured
	// 2026-09-22). A broken instrument reported an empty world.
	//
	// BUT AN ERROR ALONGSIDE A PAYLOAD IS A WARNING, NOT A FAILURE, and the
	// distinction is load-bearing rather than pedantic. A healthy response on
	// this box carries BOTH seven usable AAD accounts AND
	//
	//	{"context":"msa WAM FindAllAccountsAsync failed with status: 1",
	//	 "errorCode":2147942405}   // 0x80070005, ACCESS_DENIED
	//
	// because the signed-in identity has no consumer MSA half. Rejecting that
	// would break every working machine to fix a broken one -- which a first
	// draft of this check did, turning a repaired broker back into a hard
	// failure.
	//
	// So the rule is: an error is fatal only when it is the WHOLE response.
	// Anything carrying a payload beside it is a partial success, and the
	// decoder downstream is entitled to the payload.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &envelope); err == nil {
		if rawErr, ok := envelope["error"]; ok && len(envelope) == 1 {
			var failure wslBrokerError
			if json.Unmarshal(rawErr, &failure) == nil {
				return nil, &AuthError{
					Code:    CodeWSLBrokerFailed,
					Message: fmt.Sprintf("the Windows MSAL proxy failed %s: %s", method, sanitizeDiagnostic(failure.String())),
				}
			}
		}
	}

	return trimmed, nil
}

// wslGetAccounts lists the host-side accounts visible to this client.
func (e wslEnvironment) wslGetAccounts(ctx context.Context, proxy, clientID, authority string) ([]wslAccount, *AuthError) {
	raw, authErr := e.callProxy(ctx, proxy, "getAccounts", map[string]any{
		"clientId":    clientID,
		"authority":   authority,
		"redirectUri": wslBrokerRedirectURI,
	})
	if authErr != nil {
		return nil, authErr
	}
	var decoded struct {
		Accounts []wslAccount `json:"accounts"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, &AuthError{
			Code:    CodeWSLBrokerFailed,
			Message: "the Windows MSAL proxy returned an account list this build cannot parse",
		}
	}
	return decoded.Accounts, nil
}

// selectAccount picks which host-side identity to acquire for.
//
// Tenant first: the proxy returns every account the host is signed into,
// including personal and other-tenant ones, and the same human can appear
// several times under different realms. Acquiring silently for the wrong one
// yields a token that is valid, wrong, and rejected downstream with an opaque
// authorization error -- the expensive shape of failure. Matching realm to the
// provider's tenant makes the choice explicit.
//
// The fallback to a single remaining account is deliberate and narrow: with
// exactly one candidate there is nothing to get wrong. With several and no
// tenant match, this refuses and names them, because guessing an identity is
// not a thing an auth library should do quietly.
func selectAccount(accounts []wslAccount, tenantID string) (wslAccount, *AuthError) {
	if len(accounts) == 0 {
		return wslAccount{}, &AuthError{
			Code: CodeWSLBrokerFailed,
			Message: "the Windows broker holds no accounts; sign in on the Windows host first " +
				"(any Microsoft app, or Settings > Accounts)",
		}
	}
	for _, account := range accounts {
		if tenantID != "" && strings.EqualFold(account.Realm, tenantID) {
			return account, nil
		}
	}
	if len(accounts) == 1 {
		return accounts[0], nil
	}
	var names []string
	for _, account := range accounts {
		names = append(names, fmt.Sprintf("%s (tenant %s)", account.Username, account.Realm))
	}
	return wslAccount{}, &AuthError{
		Code: CodeWSLBrokerFailed,
		Message: fmt.Sprintf("the Windows broker holds no account for tenant %s; it holds: %s",
			tenantID, strings.Join(names, ", ")),
	}
}

// acquireWSLBroker acquires one token through the Windows broker.
//
// Silent only, and that is the point rather than a limitation. The host already
// holds the signed-in account and its refresh material, so this is exactly the
// case a Linux caller could not reach before. An interactive fallback would put
// a Windows dialog in front of a user who may be looking at a terminal on
// another display, so a caller who is genuinely signed out gets a clear error
// naming the remedy instead.
func (p *Provider) acquireWSLBroker(ctx context.Context, scope string) (cachedToken, error) {
	env := p.wslEnvironmentOrDefault()

	proxy, authErr := env.msalProxyPath(ctx)
	if authErr != nil {
		return cachedToken{}, authErr
	}

	authority := fmt.Sprintf("https://login.microsoftonline.com/%s", p.TenantID)

	accounts, authErr := env.wslGetAccounts(ctx, proxy, p.ClientID, authority)
	if authErr != nil {
		return cachedToken{}, authErr
	}
	account, authErr := selectAccount(accounts, p.TenantID)
	if authErr != nil {
		return cachedToken{}, authErr
	}

	// The request shape is not obvious and was established by experiment: four
	// flatter arrangements were rejected with "Invalid requestJson" (tag
	// 508371229) before this one succeeded. The parameters must be nested under
	// authParameters, the account object must appear BOTH at the top level and
	// inside it, and authorizationType must be 8. Do not "tidy" this.
	authParameters := map[string]any{
		"account": account.raw,
		"additionalQueryParametersForAuthorization": map[string]string{},
		"authority":         authority,
		"authorizationType": 8,
		"clientId":          p.ClientID,
		"redirectUri":       wslBrokerRedirectURI,
		"requestedScopes":   []string{scope},
		"username":          account.Username,
	}
	raw, authErr := env.callProxy(ctx, proxy, "acquireTokenSilently", map[string]any{
		"account":        account.raw,
		"authParameters": authParameters,
	})
	if authErr != nil {
		return cachedToken{}, authErr
	}

	var response wslBrokerResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return cachedToken{}, &AuthError{
			Code:    CodeWSLBrokerFailed,
			Message: "the Windows MSAL proxy returned a token response this build cannot parse",
		}
	}
	if brokerErr := response.BrokerTokenResponse.Error; brokerErr != nil {
		return cachedToken{}, &AuthError{
			Code:    CodeWSLBrokerFailed,
			Message: fmt.Sprintf("the Windows broker refused the request: %s", sanitizeDiagnostic(brokerErr.String())),
		}
	}
	token := response.BrokerTokenResponse.AccessToken
	if token == "" {
		return cachedToken{}, &AuthError{
			Code:    CodeWSLBrokerFailed,
			Message: "the Windows broker returned an empty access token",
		}
	}

	expiry, authErr := parseWSLExpiry(response.BrokerTokenResponse.ExpiresOn)
	if authErr != nil {
		return cachedToken{}, authErr
	}

	return cachedToken{AccessToken: token, ExpiresAt: expiry, Source: sourceWSLBroker}, nil
}

// parseWSLExpiry converts the broker's expiry to a time.
//
// EXPIRESON IS EPOCH MILLISECONDS, NOT SECONDS. An observed value is
// 1787860282000; read as seconds that is the year 58620, which would make every
// token look valid forever, defeat MinValidity, and serve expired tokens from
// cache until something downstream returned 401. A unit error here does not
// fail loudly, it fails as a wrong answer -- so the magnitude is checked rather
// than assumed, and a value that cannot be milliseconds is refused instead of
// being reinterpreted.
func parseWSLExpiry(value json.Number) (time.Time, *AuthError) {
	if value == "" {
		return time.Time{}, &AuthError{
			Code:    CodeWSLBrokerFailed,
			Message: "the Windows broker returned a token with no expiry",
		}
	}
	millis, err := value.Int64()
	if err != nil {
		return time.Time{}, &AuthError{
			Code:    CodeWSLBrokerFailed,
			Message: fmt.Sprintf("the Windows broker returned an unreadable expiry %q", value.String()),
		}
	}
	// Anything below this is not a plausible millisecond timestamp. 10^12 ms is
	// 2001-09-09; a seconds-valued field would land far below it and be caught
	// here rather than becoming a token that never appears to expire.
	const minimumPlausibleMillis = int64(1_000_000_000_000)
	if millis < minimumPlausibleMillis {
		return time.Time{}, &AuthError{
			Code: CodeWSLBrokerFailed,
			Message: fmt.Sprintf("the Windows broker returned expiry %d, which is too small to be "+
				"epoch milliseconds; refusing rather than guessing the unit", millis),
		}
	}
	return time.UnixMilli(millis).UTC(), nil
}
