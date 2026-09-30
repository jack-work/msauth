package msauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests for the WSL branch.
//
// NOTHING HERE SPAWNS A WINDOWS BINARY, REACHES A NETWORK, OR TOUCHES A
// CREDENTIAL. The wslEnvironment seam is substituted in every case, so the
// suite is identical on a developer's Mac, on CI, and on the one machine where
// the real proxy exists. A test that only passes where the broker happens to be
// installed is not a test of this code.

// fakeProxy records what it was asked and replies with canned JSON.
type fakeProxy struct {
	proxyPath string
	// replies is method -> JSON reply.
	replies map[string]string
	// failures is method -> error.
	failures map[string]error
	// calls records every invocation for assertions.
	calls []fakeCall
	// noWslinfo makes lookPath fail, modelling the PATH fault.
	noWslinfo bool
	// osrelease is the kernel string the detector reads.
	osrelease string
}

type fakeCall struct {
	method  string
	request map[string]any
}

func (f *fakeProxy) env(goos string) wslEnvironment {
	release := f.osrelease
	if release == "" {
		release = "6.6.87.2-microsoft-standard-WSL2"
	}
	return wslEnvironment{
		goos: goos,
		readFile: func(string) ([]byte, error) {
			return []byte(release), nil
		},
		lookPath: func(name string) (string, error) {
			if f.noWslinfo {
				return "", errors.New("executable file not found in $PATH")
			}
			return "/bin/" + name, nil
		},
		run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			// Matched on the base name: production now resolves wslinfo to an
			// absolute path, so this arrives as "/bin/wslinfo".
			if filepath.Base(name) == "wslinfo" {
				return []byte(f.proxyPath + "\n"), nil
			}
			var method, body string
			for i := 0; i+1 < len(args); i += 2 {
				switch args[i] {
				case "--method":
					method = args[i+1]
				case "--requestJson":
					body = args[i+1]
				}
			}
			var decoded map[string]any
			_ = json.Unmarshal([]byte(body), &decoded)
			f.calls = append(f.calls, fakeCall{method: method, request: decoded})
			if err, ok := f.failures[method]; ok {
				return nil, err
			}
			reply, ok := f.replies[method]
			if !ok {
				return nil, fmt.Errorf("fake proxy has no reply for %q", method)
			}
			// Windows console output: CRLF, and sometimes NUL padding. Emitting
			// it here is the point -- if the production cleaner regresses, this
			// is what catches it.
			return []byte("\x00" + strings.ReplaceAll(reply, "\n", "\r\n") + "\r\n"), nil
		},
	}
}

func accountsJSON(accounts ...string) string {
	return `{"accounts":[` + strings.Join(accounts, ",") + `]}`
}

func accountJSON(username, realm string) string {
	return fmt.Sprintf(
		`{"homeAccountId":"oid.%s","username":%q,"realm":%q,"environment":"login.microsoftonline.com","localAccountId":"oid","familyName":"F"}`,
		realm, username, realm)
}

func tokenJSON(token string, expiresOnMillis int64) string {
	return fmt.Sprintf(`{"brokerTokenResponse":{"accessToken":%q,"expiresOn":%d,"grantedScopes":"s"}}`,
		token, expiresOnMillis)
}

const testTenant = "72f988bf-86f1-41af-91ab-2d7cd011db47"

func providerWithProxy(f *fakeProxy, goos string) *Provider {
	p := &Provider{ClientID: "client", TenantID: testTenant}
	p.defaults()
	p.goos = goos
	p.wslEnv = f.env(goos)
	p.load = func(string) map[string]cachedToken { return map[string]cachedToken{} }
	p.save = func(string, map[string]cachedToken) error { return nil }
	return p
}

func TestWSLBrokerAcquiresAToken(t *testing.T) {
	expires := time.Now().Add(time.Hour).UnixMilli()
	f := &fakeProxy{
		proxyPath: "/mnt/c/Program Files/WSL/msal.wsl.proxy.exe",
		replies: map[string]string{
			"getAccounts":          accountsJSON(accountJSON("user@example.com", testTenant)),
			"acquireTokenSilently": tokenJSON("header.payload.signature", expires),
		},
	}
	p := providerWithProxy(f, "linux")

	token, err := p.acquireWSLBroker(context.Background(), "https://help.kusto.windows.net/.default")
	if err != nil {
		t.Fatalf("acquiring: %v", err)
	}
	if token.AccessToken != "header.payload.signature" {
		t.Errorf("access token = %q", token.AccessToken)
	}
	if token.Source != sourceWSLBroker {
		t.Errorf("source = %q, want %q", token.Source, sourceWSLBroker)
	}
	if got := token.ExpiresAt.UnixMilli(); got != expires {
		t.Errorf("expiry = %d, want %d", got, expires)
	}
}

// The request shape was established by experiment and four flatter arrangements
// were rejected by the real broker. That makes it a wire contract, and a wire
// contract with no test is a thing someone tidies away.
func TestWSLBrokerSendsTheShapeTheBrokerAccepts(t *testing.T) {
	f := &fakeProxy{
		proxyPath: "/p.exe",
		replies: map[string]string{
			"getAccounts":          accountsJSON(accountJSON("user@example.com", testTenant)),
			"acquireTokenSilently": tokenJSON("a.b.c", time.Now().Add(time.Hour).UnixMilli()),
		},
	}
	p := providerWithProxy(f, "linux")
	if _, err := p.acquireWSLBroker(context.Background(), "scope/.default"); err != nil {
		t.Fatalf("acquiring: %v", err)
	}

	var request map[string]any
	for _, call := range f.calls {
		if call.method == "acquireTokenSilently" {
			request = call.request
		}
	}
	if request == nil {
		t.Fatal("no acquireTokenSilently call was made")
	}
	if _, ok := request["account"]; !ok {
		t.Error("the account must appear at the TOP level; a flat request is rejected")
	}
	params, ok := request["authParameters"].(map[string]any)
	if !ok {
		t.Fatal("parameters must be nested under authParameters")
	}
	if _, ok := params["account"]; !ok {
		t.Error("the account must ALSO appear inside authParameters")
	}
	if got := params["authorizationType"]; got != float64(8) {
		t.Errorf("authorizationType = %v, want 8", got)
	}
	scopes, ok := params["requestedScopes"].([]any)
	if !ok || len(scopes) != 1 || scopes[0] != "scope/.default" {
		t.Errorf("requestedScopes = %v, want [scope/.default]", params["requestedScopes"])
	}
	if params["clientId"] != "client" {
		t.Errorf("clientId = %v", params["clientId"])
	}
	if !strings.HasSuffix(fmt.Sprint(params["authority"]), testTenant) {
		t.Errorf("authority = %v, want it to name the tenant", params["authority"])
	}
}

// The account object must survive the round trip byte for byte. The broker
// matches on fields this package does not model, so re-serialising only the
// modelled ones would drop them -- and would present as "account not found" on
// a machine where the account plainly exists.
func TestWSLBrokerRoundTripsUnmodelledAccountFields(t *testing.T) {
	account := `{"homeAccountId":"h","username":"u@e.com","realm":"` + testTenant +
		`","environment":"login.microsoftonline.com","someFutureField":"must-survive","clientInfo":"ci"}`
	f := &fakeProxy{
		proxyPath: "/p.exe",
		replies: map[string]string{
			"getAccounts":          accountsJSON(account),
			"acquireTokenSilently": tokenJSON("a.b.c", time.Now().Add(time.Hour).UnixMilli()),
		},
	}
	p := providerWithProxy(f, "linux")
	if _, err := p.acquireWSLBroker(context.Background(), "s"); err != nil {
		t.Fatalf("acquiring: %v", err)
	}
	for _, call := range f.calls {
		if call.method != "acquireTokenSilently" {
			continue
		}
		sent, _ := json.Marshal(call.request["account"])
		if !strings.Contains(string(sent), "must-survive") {
			t.Fatalf("an unmodelled account field was dropped: %s", sent)
		}
	}
}

// EXPIRESON IS MILLISECONDS. Read as seconds it becomes the year 58620, every
// token looks valid forever, MinValidity stops meaning anything, and expired
// tokens are served from cache until something downstream returns 401. A unit
// error here is a wrong answer, not a crash, so it gets a test in both
// directions.
func TestWSLExpiryIsMillisecondsAndRejectsSeconds(t *testing.T) {
	millis := int64(1787860282000)
	got, authErr := parseWSLExpiry(json.Number(fmt.Sprint(millis)))
	if authErr != nil {
		t.Fatalf("parsing milliseconds: %v", authErr)
	}
	if got.Year() != 2026 {
		t.Errorf("year = %d, want 2026; the value was read in the wrong unit", got.Year())
	}

	// The same instant expressed in SECONDS must be refused, not reinterpreted.
	if _, authErr := parseWSLExpiry(json.Number(fmt.Sprint(millis / 1000))); authErr == nil {
		t.Fatal("a seconds-valued expiry was accepted; that yields a token that never appears to expire")
	}
	if _, authErr := parseWSLExpiry(json.Number("")); authErr == nil {
		t.Error("an empty expiry was accepted")
	}
	if _, authErr := parseWSLExpiry(json.Number("not-a-number")); authErr == nil {
		t.Error("an unparseable expiry was accepted")
	}
}

// The PATH fault that masqueraded as a network failure gets its own code, so a
// caller can tell "your PATH is wrong" from "the broker said no".
func TestMissingWslinfoIsItsOwnCodeAndNamesPATH(t *testing.T) {
	f := &fakeProxy{proxyPath: "/p.exe", noWslinfo: true}
	p := providerWithProxy(f, "linux")

	_, err := p.acquireWSLBroker(context.Background(), "s")
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T", err)
	}
	if authErr.Code != CodeWSLProxyUnavailable {
		t.Errorf("code = %q, want %q", authErr.Code, CodeWSLProxyUnavailable)
	}
	if !strings.Contains(authErr.Message, "PATH") {
		t.Errorf("the message must name PATH, got %q", authErr.Message)
	}
	// The remedy differs depending on whether a fallback location was even
	// looked at, so the message has to say it tried.
	for _, candidate := range wslInfoFallbacks {
		if !strings.Contains(authErr.Message, candidate) {
			t.Errorf("the message must name the fallback %q it tried, got %q", candidate, authErr.Message)
		}
	}
}

// The regression this whole fallback exists for: a systemd user unit has no
// /bin on PATH, so lookPath fails while /bin/wslinfo is sitting right there.
// Before the fallback, every such service reported a network problem.
func TestWslinfoIsFoundAtItsAbsolutePathWhenPATHLacksIt(t *testing.T) {
	f := &fakeProxy{
		proxyPath: "/p.exe",
		noWslinfo: true, // PATH cannot see it, exactly as under systemd
		replies: map[string]string{
			"getAccounts": accountsJSON(accountJSON("u@example.com", testTenant)),
			"acquireTokenSilently": tokenJSON(
				"t", time.Now().Add(time.Hour).UnixMilli()),
		},
	}
	env := f.env("linux")
	// The filesystem still has it, at the first fallback location.
	env.statExecutable = func(path string) error {
		if path == wslInfoFallbacks[0] {
			return nil
		}
		return errors.New("no such file")
	}

	resolved, authErr := env.resolveWSLInfo()
	if authErr != nil {
		t.Fatalf("resolving should have fallen back, got %v", authErr)
	}
	if resolved != wslInfoFallbacks[0] {
		t.Errorf("resolved = %q, want %q", resolved, wslInfoFallbacks[0])
	}

	// And the proxy path is then obtainable, which is the part that was broken.
	proxy, authErr := env.msalProxyPath(context.Background())
	if authErr != nil {
		t.Fatalf("msalProxyPath: %v", authErr)
	}
	if proxy != "/p.exe" {
		t.Errorf("proxy = %q, want %q", proxy, "/p.exe")
	}
}

// PATH wins when it works: an operator who placed wslinfo deliberately is not
// second-guessed by a hardcoded list.
func TestPATHIsPreferredOverTheFallback(t *testing.T) {
	f := &fakeProxy{proxyPath: "/p.exe"}
	env := f.env("linux")
	env.lookPath = func(string) (string, error) { return "/opt/custom/wslinfo", nil }
	env.statExecutable = func(string) error {
		t.Error("the fallback was consulted even though PATH resolved")
		return nil
	}

	resolved, authErr := env.resolveWSLInfo()
	if authErr != nil {
		t.Fatalf("resolveWSLInfo: %v", authErr)
	}
	if resolved != "/opt/custom/wslinfo" {
		t.Errorf("resolved = %q, want the PATH answer", resolved)
	}
}

func TestWSLDetection(t *testing.T) {
	cases := []struct {
		name    string
		goos    string
		release string
		want    bool
	}{
		{"wsl2 kernel", "linux", "6.6.87.2-microsoft-standard-WSL2", true},
		{"microsoft kernel", "linux", "5.15.0-1000-microsoft", true},
		{"ordinary linux", "linux", "6.12.4-arch1-1", false},
		{"windows", "windows", "6.6.87.2-microsoft-standard-WSL2", false},
		{"darwin", "darwin", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := wslEnvironment{
				goos:     c.goos,
				readFile: func(string) ([]byte, error) { return []byte(c.release), nil },
			}
			if got := env.runningUnderWSL(); got != c.want {
				t.Errorf("runningUnderWSL() = %v, want %v", got, c.want)
			}
		})
	}
}

// A false positive here sends a plain Linux user down a branch whose every
// error message talks about Windows, so the detector must ignore the
// environment variable that a container, an ssh session or sudo can carry in.
func TestWSLDetectionIgnoresTheEnvironmentVariable(t *testing.T) {
	t.Setenv("WSL_DISTRO_NAME", "Ubuntu")
	env := wslEnvironment{
		goos:     "linux",
		readFile: func(string) ([]byte, error) { return []byte("6.12.4-arch1-1"), nil },
	}
	if env.runningUnderWSL() {
		t.Fatal("WSL_DISTRO_NAME must not be evidence; it survives into places that are not WSL")
	}
}

func TestSelectAccountPrefersTheTenantAndRefusesToGuess(t *testing.T) {
	other := wslAccount{Username: "user@other.com", Realm: "11111111-1111-1111-1111-111111111111"}
	mine := wslAccount{Username: "user@example.com", Realm: testTenant}

	got, authErr := selectAccount([]wslAccount{other, mine}, testTenant)
	if authErr != nil || got.Username != mine.Username {
		t.Fatalf("tenant match failed: %v %v", got.Username, authErr)
	}

	// One candidate and no tenant match: nothing to get wrong.
	if _, authErr := selectAccount([]wslAccount{other}, testTenant); authErr != nil {
		t.Errorf("a single account should be used: %v", authErr)
	}

	// Several candidates and no tenant match: refuse, and name them.
	_, authErr = selectAccount([]wslAccount{other, {Username: "third@x.com", Realm: "2222"}}, testTenant)
	if authErr == nil {
		t.Fatal("an ambiguous identity was silently chosen")
	}
	if !strings.Contains(authErr.Message, "user@other.com") {
		t.Errorf("the error must list the candidates, got %q", authErr.Message)
	}

	if _, authErr := selectAccount(nil, testTenant); authErr == nil {
		t.Error("an empty account list was accepted")
	}
}

func TestWSLBrokerSurfacesABrokerRefusal(t *testing.T) {
	f := &fakeProxy{
		proxyPath: "/p.exe",
		replies: map[string]string{
			"getAccounts": accountsJSON(accountJSON("u@e.com", testTenant)),
			"acquireTokenSilently": `{"brokerTokenResponse":{"error":{"context":"Invalid requestJson",` +
				`"errorCode":0,"status":0,"subStatus":0,"tag":508371229}}}`,
		},
	}
	p := providerWithProxy(f, "linux")
	_, err := p.acquireWSLBroker(context.Background(), "s")
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T", err)
	}
	if authErr.Code != CodeWSLBrokerFailed {
		t.Errorf("code = %q, want %q", authErr.Code, CodeWSLBrokerFailed)
	}
	// The tag is the only part a Microsoft engineer can look up.
	if !strings.Contains(authErr.Message, "508371229") {
		t.Errorf("the broker's tag must survive into the message, got %q", authErr.Message)
	}
}

// Policy routing: the same policy must reach a broker on Windows AND under WSL,
// and must still degrade honestly on bare Linux.
func TestBrokerPolicyRoutesByPlatform(t *testing.T) {
	newProvider := func(goos, release string) (*Provider, *bool, *bool) {
		wamCalled, wslCalled := false, false
		p := &Provider{ClientID: "c", TenantID: testTenant}
		p.defaults()
		p.goos = goos
		p.wslEnv = wslEnvironment{
			goos:     goos,
			readFile: func(string) ([]byte, error) { return []byte(release), nil },
			lookPath: func(n string) (string, error) { return "/bin/" + n, nil },
			run:      func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("unused") },
		}
		p.wam = func(context.Context, string) (cachedToken, error) {
			wamCalled = true
			return cachedToken{AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour), Source: "wam"}, nil
		}
		p.wsl = func(context.Context, string) (cachedToken, error) {
			wslCalled = true
			return cachedToken{AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour), Source: sourceWSLBroker}, nil
		}
		p.azure = func(context.Context, string) (cachedToken, error) {
			return cachedToken{}, errors.New("azure cli unavailable")
		}
		p.load = func(string) map[string]cachedToken { return map[string]cachedToken{} }
		p.save = func(string, map[string]cachedToken) error { return nil }
		return p, &wamCalled, &wslCalled
	}

	t.Run("windows uses WAM", func(t *testing.T) {
		p, wam, wsl := newProvider("windows", "")
		result, err := p.Acquire(context.Background(), TokenRequest{Scope: "s", Policy: PolicyWAMOnly})
		if err != nil || !*wam || *wsl {
			t.Fatalf("err=%v wam=%v wsl=%v", err, *wam, *wsl)
		}
		if result.Source != "wam" {
			t.Errorf("source = %q", result.Source)
		}
	})

	t.Run("wsl uses the bridge", func(t *testing.T) {
		p, wam, wsl := newProvider("linux", "6.6.87.2-microsoft-standard-WSL2")
		result, err := p.Acquire(context.Background(), TokenRequest{Scope: "s", Policy: PolicyWAMOnly})
		if err != nil || *wam || !*wsl {
			t.Fatalf("err=%v wam=%v wsl=%v", err, *wam, *wsl)
		}
		if result.Source != sourceWSLBroker {
			t.Errorf("source = %q, want %q", result.Source, sourceWSLBroker)
		}
	})

	t.Run("bare linux has no broker", func(t *testing.T) {
		p, wam, wsl := newProvider("linux", "6.12.4-arch1-1")
		_, err := p.Acquire(context.Background(), TokenRequest{Scope: "s", Policy: PolicyWAMOnly})
		if err == nil {
			t.Fatal("bare Linux must not claim a broker")
		}
		if *wam || *wsl {
			t.Errorf("no broker should have been called: wam=%v wsl=%v", *wam, *wsl)
		}
		// The top-level message is deliberately generic; the per-source detail
		// lives in Attempts, which is what an operator is shown. Assert there,
		// not on the summary -- asserting on the summary would pass while the
		// useful half went missing.
		var authErr *AuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("want *AuthError, got %T", err)
		}
		var found bool
		for _, attempt := range authErr.Attempts {
			if attempt.Code == CodeWAMUnavailable && strings.Contains(attempt.Message, "WSL") {
				found = true
			}
		}
		if !found {
			t.Errorf("no attempt explained that neither WAM nor a WSL bridge was available: %+v", authErr.Attempts)
		}
	})
}

// A cached broker token must satisfy a broker-only policy. If it does not, the
// cache appears to work while never being read -- a silent bug, not a loud one.
func TestCachedWSLTokenSatisfiesBrokerOnlyPolicy(t *testing.T) {
	if !sourceAllowed(PolicyWAMOnly, sourceWSLBroker) {
		t.Error("a wsl-broker token must satisfy wam-only; it is the same credential")
	}
	if !sourceAllowed(PolicyWAMFirst, sourceWSLBroker) {
		t.Error("a wsl-broker token must satisfy wam-first")
	}
	if sourceAllowed(PolicyAzureCLIOnly, sourceWSLBroker) {
		t.Error("a wsl-broker token must NOT satisfy azure-cli-only; the policy names a source")
	}
}

// TestWSLBrokerAgainstTheRealProxy is the integration check.
//
// Everything above uses a fake and therefore proves only that this package is
// self-consistent. The request shape is a WIRE CONTRACT with a Microsoft binary
// that no test here can see, and a fake will happily agree with a shape the real
// broker rejects -- which is precisely how the four earlier arrangements looked
// correct right up until they returned "Invalid requestJson". This is the test
// that can actually be wrong in the useful direction.
//
// It is env-gated because it needs a real WSL distro, a real Windows host, and
// a real signed-in account. Absent those it SKIPS, and a skip is visible in test
// output rather than a green tick.
//
//	MSAUTH_WSL_INTEGRATION=1 go test -run TestWSLBrokerAgainstTheRealProxy -v .
func TestWSLBrokerAgainstTheRealProxy(t *testing.T) {
	if os.Getenv("MSAUTH_WSL_INTEGRATION") == "" {
		t.Skip("set MSAUTH_WSL_INTEGRATION=1 to acquire a real token through the Windows broker")
	}
	env := defaultWSLEnvironment()
	if !env.runningUnderWSL() {
		t.Skip("not running under WSL")
	}

	scope := os.Getenv("MSAUTH_WSL_INTEGRATION_SCOPE")
	if scope == "" {
		scope = "https://help.kusto.windows.net/.default"
	}
	tenant := os.Getenv("MSAUTH_WSL_INTEGRATION_TENANT")
	if tenant == "" {
		tenant = testTenant
	}

	p := &Provider{ClientID: "04b07795-8ddb-461a-bbee-02f9e1bf7b46", TenantID: tenant}
	p.defaults()
	p.goos = "linux"

	token, err := p.acquireWSLBroker(context.Background(), scope)
	if err != nil {
		t.Fatalf("acquiring %s through the Windows broker: %v", scope, err)
	}

	// Assert on shape and lifetime, never on token material.
	if parts := strings.Split(token.AccessToken, "."); len(parts) != 3 {
		t.Fatalf("the credential is not a JWT: %d segments", len(parts))
	}
	if token.Source != sourceWSLBroker {
		t.Errorf("source = %q, want %q", token.Source, sourceWSLBroker)
	}
	remaining := time.Until(token.ExpiresAt)
	if remaining <= 0 {
		t.Fatalf("the token is already expired (%s); the expiry unit is wrong", token.ExpiresAt)
	}
	if remaining > 48*time.Hour {
		t.Fatalf("expiry %s is implausibly far out; the unit is probably wrong", token.ExpiresAt)
	}
	t.Logf("acquired %d-character token for %s, valid %s, expiring %s",
		len(token.AccessToken), scope, remaining.Round(time.Second), token.ExpiresAt.Format(time.RFC3339))
}

// TestProxyErrorIsNotAnEmptyAccountList pins the class of bug where a broken
// instrument reports an empty world.
//
// The proxy signals method failure as a top-level `{"error":{...}}` and exits 0.
// The getAccounts decoder is shaped for the happy path and accepts that payload
// silently -- no matching keys, no error, a zero-length slice. Measured on
// 2026-09-22 the real answer was "aad WAM FindAllAccountsAsync failed with
// status: 3" and msauth reported "the Windows broker holds no accounts; sign in
// on the Windows host first": wrong, unfollowable, and pointing away from the
// fault. An error must never arrive as an absence.
func TestProxyErrorIsNotAnEmptyAccountList(t *testing.T) {
	const proxyError = `{"error":{"context":"aad WAM FindAllAccountsAsync failed with status: 3, errorMsg: (pii) ","errorCode":3400335369,"status":0,"subStatus":0,"tag":576582538}}`
	env := wslEnvironment{
		goos: "linux",
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte(proxyError), nil
		},
	}

	accounts, authErr := env.wslGetAccounts(context.Background(), "proxy.exe", "client", "https://login.microsoftonline.com/tenant")
	if authErr == nil {
		t.Fatalf("a proxy error decoded as success with %d accounts", len(accounts))
	}
	if authErr.Code != CodeWSLBrokerFailed {
		t.Fatalf("code=%q want %q", authErr.Code, CodeWSLBrokerFailed)
	}
	// The operator needs the broker's own words to have anything to act on.
	if !strings.Contains(authErr.Message, "FindAllAccountsAsync") {
		t.Fatalf("the broker's own diagnosis was dropped: %q", authErr.Message)
	}
	if !strings.Contains(authErr.Message, "getAccounts") {
		t.Fatalf("the failing method is not named: %q", authErr.Message)
	}
}

// TestProxySuccessStillDecodes guards the other direction: the new check must
// not reject a normal response that happens to have no error field.
func TestProxySuccessStillDecodes(t *testing.T) {
	const ok = `{"accounts":[{"homeAccountId":"oid.tid","username":"a@b.com","realm":"tid","environment":"login.microsoftonline.com"}]}`
	env := wslEnvironment{
		goos: "linux",
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte(ok), nil
		},
	}

	accounts, authErr := env.wslGetAccounts(context.Background(), "proxy.exe", "client", "https://login.microsoftonline.com/tid")
	if authErr != nil {
		t.Fatalf("a healthy response was rejected: %v", authErr)
	}
	if len(accounts) != 1 || accounts[0].Username != "a@b.com" {
		t.Fatalf("accounts=%+v", accounts)
	}
}

// TestPartialFailureKeepsThePayload is the other half of
// TestProxyErrorIsNotAnEmptyAccountList, and it exists because the first draft
// of that fix broke a WORKING machine.
//
// A healthy response on a corp-joined box carries seven usable AAD accounts AND
// an MSA enumeration error, because the signed-in identity has no consumer half
// (0x80070005, ACCESS_DENIED). Treating any error as fatal turned a repaired
// broker straight back into a hard failure. An error beside a payload is a
// warning; only an error that is the WHOLE response is a failure.
func TestPartialFailureKeepsThePayload(t *testing.T) {
	const partial = `{"accounts":[{"homeAccountId":"oid.tid","username":"a@b.com","realm":"tid","environment":"login.microsoftonline.com"}],"error":{"context":"msa WAM FindAllAccountsAsync failed with status: 1","errorCode":2147942405,"status":6,"subStatus":0,"tag":539075027}}`
	env := wslEnvironment{
		goos: "linux",
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte(partial), nil
		},
	}

	accounts, authErr := env.wslGetAccounts(context.Background(), "proxy.exe", "client", "https://login.microsoftonline.com/tid")
	if authErr != nil {
		t.Fatalf("a partial failure must not discard a usable payload: %v", authErr)
	}
	if len(accounts) != 1 || accounts[0].Username != "a@b.com" {
		t.Fatalf("accounts=%+v", accounts)
	}
}
