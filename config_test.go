package msauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Every test here is pure: it writes only to t.TempDir, sets only this
// package's own environment variables, and never authenticates or touches the
// real cache. Configuration resolution is the layer that decides WHICH tenant
// and WHICH application a token is requested for, so it must be provable
// without a network and without an identity.

func withConfigEnv(t *testing.T, file, tenant, client string) {
	t.Helper()
	t.Setenv(EnvConfigFile, file)
	t.Setenv(EnvTenant, tenant)
	t.Setenv(EnvClient, client)
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// A machine with no config file and no overrides must resolve exactly what
// this package shipped with. Without this, adding configuration would be a
// silent behavior change for every existing client.
func TestNoConfigurationResolvesTheBuiltInDefaults(t *testing.T) {
	withConfigEnv(t, filepath.Join(t.TempDir(), "absent.json"), "", "")

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if config.TenantID != MicrosoftTenantID {
		t.Errorf("tenant = %q, want the built-in default", config.TenantID)
	}
	if config.DefaultClient != DefaultClientName {
		t.Errorf("default client = %q, want %q", config.DefaultClient, DefaultClientName)
	}
	if got := strings.Join(config.ClientNames(), ","); got != "office,teams,azure-cli" {
		t.Errorf("clients = %q, want the three built-ins in order", got)
	}
}

// The precedence chain is the whole contract. Assert every rung in one test so
// a reordering cannot pass by satisfying the rungs individually.
func TestPrecedenceRunsDefaultsThenFileThenEnvironmentThenArgument(t *testing.T) {
	path := writeConfig(t, `{"tenant":"file-tenant","defaultClient":"teams"}`)

	withConfigEnv(t, path, "", "")
	fileOnly, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig with file: %v", err)
	}
	if fileOnly.TenantID != "file-tenant" || fileOnly.DefaultClient != "teams" {
		t.Fatalf("file layer ignored: %+v", fileOnly)
	}

	withConfigEnv(t, path, "env-tenant", "azure-cli")
	withEnv, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig with environment: %v", err)
	}
	if withEnv.TenantID != "env-tenant" {
		t.Errorf("tenant = %q, want the environment to beat the file", withEnv.TenantID)
	}
	if withEnv.DefaultClient != "azure-cli" {
		t.Errorf("default client = %q, want the environment to beat the file", withEnv.DefaultClient)
	}

	provider, err := withEnv.NewProvider("office")
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if provider.ClientID != OfficeClientID {
		t.Errorf("client id = %q, want the explicitly named client to beat the configured default", provider.ClientID)
	}
	if provider.TenantID != "env-tenant" {
		t.Errorf("tenant = %q, want the resolved tenant", provider.TenantID)
	}
}

// A provider built from configuration must carry the configured tenant, not
// the compile-time constant. This is the defect that made a shared foundation
// look Microsoft-internal and unusable in another tenant.
func TestProviderUsesTheConfiguredTenantRatherThanTheConstant(t *testing.T) {
	withConfigEnv(t, filepath.Join(t.TempDir(), "absent.json"), "contoso-tenant", "")

	provider, err := NewForClient("teams")
	if err != nil {
		t.Fatalf("NewForClient: %v", err)
	}
	if provider.TenantID != "contoso-tenant" {
		t.Errorf("tenant = %q, want the configured tenant", provider.TenantID)
	}
	if provider.TenantID == MicrosoftTenantID {
		t.Error("the provider fell back to the compile-time tenant constant")
	}
}

// An empty client name is the Go API's way of saying "whatever this host is
// configured for". The wire protocol deliberately does not allow it; that
// asymmetry is asserted in TestProtocolStillRequiresAnExplicitClient.
func TestEmptyClientNameSelectsTheConfiguredDefault(t *testing.T) {
	withConfigEnv(t, filepath.Join(t.TempDir(), "absent.json"), "", "azure-cli")

	provider, err := NewForClient("")
	if err != nil {
		t.Fatalf("NewForClient: %v", err)
	}
	if provider.ClientID != AzureCLIClientID {
		t.Errorf("client id = %q, want the configured default client", provider.ClientID)
	}
	if provider.defaultPolicy != PolicyAzureCLIOnly {
		t.Errorf("policy = %q, want a non-broker client to default to azure-cli-only", provider.defaultPolicy)
	}
}

func TestProtocolStillRequiresAnExplicitClient(t *testing.T) {
	withConfigEnv(t, filepath.Join(t.TempDir(), "absent.json"), "", "")

	response := ExecuteProtocol(t.Context(), ProtocolRequest{
		Version:   ProtocolVersion,
		Operation: OperationAcquireToken,
		Audience:  "https://graph.microsoft.com",
	})
	if response.OK || response.Error == nil {
		t.Fatalf("an acquireToken request with no client must be rejected: %+v", response)
	}
	if response.Error.Code != CodeInvalidRequest {
		t.Errorf("code = %q, want %q", response.Error.Code, CodeInvalidRequest)
	}
	// The rejection must name the default rather than merely refusing, or a
	// caller cannot tell what to send instead.
	if !strings.Contains(response.Error.Message, DefaultClientName) {
		t.Errorf("message %q does not name the configured default client", response.Error.Message)
	}
}

// A bare application GUID must work with no configuration at all. This is what
// lets a contributor use their own registration without editing the shared
// foundation, which is the alternative that produced forks.
func TestBareApplicationIDResolvesWithoutConfiguration(t *testing.T) {
	withConfigEnv(t, filepath.Join(t.TempDir(), "absent.json"), "", "")

	const appID = "11111111-2222-3333-4444-555555555555"
	provider, err := NewForClient(appID)
	if err != nil {
		t.Fatalf("NewForClient: %v", err)
	}
	if provider.ClientID != appID {
		t.Errorf("client id = %q, want the supplied application id", provider.ClientID)
	}
	if provider.defaultPolicy != PolicyWAMFirst {
		t.Errorf("policy = %q, want wam-first for an ad-hoc broker client", provider.defaultPolicy)
	}
}

func TestUnknownClientNamesTheConfiguredAlternatives(t *testing.T) {
	withConfigEnv(t, filepath.Join(t.TempDir(), "absent.json"), "", "")

	_, err := NewForClient("not-a-client")
	if err == nil {
		t.Fatal("an unknown client must be rejected")
	}
	message := err.Error()
	for _, want := range []string{"not-a-client", "office", "teams", "azure-cli"} {
		if !strings.Contains(message, want) {
			t.Errorf("message %q does not mention %q", message, want)
		}
	}
}

// A config file may replace a built-in client in place, which is how a caller
// points an existing tool at their own registration without renaming it.
func TestConfigFileReplacesABuiltInClientAndAppendsNewOnes(t *testing.T) {
	path := writeConfig(t, `{"clients":[
	  {"name":"office","id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","broker":true},
	  {"name":"internal","id":"99999999-8888-7777-6666-555555555555","broker":false}
	]}`)
	withConfigEnv(t, path, "", "")

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := strings.Join(config.ClientNames(), ","); got != "office,teams,azure-cli,internal" {
		t.Fatalf("clients = %q, want office replaced in place and internal appended", got)
	}
	office, _ := config.LookupClient("office")
	if office.ID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Errorf("office id = %q, want the configured override", office.ID)
	}
	internal, _ := config.LookupClient("internal")
	if internal.DefaultPolicy != PolicyAzureCLIOnly {
		t.Errorf("policy = %q, want a non-broker client to derive azure-cli-only", internal.DefaultPolicy)
	}
}

// Failing loudly is the point: a config file that cannot be understood must
// never degrade into "authenticate with the defaults", because the defaults are
// a different tenant and a different application than the file asked for.
func TestMalformedConfigurationFailsRatherThanFallingBack(t *testing.T) {
	for name, body := range map[string]string{
		"not json":        `{`,
		"unknown field":   `{"tenantId":"x"}`,
		"nameless client": `{"clients":[{"name":"","id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}`,
		"unknown policy":  `{"clients":[{"name":"office","id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","defaultPolicy":"trust-me"}]}`,
		"missing id":      `{"clients":[{"name":"nameless","id":""}]}`,
		"absent default":  `{"defaultClient":"nobody"}`,
	} {
		t.Run(name, func(t *testing.T) {
			withConfigEnv(t, writeConfig(t, body), "", "")
			if _, err := LoadConfig(); err == nil {
				t.Fatal("a malformed configuration must be an error")
			}
			// A caller that cannot resolve configuration must not be handed a
			// provider built from the defaults it did not ask for.
			if _, err := NewForClient("office"); err == nil {
				t.Fatal("NewForClient must fail when configuration cannot be resolved")
			}
		})
	}
}

// The diagnostic path must never fail, because it exists to explain a failure.
func TestDescribeConfigReportsAFaultInsteadOfFailing(t *testing.T) {
	path := writeConfig(t, `{`)
	withConfigEnv(t, path, "", "")

	report := DescribeConfig()
	if report.Path != path || !report.Exists {
		t.Errorf("report does not identify the file it read: %+v", report)
	}
	if report.Error == "" {
		t.Error("a broken config file must be reported")
	}
	if report.TenantID == "" || report.DefaultClient == "" {
		t.Errorf("a broken config must still report what would be used: %+v", report)
	}
}

// Capabilities is the only non-authenticating way a non-Go client can see what
// tenant and client a msauth build resolved. A report that quoted the compiled
// constants would be worse than no report at all.
func TestCapabilitiesReportResolvedConfigurationNotConstants(t *testing.T) {
	path := writeConfig(t, `{"tenant":"reported-tenant","defaultClient":"teams"}`)
	withConfigEnv(t, path, "", "")

	capabilities := Describe()
	if capabilities.Tenant != "reported-tenant" {
		t.Errorf("tenant = %q, want the resolved tenant", capabilities.Tenant)
	}
	if capabilities.DefaultClient != "teams" {
		t.Errorf("default client = %q, want the resolved default", capabilities.DefaultClient)
	}
	if capabilities.ConfigPath != path {
		t.Errorf("config path = %q, want %q", capabilities.ConfigPath, path)
	}
}

// Two tenants must not share a cache file. The cache key already includes the
// tenant, but nothing asserted it, and configuration is what makes a second
// tenant reachable in the first place.
func TestConfiguredTenantsGetSeparateCacheFiles(t *testing.T) {
	first := &Provider{ClientID: OfficeClientID, TenantID: "tenant-one"}
	second := &Provider{ClientID: OfficeClientID, TenantID: "tenant-two"}
	if first.cachePath("") == second.cachePath("") {
		t.Fatal("two tenants share one cache file; one tenant's token could be served to the other")
	}
}

// The configuration variables must not collide with the private broker channel.
// MSAUTH_CLIENT (configuration) and MSAUTH_BROKER_CLIENT_ID (an implementation
// detail passed to PowerShell) were one prefix apart, and an operator who set
// the wrong one would have been silently ignored.
func TestConfigurationEnvironmentIsDisjointFromTheBrokerChannel(t *testing.T) {
	configuration := []string{EnvTenant, EnvClient, EnvConfigFile}
	broker := []string{"MSAUTH_BROKER_CLIENT_ID", "MSAUTH_BROKER_TENANT_ID", "MSAUTH_BROKER_SCOPE", EnvBrokerModule, EnvPowerShell}
	for _, c := range configuration {
		for _, b := range broker {
			if c == b {
				t.Errorf("%q is both a configuration and a broker variable", c)
			}
			if strings.HasPrefix(b, c+"_") {
				t.Errorf("broker variable %q is a prefix extension of configuration variable %q, which invites the wrong one being set", b, c)
			}
		}
	}
	// The last two assertions read wamScript, which is the real PowerShell only
	// on Windows -- wam_other.go defines it as "" so the package builds
	// elsewhere. On Linux they therefore failed for every developer on every
	// run, which is exactly the permanently-red gate .msauth-floor warns about:
	// one people learn to ignore, and behind which a real regression can hide.
	// Verified as pre-existing on a clean clone of 3490dee before the WSL branch
	// existed. Skipping is honest and stays visible in test output; deleting the
	// checks would lose them on the one platform where they mean something.
	if runtime.GOOS != "windows" {
		t.Skip("wamScript is the stub off Windows; the rename assertions below can only be checked there")
	}
	if !strings.Contains(wamScript, "MSAUTH_BROKER_CLIENT_ID") {
		t.Error("the broker script does not read the renamed variable; the rename is incomplete")
	}
	if strings.Contains(wamScript, "$env:MSAUTH_CLIENT_ID") {
		t.Error("the broker script still reads the old variable name")
	}
}

// The fleet list is the foundation author's half of delivery: after committing,
// one command must name every installed artifact the commit obliges a rebuild
// of. It lives in configuration because the paths are machine-specific and
// several client repositories are public.

func TestFleetReplacesRatherThanAccumulates(t *testing.T) {
	base := Config{TenantID: "t", DefaultClient: "office", Fleet: []string{"old.exe", "gone.exe"}}
	merged := base.merge(Config{Fleet: []string{"new.exe"}})
	if len(merged.Fleet) != 1 || merged.Fleet[0] != "new.exe" {
		t.Fatalf("fleet = %v, want the override to replace: a decommissioned path must be removable", merged.Fleet)
	}
	kept := base.merge(Config{TenantID: "other"})
	if len(kept.Fleet) != 2 {
		t.Fatalf("fleet = %v, want the lower layer kept when the override names none", kept.Fleet)
	}
}

func TestConfigReportCountsTheFleetWithoutDisclosingPaths(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "auth.json")
	body := `{"fleet":["C:/Users/someone/bin/tomb.exe","C:/Users/someone/go/bin/jacques.exe"]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(EnvConfigFile, path)

	report := DescribeConfig()
	if report.Fleet != 2 {
		t.Fatalf("Fleet = %d, want 2", report.Fleet)
	}
	rendered, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// A diagnostic report is the thing most likely to be pasted somewhere public.
	if strings.Contains(string(rendered), "someone") || strings.Contains(string(rendered), "tomb.exe") {
		t.Fatalf("the config report discloses install paths: %s", rendered)
	}
}
