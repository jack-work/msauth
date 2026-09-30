package msauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Tenant and client selection is configuration, not code. The identifiers this
// package ships with are publicly documented and carry no credential -- a
// public client proves nothing by quoting its own ID -- but they are still
// choices, and a caller in a different tenant, or one who registered their own
// application, must be able to override them without editing this package or
// rebuilding every client that links it.
//
// Resolution order, lowest precedence first:
//
//  1. the built-in defaults below
//  2. the JSON config file reported by ConfigPath
//  3. the environment variables below
//  4. explicit arguments: a named client, ProtocolRequest.Tenant, Provider fields
//
// Every layer is optional. A machine with no config file and no environment
// overrides resolves exactly the configuration this package shipped with, so
// adding this layer changes no existing caller's behavior.
const (
	// MicrosoftTenantID is the default Entra tenant. It is not a secret; it
	// appears in public documentation and in every token issued for it.
	MicrosoftTenantID = "72f988bf-86f1-41af-91ab-2d7cd011db47"

	// Well-known public client applications, published by their vendors.
	OfficeClientID   = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
	TeamsClientID    = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
	AzureCLIClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

	// DefaultClientName is used when a caller does not name a client.
	DefaultClientName = "office"
)

// Configuration environment variables. These are deliberately distinct from
// the MSAUTH_BROKER_* variables, which are this package's private channel to
// the PowerShell broker script and are not a configuration surface.
const (
	EnvTenant     = "MSAUTH_TENANT"
	EnvClient     = "MSAUTH_CLIENT"
	EnvConfigFile = "MSAUTH_CONFIG"
)

// Config selects the tenant and the client applications this build may
// authenticate as. It is plain data, so a Go caller can build one directly, and
// it round-trips through the JSON config file.
type Config struct {
	// TenantID is the Entra tenant tokens are requested from.
	TenantID string `json:"tenant,omitempty"`
	// DefaultClient names the client used when a request does not choose one.
	DefaultClient string `json:"defaultClient,omitempty"`
	// Clients extends or replaces the built-in registry. An entry whose name
	// matches a built-in replaces it; any other entry is appended.
	Clients []Client `json:"clients,omitempty"`

	// Fleet lists the installed artifacts this machine expects to carry the
	// foundation, for "msauth audit --fleet". It is deliberately CONFIGURATION
	// rather than anything committed: the paths are machine-specific, several
	// clients have public remotes, and an install path in one of them leaks an
	// account name. It has no default, because a fleet list nobody wrote is a
	// list nobody maintains, and an empty audit must never read as a pass.
	Fleet []string `json:"fleet,omitempty"`
}

// DefaultConfig returns the built-in configuration as a fresh copy.
func DefaultConfig() Config {
	return Config{
		TenantID:      MicrosoftTenantID,
		DefaultClient: DefaultClientName,
		Clients: []Client{
			{
				Name:        "office",
				ID:          OfficeClientID,
				Broker:      true,
				Description: "Microsoft Office; Graph, SharePoint, and Substrate delegated access",
			},
			{
				Name:        "teams",
				ID:          TeamsClientID,
				Broker:      true,
				Description: "Microsoft Teams; Teams and IcM upstream flows",
			},
			{
				Name:        "azure-cli",
				ID:          AzureCLIClientID,
				Broker:      false,
				Description: "Use the current Azure CLI login (fallback scopes only)",
			},
		},
	}
}

// ConfigPath reports the JSON config file LoadConfig consults: MSAUTH_CONFIG
// when set, otherwise auth.json beside the protected token cache.
func ConfigPath() string {
	if custom := strings.TrimSpace(os.Getenv(EnvConfigFile)); custom != "" {
		return custom
	}
	return filepath.Join(configDir(), "auth.json")
}

// LoadConfig resolves the effective configuration. A missing config file is
// not an error, because the defaults are usable as shipped; a malformed one is,
// because silently authenticating as an unintended client or against an
// unintended tenant is worse than failing loudly.
func LoadConfig() (Config, error) {
	config := DefaultConfig()

	path := ConfigPath()
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var fileConfig Config
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.DisallowUnknownFields()
		if decodeErr := decoder.Decode(&fileConfig); decodeErr != nil {
			return Config{}, newRequestError("config file %s is not valid: %s", path, sanitizeDiagnostic(decodeErr.Error()))
		}
		config = config.merge(fileConfig)
	case os.IsNotExist(err):
		// The normal case.
	default:
		return Config{}, newRequestError("config file %s could not be read: %s", path, sanitizeDiagnostic(err.Error()))
	}

	if tenant := strings.TrimSpace(os.Getenv(EnvTenant)); tenant != "" {
		config.TenantID = tenant
	}
	if client := strings.TrimSpace(os.Getenv(EnvClient)); client != "" {
		config.DefaultClient = client
	}
	return config.normalized()
}

// merge overlays a higher-precedence configuration onto the receiver.
func (c Config) merge(override Config) Config {
	merged := Config{
		TenantID:      c.TenantID,
		DefaultClient: c.DefaultClient,
		Clients:       append([]Client(nil), c.Clients...),
		Fleet:         append([]string(nil), c.Fleet...),
	}
	if len(override.Fleet) > 0 {
		// A fleet list REPLACES rather than accumulates. Merging would make it
		// impossible to remove a decommissioned artifact from a lower layer, and
		// an audit that keeps judging a path nobody installs any more trains its
		// reader to ignore it.
		merged.Fleet = append([]string(nil), override.Fleet...)
	}
	if override.TenantID != "" {
		merged.TenantID = override.TenantID
	}
	if override.DefaultClient != "" {
		merged.DefaultClient = override.DefaultClient
	}
	for _, client := range override.Clients {
		replaced := false
		for i := range merged.Clients {
			if strings.EqualFold(merged.Clients[i].Name, client.Name) {
				merged.Clients[i] = client
				replaced = true
				break
			}
		}
		if !replaced {
			merged.Clients = append(merged.Clients, client)
		}
	}
	return merged
}

// normalized validates a configuration and fills in derived fields. A client
// that cannot use the broker must never silently attempt it, so an entry with
// no explicit policy derives one from Broker rather than inheriting wam-first.
func (c Config) normalized() (Config, error) {
	if strings.TrimSpace(c.TenantID) == "" {
		return Config{}, newRequestError("configuration has no tenant")
	}
	if len(c.Clients) == 0 {
		return Config{}, newRequestError("configuration has no clients")
	}
	c.Clients = append([]Client(nil), c.Clients...)
	for i := range c.Clients {
		if strings.TrimSpace(c.Clients[i].Name) == "" {
			return Config{}, newRequestError("configured client %d has no name", i)
		}
		if strings.TrimSpace(c.Clients[i].ID) == "" {
			return Config{}, newRequestError("configured client %q has no id", c.Clients[i].Name)
		}
		if c.Clients[i].DefaultPolicy == "" {
			if c.Clients[i].Broker {
				c.Clients[i].DefaultPolicy = PolicyWAMFirst
			} else {
				c.Clients[i].DefaultPolicy = PolicyAzureCLIOnly
			}
		}
		if !validPolicy(c.Clients[i].DefaultPolicy) {
			return Config{}, newRequestError("configured client %q has unknown policy %q", c.Clients[i].Name, c.Clients[i].DefaultPolicy)
		}
	}
	if strings.TrimSpace(c.DefaultClient) == "" {
		c.DefaultClient = c.Clients[0].Name
	}
	if _, ok := c.LookupClient(c.DefaultClient); !ok {
		return Config{}, newRequestError("default client %q is not configured", c.DefaultClient)
	}
	return c, nil
}

func validPolicy(policy Policy) bool {
	switch policy {
	case PolicyWAMFirst, PolicyWAMOnly, PolicyAzureCLIOnly:
		return true
	}
	return false
}

// NewProvider builds a provider for one configured client. An empty name
// selects the configured default client.
func (c Config) NewProvider(name string) (*Provider, error) {
	if strings.TrimSpace(name) == "" {
		name = c.DefaultClient
	}
	client, ok := c.LookupClient(name)
	if !ok {
		return nil, newRequestError("unknown client %q; this build is configured with %s",
			name, strings.Join(c.ClientNames(), ", "))
	}
	return &Provider{
		ClientID:      client.ID,
		TenantID:      c.TenantID,
		defaultPolicy: client.DefaultPolicy,
	}, nil
}

// ConfigReport describes the effective configuration without disclosing
// anything a token would not already reveal. It is safe to print.
type ConfigReport struct {
	Path          string `json:"path"`
	Exists        bool   `json:"exists"`
	TenantID      string `json:"tenant"`
	DefaultClient string `json:"defaultClient"`
	// Fleet is reported as a COUNT, not as paths. A diagnostic report is the
	// thing most likely to be pasted into an issue or a chat, and these paths
	// contain an account name.
	Fleet int    `json:"fleet"`
	Error string `json:"error,omitempty"`
}

// DescribeConfig reports where configuration came from and what it resolved to.
// It never fails: a broken config file is reported as a field, so a diagnostic
// can explain the fault instead of failing the way the caller already failed.
func DescribeConfig() ConfigReport {
	path := ConfigPath()
	report := ConfigReport{Path: path}
	if _, err := os.Stat(path); err == nil {
		report.Exists = true
	}
	config, err := LoadConfig()
	if err != nil {
		report.Error = sanitizeDiagnostic(err.Error())
		fallback := DefaultConfig()
		report.TenantID = fallback.TenantID
		report.DefaultClient = fallback.DefaultClient
		return report
	}
	report.TenantID = config.TenantID
	report.DefaultClient = config.DefaultClient
	report.Fleet = len(config.Fleet)
	return report
}

// effectiveConfig resolves configuration for reporting paths that must not
// fail. A broken config file falls back to the built-in defaults, which is
// honest because DescribeConfig reports the error alongside.
func effectiveConfig() Config {
	config, err := LoadConfig()
	if err != nil {
		return DefaultConfig()
	}
	return config
}
