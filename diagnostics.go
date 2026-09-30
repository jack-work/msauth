package msauth

import (
	"context"
	"os"
	"runtime"
	"time"
)

// Diagnostics is a read-only report of everything needed to explain an
// authentication failure without authenticating: which msauth answered, which
// PowerShell host and Az.Accounts the broker would use, whether that assembly
// set actually loads, and whether the token cache is warm.
//
// It contains no credential material. Cache entries are reported by path and
// modification time only; the protected contents are never opened.
type Diagnostics struct {
	Version         string             `json:"version"`
	ProtocolVersion int                `json:"protocolVersion"`
	Operations      []string           `json:"operations"`
	OS              string             `json:"os"`
	CacheDirectory  string             `json:"cacheDirectory"`
	Config          ConfigReport       `json:"config"`
	CacheEntries    []CacheEntryReport `json:"cacheEntries"`
	Broker          BrokerDiagnostics  `json:"broker"`
	Healthy         bool               `json:"healthy"`
}

// CacheEntryReport describes one protected cache file's existence and age. A
// warm cache is why a broken broker can stay invisible for a day, so a
// diagnostic that omits it invites the wrong conclusion.
type CacheEntryReport struct {
	Client   string    `json:"client"`
	Path     string    `json:"path"`
	Exists   bool      `json:"exists"`
	Bytes    int64     `json:"bytes,omitempty"`
	Modified time.Time `json:"modified,omitempty"`
}

// BrokerDiagnostics reports the Windows broker environment.
type BrokerDiagnostics struct {
	Supported    bool               `json:"supported"`
	Hosts        []BrokerHostReport `json:"hosts,omitempty"`
	Selected     *BrokerModule      `json:"selected,omitempty"`
	SelectedHost string             `json:"selectedHost,omitempty"`
	LoadCheck    *BrokerLoadCheck   `json:"loadCheck,omitempty"`
	Error        *AuthError         `json:"error,omitempty"`
	Overrides    map[string]string  `json:"overrides,omitempty"`
}

// BrokerHostReport is one PowerShell host and what it can see.
type BrokerHostReport struct {
	Name    string         `json:"name"`
	Path    string         `json:"path,omitempty"`
	Version string         `json:"version,omitempty"`
	Modules []BrokerModule `json:"modules,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// BrokerLoadCheck records whether the selected assembly set actually loads.
// The check stops after the broker extension binds and never requests a token,
// so it proves the environment without authenticating.
type BrokerLoadCheck struct {
	Attempted bool   `json:"attempted"`
	OK        bool   `json:"ok"`
	Directory string `json:"directory,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Diagnose builds the report. It never authenticates and never fails.
func Diagnose(ctx context.Context) Diagnostics {
	diagnostics := Diagnostics{
		Version:         Version(),
		ProtocolVersion: ProtocolVersion,
		Operations:      Operations(),
		OS:              runtime.GOOS,
		CacheDirectory:  configDir(),
		Config:          DescribeConfig(),
		CacheEntries:    cacheReports(),
	}
	diagnostics.Broker = diagnoseBroker(ctx)
	switch {
	case !diagnostics.Broker.Supported:
		// No broker is expected off Windows; that is not ill health.
		diagnostics.Healthy = true
	case diagnostics.Broker.Error != nil:
		diagnostics.Healthy = false
	case diagnostics.Broker.LoadCheck != nil && !diagnostics.Broker.LoadCheck.OK:
		diagnostics.Healthy = false
	default:
		diagnostics.Healthy = true
	}
	return diagnostics
}

func cacheReports() []CacheEntryReport {
	config := effectiveConfig()
	clients := config.ClientList()
	reports := make([]CacheEntryReport, 0, len(clients))
	for _, client := range clients {
		if !client.Broker {
			continue
		}
		provider := &Provider{ClientID: client.ID, TenantID: config.TenantID}
		path := provider.cachePath("")
		report := CacheEntryReport{Client: client.Name, Path: path}
		if info, err := os.Stat(path); err == nil {
			report.Exists = true
			report.Bytes = info.Size()
			report.Modified = info.ModTime()
		} else if size, ok := protectedSize(path); ok {
			// Not every platform keeps this cache in a file: Linux seals it into
			// the Secret Service, where there is no path to stat and no
			// modification time to report.
			report.Exists = true
			report.Bytes = size
		}
		reports = append(reports, report)
	}
	return reports
}

func brokerOverrides() map[string]string {
	overrides := map[string]string{}
	for _, name := range []string{EnvPowerShell, EnvBrokerModule} {
		if value := os.Getenv(name); value != "" {
			overrides[name] = value
		}
	}
	if len(overrides) == 0 {
		return nil
	}
	return overrides
}
