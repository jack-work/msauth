//go:build windows

package msauth

import (
	"bytes"
	"context"
	"os"
	"os/exec"
)

// diagnoseBroker probes every candidate host, selects a module with the same
// rule the acquisition path uses, and then proves the selection by loading it.
// Nothing here authenticates.
func diagnoseBroker(ctx context.Context) BrokerDiagnostics {
	diagnostics := BrokerDiagnostics{Supported: true, Overrides: brokerOverrides()}
	for _, name := range candidateHosts() {
		report := BrokerHostReport{Name: name}
		resolved, err := exec.LookPath(name)
		if err != nil {
			report.Error = "not found on PATH"
			diagnostics.Hosts = append(diagnostics.Hosts, report)
			continue
		}
		report.Path = resolved
		inventory, probeErr := probeBrokerHost(ctx, resolved)
		if probeErr != nil {
			report.Error = probeErr.Message
			diagnostics.Hosts = append(diagnostics.Hosts, report)
			continue
		}
		report.Version = inventory.HostVersion
		report.Modules = inventory.Modules
		diagnostics.Hosts = append(diagnostics.Hosts, report)
	}

	selection, err := resolveBroker(ctx)
	if err != nil {
		diagnostics.Error = err
		return diagnostics
	}
	module := selection.Module
	diagnostics.Selected = &module
	diagnostics.SelectedHost = selection.Host
	diagnostics.LoadCheck = brokerLoadCheck(ctx, selection)
	return diagnostics
}

// brokerLoadCheck runs the real acquisition script in load-only mode. It builds
// the broker-enabled application and stops before AcquireTokenSilent, so it
// exercises exactly the assembly load that failed on 2026-07-30 without
// touching an account, a cache, or the network.
func brokerLoadCheck(ctx context.Context, selection *brokerSelection) *BrokerLoadCheck {
	check := &BrokerLoadCheck{Attempted: true, Directory: selection.Module.Directory}
	cmd := exec.CommandContext(ctx, selection.Host, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", wamScript)
	cmd.Env = append(os.Environ(),
		"MSAUTH_BROKER_CLIENT_ID="+OfficeClientID,
		"MSAUTH_BROKER_TENANT_ID="+MicrosoftTenantID,
		"MSAUTH_BROKER_SCOPE=https://graph.microsoft.com/.default",
		"MSAUTH_BROKER_DIR="+selection.Module.Directory,
		"MSAUTH_BROKER_LOAD_ONLY=1",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		check.Error = sanitizeDiagnostic(err.Error() + ": " + stderr.String())
		return check
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"loaded"`)) {
		check.Error = "load check did not report success: " + sanitizeDiagnostic(stdout.String())
		return check
	}
	check.OK = true
	return check
}
