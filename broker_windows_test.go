//go:build windows

package msauth

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// These tests probe the real machine. They authenticate nothing, request no
// token, and touch no network: they read assembly metadata and, at most, load
// the broker assemblies and stop before AcquireTokenSilent.
//
// They exist because the 2026-07-30 outage was invisible to every mocked test
// in the fleet. The protocol was healthy; the machine was not.

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestInstalledBrokerAssemblySetIsUsable is the highest-value test here: it
// turns a defect that took 24 hours to surface, as a total outage, into an
// immediate failure.
func TestInstalledBrokerAssemblySetIsUsable(t *testing.T) {
	host, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("powershell.exe is not on PATH")
	}
	inventory, probeErr := probeBrokerHost(testContext(t), host)
	if probeErr != nil {
		t.Fatalf("broker inventory failed: %s", probeErr.Message)
	}
	if len(inventory.Modules) == 0 {
		t.Skip("no Az.Accounts installation is present to validate")
	}
	for _, module := range inventory.Modules {
		t.Logf("Az.Accounts %-8s %-12s %s %s", module.Version, module.Verdict, module.Directory, module.Reason)
	}
	module, selectErr := selectBrokerModule(inventory)
	if selectErr != nil {
		t.Fatalf("no usable Az.Accounts broker assembly set: [%s] %s", selectErr.Code, selectErr.Message)
	}
	t.Logf("selected Az.Accounts %s (%s) at %s", module.Version, module.Verdict, module.Directory)
}

// TestBrokerAssembliesActuallyLoad runs the real acquisition script in
// load-only mode. Metadata agreement is necessary but not sufficient; this
// proves the loader agrees.
func TestBrokerAssembliesActuallyLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("load check starts a PowerShell host")
	}
	selection, err := resolveBroker(testContext(t))
	if err != nil {
		if err.Code == CodeBrokerUnavailable && strings.Contains(err.Message, "no Az.Accounts") {
			t.Skip("no Az.Accounts installation is present to validate")
		}
		t.Fatalf("broker resolution failed: [%s] %s", err.Code, err.Message)
	}
	check := brokerLoadCheck(testContext(t), selection)
	if !check.OK {
		t.Fatalf("broker assemblies did not load from %s: %s", check.Directory, check.Error)
	}
}

// A module that a host can see but cannot load must never be selected, no
// matter how the hosts disagree. This asserts the whole-machine invariant
// rather than one host's view.
func TestNoHostOffersOnlyInconsistentModules(t *testing.T) {
	ctx := testContext(t)
	var probed int
	for _, name := range candidateHosts() {
		host, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		inventory, probeErr := probeBrokerHost(ctx, host)
		if probeErr != nil {
			t.Logf("%s: %s", name, probeErr.Message)
			continue
		}
		probed++
		if len(inventory.Modules) == 0 {
			continue
		}
		if _, selectErr := selectBrokerModule(inventory); selectErr != nil {
			t.Errorf("%s (PowerShell %s) can see Az.Accounts but none is loadable: [%s] %s",
				name, inventory.HostVersion, selectErr.Code, selectErr.Message)
		}
	}
	if probed == 0 {
		t.Skip("no PowerShell host could be probed")
	}
}

// Diagnose must stay safe to run and safe to paste into a bug report.
func TestDiagnoseIsSafeAndSelfConsistent(t *testing.T) {
	if testing.Short() {
		t.Skip("diagnose starts a PowerShell host")
	}
	diagnostics := Diagnose(testContext(t))
	if diagnostics.ProtocolVersion != ProtocolVersion {
		t.Errorf("protocol version = %d, want %d", diagnostics.ProtocolVersion, ProtocolVersion)
	}
	if !diagnostics.Broker.Supported {
		t.Fatal("the broker must be reported as supported on Windows")
	}
	if diagnostics.Broker.Error == nil && diagnostics.Broker.Selected == nil {
		t.Error("a broker report with no error must name the selected module")
	}
	document, err := json.Marshal(diagnostics)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// A diagnostic is pasted into bug reports and kreg records. It must never
	// carry credential material, so assert on the serialized form rather than
	// trusting that no field was added later.
	for _, forbidden := range []string{"accessToken", "access_token", "Bearer ", "eyJ0eXAi"} {
		if strings.Contains(string(document), forbidden) {
			t.Errorf("diagnostics contain %q", forbidden)
		}
	}
}

// On a host that cannot read assembly references, every candidate is merely
// unverified, and selecting the newest is a guess. These tests pin the
// fallback: prove the guess by loading it, and move on when it fails.

func unverified(version, directory string) BrokerModule {
	module := azAccounts530()
	module.Version = version
	module.Directory = directory
	module.Required = nil
	module.RequiredError = "ReflectionOnly loading is not supported on this platform."
	return module
}

func TestSelectVerifiedModuleProvesAnUnverifiedGuess(t *testing.T) {
	original := verifyBrokerModule
	t.Cleanup(func() { verifyBrokerModule = original })

	var probed []string
	// The newest candidate is the one that does not load. Metadata order alone
	// would pick it, which is exactly the mistake the probe exists to catch.
	verifyBrokerModule = func(_ context.Context, _ string, module BrokerModule) error {
		probed = append(probed, module.Version)
		if module.Version == "9.9.9" {
			return errors.New("ReflectionTypeLoadException: NativeInterop 0.16.1.0 not found")
		}
		return nil
	}

	inventory := BrokerInventory{Modules: []BrokerModule{
		unverified("5.2.0", `C:\good\lib
etstandard2.0`),
		unverified("9.9.9", `C:roken\lib
etstandard2.0`),
	}}

	selection, err := selectVerifiedModule(context.Background(), "powershell.exe", inventory)
	if err != nil {
		t.Fatalf("selection failed: [%s] %s", err.Code, err.Message)
	}
	if selection.Module.Version != "5.2.0" {
		t.Fatalf("selected %s, want the candidate that actually loads", selection.Module.Version)
	}
	if len(probed) != 2 || probed[0] != "9.9.9" {
		t.Fatalf("probe order = %v, want the newest first then the fallback", probed)
	}
	if selection.Module.Reason != "verified by load probe" {
		t.Errorf("reason = %q, want the load-probe provenance", selection.Module.Reason)
	}
}

func TestSelectVerifiedModuleSkipsTheProbeWhenMetadataDecides(t *testing.T) {
	original := verifyBrokerModule
	t.Cleanup(func() { verifyBrokerModule = original })
	verifyBrokerModule = func(context.Context, string, BrokerModule) error {
		t.Fatal("a metadata-verified module must not cost a load probe")
		return nil
	}
	inventory := BrokerInventory{Modules: []BrokerModule{azAccounts304(), azAccounts530()}}
	selection, err := selectVerifiedModule(context.Background(), "powershell.exe", inventory)
	if err != nil {
		t.Fatalf("selection failed: [%s] %s", err.Code, err.Message)
	}
	if selection.Module.Version != "5.3.0" {
		t.Fatalf("selected %s, want 5.3.0", selection.Module.Version)
	}
}

func TestSelectVerifiedModuleReportsEveryLoadFailure(t *testing.T) {
	original := verifyBrokerModule
	t.Cleanup(func() { verifyBrokerModule = original })
	verifyBrokerModule = func(context.Context, string, BrokerModule) error {
		return errors.New("ReflectionTypeLoadException")
	}
	inventory := BrokerInventory{Modules: []BrokerModule{unverified("5.3.0", `C:\lib
etstandard2.0`)}}
	_, err := selectVerifiedModule(context.Background(), "powershell.exe", inventory)
	if err == nil {
		t.Fatal("a candidate that does not load must not be selected")
	}
	if err.Code != CodeBrokerAssemblyMismatch {
		t.Fatalf("code = %q, want %q", err.Code, CodeBrokerAssemblyMismatch)
	}
	for _, want := range []string{"did not load", "5.3.0", "Install-Module Az.Accounts"} {
		if !strings.Contains(err.Message, want) {
			t.Errorf("message %q does not contain %q", err.Message, want)
		}
	}
}
