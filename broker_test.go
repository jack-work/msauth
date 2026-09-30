package msauth

import (
	"encoding/json"
	"strings"
	"testing"
)

// The two fixtures below are the real assembly sets observed on 2026-07-30.
// azAccounts304 is the installation that caused a total IcM outage: its broker
// binds to a NativeInterop version it does not ship, so Add-Type throws
// ReflectionTypeLoadException. azAccounts530 is the installation that works.
func azAccounts304() BrokerModule {
	return BrokerModule{
		Version:    "3.0.4",
		ModuleBase: `C:\Program Files\WindowsPowerShell\Modules\Az.Accounts\3.0.4`,
		Directory:  `C:\Program Files\WindowsPowerShell\Modules\Az.Accounts\3.0.4\lib\netstandard2.0`,
		Shipped: map[string]string{
			assemblyBroker:        "4.61.3.0",
			assemblyMSAL:          "4.61.3.0",
			assemblyNativeInterop: "0.16.2.0",
			assemblyAbstractions:  "6.35.0.0",
		},
		Required: map[string]string{
			assemblyMSAL:          "4.61.3.0",
			assemblyNativeInterop: "0.16.1.0",
			assemblyAbstractions:  "6.35.0.0",
		},
	}
}

func azAccounts530() BrokerModule {
	return BrokerModule{
		Version:    "5.3.0",
		ModuleBase: `C:\Users\u\Documents\PowerShell\Modules\Az.Accounts\5.3.0`,
		Directory:  `C:\Users\u\Documents\PowerShell\Modules\Az.Accounts\5.3.0\lib\netstandard2.0`,
		Shipped: map[string]string{
			assemblyBroker:        "4.65.0.0",
			assemblyMSAL:          "4.65.0.0",
			assemblyNativeInterop: "0.16.2.0",
			assemblyAbstractions:  "6.35.0.0",
		},
		Required: map[string]string{
			assemblyMSAL:          "4.65.0.0",
			assemblyNativeInterop: "0.16.2.0",
			assemblyAbstractions:  "6.35.0.0",
		},
	}
}

func TestClassifyRejectsTheAssemblySetThatCausedTheOutage(t *testing.T) {
	module := classifyBrokerModule(azAccounts304())
	if module.Verdict != VerdictInconsistent {
		t.Fatalf("verdict = %q, want %q", module.Verdict, VerdictInconsistent)
	}
	for _, want := range []string{assemblyNativeInterop, "0.16.2.0", "0.16.1.0"} {
		if !strings.Contains(module.Reason, want) {
			t.Errorf("reason %q does not name %q", module.Reason, want)
		}
	}
}

func TestClassifyAcceptsAConsistentAssemblySet(t *testing.T) {
	module := classifyBrokerModule(azAccounts530())
	if module.Verdict != VerdictUsable {
		t.Fatalf("verdict = %q (%s), want %q", module.Verdict, module.Reason, VerdictUsable)
	}
	if module.Reason != "" {
		t.Errorf("a usable module needs no reason, got %q", module.Reason)
	}
}

func TestClassifyReportsMissingAssemblies(t *testing.T) {
	module := azAccounts530()
	delete(module.Shipped, assemblyNativeInterop)
	classified := classifyBrokerModule(module)
	if classified.Verdict != VerdictIncomplete {
		t.Fatalf("verdict = %q, want %q", classified.Verdict, VerdictIncomplete)
	}
	if !strings.Contains(classified.Reason, assemblyNativeInterop) {
		t.Errorf("reason %q does not name the missing assembly", classified.Reason)
	}
}

// A host that cannot read assembly references (PowerShell 7 has no
// ReflectionOnly load) must not be treated as proof of health, and must not be
// treated as proof of failure either.
func TestClassifyMarksUnreadableReferencesUnverified(t *testing.T) {
	module := azAccounts530()
	module.Required = nil
	module.RequiredError = "ReflectionOnly loading is not supported on this platform."
	classified := classifyBrokerModule(module)
	if classified.Verdict != VerdictUnverified {
		t.Fatalf("verdict = %q, want %q", classified.Verdict, VerdictUnverified)
	}
	if !strings.Contains(classified.Reason, "ReflectionOnly") {
		t.Errorf("reason %q drops the host's explanation", classified.Reason)
	}
}

func TestSelectPrefersVerifiedNewestAndNeverPicksInconsistent(t *testing.T) {
	unverified := azAccounts530()
	unverified.Version = "9.9.9"
	unverified.Directory = `C:\unverified\lib\netstandard2.0`
	unverified.Required = nil

	older := azAccounts530()
	older.Version = "5.2.0"
	older.Directory = `C:\older\lib\netstandard2.0`

	inventory := BrokerInventory{Modules: []BrokerModule{azAccounts304(), unverified, older, azAccounts530()}}
	module, err := selectBrokerModule(inventory)
	if err != nil {
		t.Fatalf("selection failed: %v", err)
	}
	if module.Version != "5.3.0" {
		t.Fatalf("selected %s (%s), want the newest verified 5.3.0", module.Version, module.Verdict)
	}
}

// An unverified module is still better than nothing: a machine whose host
// cannot read references must keep authenticating.
func TestSelectFallsBackToUnverified(t *testing.T) {
	unverified := azAccounts530()
	unverified.Required = nil
	inventory := BrokerInventory{Modules: []BrokerModule{azAccounts304(), unverified}}
	module, err := selectBrokerModule(inventory)
	if err != nil {
		t.Fatalf("selection failed: %v", err)
	}
	if module.Verdict != VerdictUnverified {
		t.Fatalf("verdict = %q, want %q", module.Verdict, VerdictUnverified)
	}
}

func TestSelectReportsTheMismatchAndTheRemedy(t *testing.T) {
	_, err := selectBrokerModule(BrokerInventory{Modules: []BrokerModule{azAccounts304()}})
	if err == nil {
		t.Fatal("an inconsistent assembly set must not be selected")
	}
	if err.Code != CodeBrokerAssemblyMismatch {
		t.Fatalf("code = %q, want %q", err.Code, CodeBrokerAssemblyMismatch)
	}
	for _, want := range []string{"3.0.4", assemblyNativeInterop, "0.16.1.0", "Install-Module Az.Accounts"} {
		if !strings.Contains(err.Message, want) {
			t.Errorf("message %q does not contain %q", err.Message, want)
		}
	}
}

func TestSelectDistinguishesNoModulesFromBadModules(t *testing.T) {
	_, err := selectBrokerModule(BrokerInventory{})
	if err == nil {
		t.Fatal("an empty inventory must not select a module")
	}
	if err.Code != CodeBrokerUnavailable {
		t.Fatalf("code = %q, want %q", err.Code, CodeBrokerUnavailable)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"5.3.0", "5.2.0", 1},
		{"5.2.0", "5.3.0", -1},
		{"5.3.0", "5.3.0", 0},
		{"10.0.0", "9.9.9", 1},
		{"5.3", "5.3.0", -1},
		{"", "1.0", -1},
		{"5.3.0-preview", "5.3.0", 1},
	}
	for _, testCase := range cases {
		if got := compareVersions(testCase.left, testCase.right); got != testCase.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", testCase.left, testCase.right, got, testCase.want)
		}
	}
}

// Windows PowerShell serializes a one-element collection as a bare object.
// Without tolerance for that, every machine with exactly one Az.Accounts would
// lose its broker.
func TestBrokerInventoryAcceptsPowerShellJSONShapes(t *testing.T) {
	cases := map[string]int{
		`{"host":"p","hostVersion":"5.1","modules":[{"version":"5.3.0"},{"version":"3.0.4"}]}`: 2,
		`{"host":"p","hostVersion":"5.1","modules":{"version":"5.3.0"}}`:                       1,
		`{"host":"p","hostVersion":"5.1","modules":null}`:                                      0,
		`{"host":"p","hostVersion":"5.1","modules":""}`:                                        0,
		`{"host":"p","hostVersion":"5.1"}`:                                                     0,
	}
	for document, want := range cases {
		var inventory BrokerInventory
		if err := json.Unmarshal([]byte(document), &inventory); err != nil {
			t.Fatalf("unmarshal %s: %v", document, err)
		}
		if len(inventory.Modules) != want {
			t.Errorf("%s -> %d modules, want %d", document, len(inventory.Modules), want)
		}
		if inventory.Host != "p" {
			t.Errorf("%s lost the host", document)
		}
	}
}
