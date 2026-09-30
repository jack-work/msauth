package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jack-work/msauth"
)

func run(t *testing.T, request string) msauth.ProtocolResponse {
	t.Helper()
	var output bytes.Buffer
	err := requestCommand(bytes.NewBufferString(request), &output)
	var response msauth.ProtocolResponse
	if decodeErr := json.Unmarshal(output.Bytes(), &response); decodeErr != nil {
		t.Fatalf("%v (stdout=%q, err=%v)", decodeErr, output.String(), err)
	}
	if response.Version != msauth.ProtocolVersion {
		t.Fatalf("response version=%d", response.Version)
	}
	if response.OK == (err != nil) {
		t.Fatalf("ok=%t but err=%v", response.OK, err)
	}
	return response
}

// An unknown field means the client is newer than this binary. Reporting it as
// a generic malformed request is what made "your msauth is too old" and "your
// request is wrong" indistinguishable.
func TestRequestCommandUnknownFieldNamesTheField(t *testing.T) {
	response := run(t, `{"version":1,"operation":"capabilities","cacheNamespaces":"x"}`)
	if response.Error == nil || response.Error.Code != msauth.CodeUnsupportedField {
		t.Fatalf("unexpected response: %+v", response)
	}
	if !strings.Contains(response.Error.Message, `"cacheNamespaces"`) {
		t.Fatalf("message does not name the field: %q", response.Error.Message)
	}
	if !strings.Contains(response.Error.Message, "cacheNamespace,") && !strings.Contains(response.Error.Message, "cacheNamespace ") {
		t.Fatalf("message does not list supported fields: %q", response.Error.Message)
	}
}

func TestRequestCommandMalformedJSONStaysInvalidRequest(t *testing.T) {
	response := run(t, `{"version":1,`)
	if response.Error == nil || response.Error.Code != msauth.CodeInvalidRequest {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestRequestCommandTrailingObjectIsRejected(t *testing.T) {
	response := run(t, `{"version":1,"operation":"capabilities"} {"version":1}`)
	if response.Error == nil || response.Error.Code != msauth.CodeInvalidRequest {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestRequestCommandUnsupportedVersion(t *testing.T) {
	response := run(t, `{"version":2,"operation":"acquireToken","client":"teams","audience":"resource"}`)
	if response.Error == nil || response.Error.Code != msauth.CodeUnsupportedVersion {
		t.Fatalf("unexpected response: %+v", response)
	}
	if !strings.Contains(response.Error.Message, "protocol version 2") {
		t.Fatalf("message does not name the version: %q", response.Error.Message)
	}
}

// The capability probe is the one operation an adapter may run to diagnose a
// failure, so it must succeed end to end through the command with no auth.
func TestRequestCommandCapabilitiesRoundTrip(t *testing.T) {
	response := run(t, `{"version":1,"operation":"capabilities"}`)
	if !response.OK || response.Capabilities == nil {
		t.Fatalf("unexpected response: %+v", response)
	}
	if !slices.Contains(response.Capabilities.Operations, msauth.OperationOpenSecret) {
		t.Fatalf("operations=%v", response.Capabilities.Operations)
	}
}

func TestRequestCommandUnsupportedOperationNamesSupportedOnes(t *testing.T) {
	response := run(t, `{"version":1,"operation":"rotateSecret"}`)
	if response.Error == nil || response.Error.Code != msauth.CodeUnsupportedOperation {
		t.Fatalf("unexpected response: %+v", response)
	}
	if !strings.Contains(response.Error.Message, msauth.OperationCapabilities) {
		t.Fatalf("message does not name the capability probe: %q", response.Error.Message)
	}
}

// doctor is the command an operator runs when authentication is broken, so it
// must produce a report rather than an error, and its JSON form must stay
// machine-readable for a client that wants to explain the fault itself.
func TestDoctorReportsWithoutAuthenticating(t *testing.T) {
	if testing.Short() {
		t.Skip("doctor starts a PowerShell host")
	}
	var output bytes.Buffer
	err := doctorCommand([]string{"--json"}, &output)
	var diagnostics msauth.Diagnostics
	if decodeErr := json.Unmarshal(output.Bytes(), &diagnostics); decodeErr != nil {
		t.Fatalf("%v (stdout=%q, err=%v)", decodeErr, output.String(), err)
	}
	if diagnostics.Healthy != (err == nil) {
		t.Fatalf("healthy=%t but err=%v", diagnostics.Healthy, err)
	}
	if strings.Contains(output.String(), "accessToken") {
		t.Fatal("the report must not carry credential material")
	}

	var text bytes.Buffer
	_ = doctorCommand(nil, &text)
	for _, want := range []string{"msauth", "cache"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text report omits %q: %s", want, text.String())
		}
	}
}

// A decode-stage rejection is answered outside ExecuteProtocol. It must still
// carry the rendered diagnostic, or a client cannot tell "this msauth is too
// old to send display" from "a current msauth rejected your JSON" -- two
// conditions whose remedies are opposites.
func TestDecodeRejectionCarriesTheRenderedDiagnostic(t *testing.T) {
	var out bytes.Buffer
	err := requestCommand(strings.NewReader("not json"), &out)
	if err == nil {
		t.Fatal("expected a protocol error")
	}
	var response msauth.ProtocolResponse
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, out.String())
	}
	if response.OK || response.Error == nil {
		t.Fatalf("expected a failure response: %s", out.String())
	}
	if response.Display == "" {
		t.Fatalf("decode rejection carried no display: %s", out.String())
	}
	if want := msauth.FormatError("", response.Error); response.Display != want {
		t.Fatalf("display: got %q want %q", response.Display, want)
	}
}

// The audit command is the estate's delivery step, so its EXIT STATUS is the
// contract: a gate that prints "FAIL" and exits 0 stops a build for nobody.

func TestAuditCommandExitsNonZeroOnAStaleArtifact(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	var output bytes.Buffer
	err = auditCommand([]string{"--required", "0000000", self}, &output)
	if err == nil {
		t.Fatalf("auditing against a revision the artifact does not carry must fail; output=%q", output.String())
	}
	if !strings.Contains(output.String(), "FAIL") {
		t.Errorf("report does not mark the failing artifact: %q", output.String())
	}
	if !strings.Contains(output.String(), "rebuild") {
		t.Errorf("report does not name the rebuild list: %q", output.String())
	}
}

// A path typo must not read as a pass. This is the case that makes a gate
// worthless: it measures nothing and reports success.
func TestAuditCommandFailsOnAnAbsentArtifact(t *testing.T) {
	var output bytes.Buffer
	missing := filepath.Join(t.TempDir(), "never-installed.exe")
	if err := auditCommand([]string{missing}, &output); err == nil {
		t.Fatalf("an absent artifact must fail the audit; output=%q", output.String())
	}
	if !strings.Contains(output.String(), "nothing is installed at this path") {
		t.Errorf("report does not explain the absence: %q", output.String())
	}
}

func TestAuditCommandRequiresAPath(t *testing.T) {
	var output bytes.Buffer
	if err := auditCommand(nil, &output); err == nil {
		t.Fatal("auditing nothing must be an error, not a vacuous pass")
	}
}

func TestAuditCommandJSONCarriesTheRebuildList(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	var output bytes.Buffer
	_ = auditCommand([]string{"--json", "--required", "0000000", self}, &output)
	var report msauth.AuditReport
	if decodeErr := json.Unmarshal(output.Bytes(), &report); decodeErr != nil {
		t.Fatalf("%v (stdout=%q)", decodeErr, output.String())
	}
	if report.OK || len(report.Rebuild) != 1 || report.Rebuild[0] != self {
		t.Fatalf("unexpected report: %+v", report)
	}
}

// --gate is how a NON-Go client reaches the same judgement a Go client gets
// from msauth.LoadGate in its test suite. icy is the reason it exists: the one
// client with working delivery must not be the one client with no gate.
func TestAuditGateReadsTheClientsFloor(t *testing.T) {
	root := t.TempDir()
	client := filepath.Join(root, "client")
	if err := os.MkdirAll(client, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(client, msauth.FloorFile), []byte("0000000\n"), 0o600); err != nil {
		t.Fatalf("write floor: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	var output bytes.Buffer
	if err := auditCommand([]string{"--gate", client, self}, &output); err == nil {
		t.Fatalf("the artifact carries no revision 0000000 and must fail; output=%q", output.String())
	}
	if !strings.Contains(output.String(), "rebuild and reinstall") {
		t.Errorf("a gate failure must carry the remedy: %q", output.String())
	}

	var missingFloor bytes.Buffer
	if err := auditCommand([]string{"--gate", root, self}, &missingFloor); err == nil {
		t.Fatal("a client with no floor file must fail rather than pass vacuously")
	}
}

func TestAuditGateRejectsContradictoryFlags(t *testing.T) {
	var output bytes.Buffer
	if err := auditCommand([]string{"--gate", ".", "--required", "abc1234", "x.exe"}, &output); err == nil {
		t.Fatal("--gate supplies the floor; combining it with --required must be refused rather than silently preferred")
	}
}

func TestAuditFleetRefusesAnEmptyFleet(t *testing.T) {
	t.Setenv(msauth.EnvConfigFile, filepath.Join(t.TempDir(), "absent.json"))
	var output bytes.Buffer
	err := auditCommand([]string{"--fleet", "--required", "abc1234"}, &output)
	if err == nil {
		t.Fatal("auditing an unconfigured fleet must fail: an audit of nothing must not report success")
	}
	if !strings.Contains(err.Error(), "fleet") {
		t.Errorf("the error must say what to configure: %v", err)
	}
}

func TestAuditFleetReadsTheConfiguredArtifacts(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	config := filepath.Join(t.TempDir(), "auth.json")
	body, err := json.Marshal(map[string]any{"fleet": []string{self}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(config, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(msauth.EnvConfigFile, config)

	var output bytes.Buffer
	_ = auditCommand([]string{"--fleet", "--required", "0000000", "--json"}, &output)
	var report msauth.AuditReport
	if decodeErr := json.Unmarshal(output.Bytes(), &report); decodeErr != nil {
		t.Fatalf("%v (stdout=%q)", decodeErr, output.String())
	}
	if len(report.Artifacts) != 1 || report.Artifacts[0].Path != self {
		t.Fatalf("the fleet was not read from configuration: %+v", report)
	}

	var conflict bytes.Buffer
	if err := auditCommand([]string{"--fleet", "other.exe"}, &conflict); err == nil {
		t.Error("--fleet plus explicit paths is ambiguous and must be refused")
	}
}
