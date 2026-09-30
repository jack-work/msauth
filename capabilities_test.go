package msauth

import (
	"context"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
)

// A client and the binary it invokes version independently, so the protocol has
// to make version skew self-describing. These tests pin that contract.

func TestCapabilitiesDescribesThisBuild(t *testing.T) {
	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version: ProtocolVersion, Operation: OperationCapabilities,
	})
	if !response.OK || response.Capabilities == nil || response.Error != nil {
		t.Fatalf("unexpected response: %+v", response)
	}
	capabilities := *response.Capabilities
	if capabilities.ProtocolVersion != ProtocolVersion {
		t.Fatalf("protocolVersion=%d", capabilities.ProtocolVersion)
	}
	for _, operation := range []string{OperationCapabilities, OperationAcquireToken, OperationProtectSecret, OperationOpenSecret, OperationDiagnose} {
		if !slices.Contains(capabilities.Operations, operation) {
			t.Fatalf("operations=%v missing %q", capabilities.Operations, operation)
		}
	}
	if !slices.Contains(capabilities.Clients, "teams") || !slices.Contains(capabilities.Policies, string(PolicyWAMOnly)) {
		t.Fatalf("unexpected capabilities: %+v", capabilities)
	}
	if capabilities.Module != modulePath || capabilities.Version == "" {
		t.Fatalf("provenance is missing: %+v", capabilities)
	}
}

// The request-field list is what lets an adapter explain an unsupported_field
// rejection, so it must be derived from the decoded type rather than restated.
func TestCapabilitiesReportsEveryDecodedRequestField(t *testing.T) {
	fields := RequestFields()
	for _, want := range []string{"version", "operation", "client", "tenant", "scope", "audience", "policy", "refresh", "cacheNamespace", "path", "secret"} {
		if !slices.Contains(fields, want) {
			t.Fatalf("requestFields=%v missing %q", fields, want)
		}
	}
}

// Capability discovery must answer even when the requested version is one this
// build does not speak. A client built for a later protocol has no other way to
// find out what it is actually talking to.
func TestCapabilitiesAnswersAtAnyRequestedVersion(t *testing.T) {
	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version: ProtocolVersion + 41, Operation: OperationCapabilities,
	})
	if !response.OK || response.Capabilities == nil {
		t.Fatalf("unexpected response: %+v", response)
	}
	if response.Version != ProtocolVersion {
		t.Fatalf("response version=%d", response.Version)
	}
}

func TestCapabilitiesRejectsExtraFields(t *testing.T) {
	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version: ProtocolVersion, Operation: OperationCapabilities, Client: "teams",
	})
	if response.OK || response.Error == nil || response.Error.Code != CodeInvalidRequest {
		t.Fatalf("unexpected response: %+v", response)
	}
}

// Version skew and a bad request must not share an error code. Before this,
// both returned invalid_request and an adapter could not tell "reinstall
// msauth" from "fix your request".
func TestVersionSkewHasDistinctCodes(t *testing.T) {
	tests := []struct {
		name    string
		request ProtocolRequest
		code    ErrorCode
	}{
		{
			name:    "unsupported version",
			request: ProtocolRequest{Version: 99, Operation: OperationAcquireToken, Client: "teams", Audience: "resource"},
			code:    CodeUnsupportedVersion,
		},
		{
			name:    "unsupported operation",
			request: ProtocolRequest{Version: ProtocolVersion, Operation: "rotateSecret"},
			code:    CodeUnsupportedOperation,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := ExecuteProtocol(context.Background(), test.request)
			if response.OK || response.Error == nil || response.Error.Code != test.code {
				t.Fatalf("unexpected response: %+v", response)
			}
			if response.Version != ProtocolVersion || response.Result != nil || response.Capabilities != nil {
				t.Fatalf("invalid envelope: %+v", response)
			}
			if !slices.Contains(UnsupportedCodes(), response.Error.Code) {
				t.Fatalf("%q is not reported as a skew code", response.Error.Code)
			}
		})
	}
}

// A skew diagnostic is only actionable if it names the rejected input and what
// this build does support.
func TestSkewMessagesAreSelfDescribing(t *testing.T) {
	tests := []struct {
		err      *AuthError
		contains []string
	}{
		{err: newUnsupportedOperationError("rotateSecret"), contains: []string{"rotateSecret", OperationOpenSecret, Version()}},
		{err: UnsupportedFieldError("cacheNamespaces"), contains: []string{"cacheNamespaces", "cacheNamespace", Version()}},
		{err: newUnsupportedVersionError(7), contains: []string{"7", "msauth"}},
	}
	for _, test := range tests {
		for _, want := range test.contains {
			if !contains(test.err.Message, want) {
				t.Fatalf("message %q does not mention %q", test.err.Message, want)
			}
		}
	}
}

// A malformed request must still be reported as a bad request, or the skew
// signal becomes noise.
func TestUnknownRequestStillRejectsBadInput(t *testing.T) {
	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version: ProtocolVersion, Operation: OperationAcquireToken, Audience: "resource",
	})
	if response.OK || response.Error == nil || response.Error.Code != CodeInvalidRequest {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// Version must never report a string that identifies no code.
//
// Every Go client on this machine links msauth through a filesystem replace
// directive. Go records such a replacement's version as the literal "(devel)",
// and the previous implementation returned it verbatim, so four clients each
// reported their auth foundation as "(devel)" and the answer to "which msauth
// is in this artifact" was a directory name at best. These tests pin the rule
// that made that possible: a version string is either real or it is labelled.

func TestReplacedVersionNeverReportsDevelAsAVersion(t *testing.T) {
	t.Cleanup(func() { Stamp = "" })
	Stamp = ""

	got := replacedVersion(&debug.Module{Path: "../msauth", Version: "(devel)"}, Stamp)
	if got == "(devel)" {
		t.Fatal(`Version reported "(devel)", which names no code and reads like a version`)
	}
	if !strings.Contains(got, "../msauth") {
		t.Errorf("version = %q, want it to name the replacement directory", got)
	}
}

func TestLinkTimeStampIdentifiesTheFoundationUnderAReplaceDirective(t *testing.T) {
	t.Cleanup(func() { Stamp = "" })
	Stamp = "53005bf"

	got := replacedVersion(&debug.Module{Path: "../msauth", Version: "(devel)"}, Stamp)
	if !strings.Contains(got, "53005bf") {
		t.Fatalf("version = %q, want the link-time stamp to identify the foundation", got)
	}
}

func TestARealModuleVersionBeatsTheStamp(t *testing.T) {
	t.Cleanup(func() { Stamp = "" })
	Stamp = "53005bf"

	// Once this module has a remote and tags, the dependency reports its own
	// version and the crutch must get out of the way rather than shadowing it.
	got := replacedVersion(&debug.Module{Path: "../msauth", Version: "v1.2.3"}, Stamp)
	if got != "v1.2.3" {
		t.Errorf("version = %q, want the real module version", got)
	}
}

func TestResolvedRejectsTheTwoUninformativeVersions(t *testing.T) {
	for _, version := range []string{"", "(devel)"} {
		if resolved(version) {
			t.Errorf("resolved(%q) = true, want false", version)
		}
	}
	for _, version := range []string{"v0.1.0", "v0.0.0-20260731205146-53005bfc7dd5"} {
		if !resolved(version) {
			t.Errorf("resolved(%q) = false, want true", version)
		}
	}
}

// The version this build reports must be the version it reports everywhere.
// A capability report and a diagnostic that disagree are worse than either.
func TestVersionIsConsistentAcrossEverySurfaceThatReportsIt(t *testing.T) {
	version := Version()
	if version == "" || version == "(devel)" {
		t.Fatalf("Version() = %q, which identifies no code", version)
	}
	if got := Describe().Version; got != version {
		t.Errorf("capabilities version = %q, want %q", got, version)
	}
	if got := Diagnose(t.Context()).Version; got != version {
		t.Errorf("diagnostics version = %q, want %q", got, version)
	}
}
