package msauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecuteProtocolRejectsBeforeAcquisition(t *testing.T) {
	tests := []struct {
		request ProtocolRequest
		code    ErrorCode
	}{
		{request: ProtocolRequest{Version: 99, Operation: OperationAcquireToken, Client: "teams", Audience: "resource"}, code: CodeUnsupportedVersion},
		{request: ProtocolRequest{Version: ProtocolVersion, Operation: "other", Client: "teams", Audience: "resource"}, code: CodeUnsupportedOperation},
		{request: ProtocolRequest{Version: ProtocolVersion, Operation: OperationAcquireToken, Audience: "resource"}, code: CodeInvalidRequest},
		{request: ProtocolRequest{Version: ProtocolVersion, Operation: OperationAcquireToken, Client: "unknown", Audience: "resource"}, code: CodeInvalidRequest},
		{request: ProtocolRequest{Version: ProtocolVersion, Operation: OperationOpenSecret, Path: "p", CacheNamespace: "n"}, code: CodeInvalidRequest},
		{request: ProtocolRequest{Version: ProtocolVersion, Operation: OperationDiagnose, Client: "teams"}, code: CodeInvalidRequest},
	}
	for _, test := range tests {
		response := ExecuteProtocol(context.Background(), test.request)
		if response.OK || response.Error == nil || response.Error.Code != test.code {
			t.Fatalf("request=%+v response=%+v", test.request, response)
		}
		if response.Version != ProtocolVersion || response.Result != nil {
			t.Fatalf("invalid envelope: %+v", response)
		}
	}
}

// A diagnosis of a broken environment is a successful diagnosis. Collapsing
// that into a protocol error would force every non-Go client to parse prose to
// tell "msauth could not look" from "msauth looked and found a problem".
func TestDiagnoseSucceedsEvenWhenTheEnvironmentIsUnhealthy(t *testing.T) {
	if testing.Short() {
		t.Skip("diagnose may start a PowerShell host")
	}
	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version: ProtocolVersion, Operation: OperationDiagnose,
	})
	if !response.OK || response.Error != nil || response.Diagnostics == nil {
		t.Fatalf("unexpected response: %+v", response)
	}
	if response.Diagnostics.Version == "" || response.Diagnostics.ProtocolVersion != ProtocolVersion {
		t.Fatalf("diagnostics lack provenance: %+v", response.Diagnostics)
	}
	if response.Result != nil || response.Secret != nil {
		t.Fatalf("diagnose must not produce a token or a secret: %+v", response)
	}
}

// A non-Go client cannot call FormatError or Hint: they are ordinary Go
// functions with no operation of their own. Carrying their output on every
// failure response is what keeps the fleet's only renderer in this package
// instead of re-appearing in Python.
func TestFailureResponseCarriesTheRenderedDiagnosticAndHint(t *testing.T) {
	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version: ProtocolVersion, Operation: "nonesuch",
	})
	if response.OK || response.Error == nil {
		t.Fatalf("expected a failure response, got %+v", response)
	}
	if want := FormatError("", response.Error); response.Display != want {
		t.Fatalf("display: got %q want %q", response.Display, want)
	}
	if response.Display == "" || !strings.Contains(response.Display, string(CodeUnsupportedOperation)) {
		t.Fatalf("display does not name the code: %q", response.Display)
	}
	// This particular failure has no remediation, and inventing one would send
	// a signed-in user to re-run a login that was never the problem.
	if response.Hint != "" {
		t.Fatalf("unsupported_operation offered a hint: %q", response.Hint)
	}
}

// The hint must survive the wire for the fault a user cannot diagnose alone.
func TestFailureResponseCarriesTheBrokerHint(t *testing.T) {
	response := protocolFailure(&AuthError{
		Code: CodeAcquisitionFailed,
		Attempts: []Attempt{
			{Source: "wam", Code: CodeBrokerAssemblyMismatch, Message: "assembly set is inconsistent"},
		},
	})
	if response.Hint != "Run: msauth doctor" {
		t.Fatalf("hint: got %q", response.Hint)
	}
	if !strings.Contains(response.Display, "wam [broker_assembly_mismatch]") {
		t.Fatalf("display lost the attempt: %q", response.Display)
	}
}

// A success response carries neither field, so a client can test presence
// rather than comparing against an empty string it also gets on success.
func TestSuccessResponseCarriesNoDiagnostic(t *testing.T) {
	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version: ProtocolVersion, Operation: OperationCapabilities,
	})
	if !response.OK {
		t.Fatalf("capabilities failed: %+v", response.Error)
	}
	if response.Display != "" || response.Hint != "" {
		t.Fatalf("success response carried display=%q hint=%q", response.Display, response.Hint)
	}
}

// testJWT builds an unsigned JWT with the given payload. The "signature" is a
// literal, because nothing here verifies one and a test that implied otherwise
// would be lying about the guarantee.
func testJWT(t *testing.T, payload string) string {
	t.Helper()
	encode := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return encode(`{"typ":"JWT","alg":"RS256"}`) + "." + encode(payload) + ".c2lnbmF0dXJl"
}

func TestInspectTokenReportsTypedAndRawClaims(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Unix()
	token := testJWT(t, fmt.Sprintf(
		`{"upn":"user@contoso.com","tid":"72f988bf","aud":"https://icm.example","exp":%d,"acct":0,"amr":["pwd","mfa"]}`, expiry))

	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version: ProtocolVersion, Operation: OperationInspectToken, Token: token,
	})
	if !response.OK || response.Error != nil || response.Inspection == nil {
		t.Fatalf("unexpected response: %+v", response)
	}
	claims := response.Inspection.Claims
	if claims.UserPrincipalName != "user@contoso.com" || claims.TenantID != "72f988bf" ||
		claims.Audience != "https://icm.example" || claims.ExpiresAt.Unix() != expiry {
		t.Fatalf("typed claims are wrong: %+v", claims)
	}
	if response.Inspection.Stale {
		t.Fatalf("a token valid for an hour is not stale: %+v", response.Inspection)
	}

	// The raw map is what makes a full "decode this token" command possible
	// without a private decoder, so the claims Claims does NOT model must be
	// present, and must survive re-encoding unchanged.
	raw := response.Inspection.RawClaims
	if got := string(raw["amr"]); got != `["pwd","mfa"]` {
		t.Fatalf("unmodeled array claim lost: %q", got)
	}
	if got := string(raw["acct"]); got != "0" {
		t.Fatalf("unmodeled numeric claim lost: %q", got)
	}
	if got := string(raw["exp"]); got != fmt.Sprint(expiry) {
		t.Fatalf("exp changed shape through the wire: %q want %d", got, expiry)
	}
	// A response that repeats the caller's credential puts it in one more
	// place for no gain. Assert on the whole encoded envelope, not on fields,
	// because the point is that the token appears NOWHERE in it.
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), token) {
		t.Fatalf("the response echoed the token back: %s", encoded)
	}
}

// The skew that decides "stale" is the foundation's, not the adapter's. icy
// maintained a 120-second margin of its own that agreed with DefaultMinValidity
// only by coincidence.
func TestInspectTokenReportsStaleUsingTheSharedSkew(t *testing.T) {
	inside := testJWT(t, fmt.Sprintf(`{"exp":%d}`, time.Now().Add(DefaultMinValidity/2).Unix()))
	outside := testJWT(t, fmt.Sprintf(`{"exp":%d}`, time.Now().Add(DefaultMinValidity*10).Unix()))
	undated := testJWT(t, `{"upn":"user@contoso.com"}`)

	for _, test := range []struct {
		name  string
		token string
		stale bool
	}{
		{"within the refresh margin", inside, true},
		{"well outside it", outside, false},
		{"no exp claim at all", undated, false},
	} {
		response := ExecuteProtocol(context.Background(), ProtocolRequest{
			Version: ProtocolVersion, Operation: OperationInspectToken, Token: test.token,
		})
		if !response.OK || response.Inspection == nil {
			t.Fatalf("%s: %+v", test.name, response)
		}
		if response.Inspection.Stale != test.stale {
			t.Fatalf("%s: stale=%t want %t", test.name, response.Inspection.Stale, test.stale)
		}
	}
	// An absent expiry must not read as "fresh" by omission: the caller has to
	// be able to tell "this build says it is good" from "this build cannot
	// date it", and the typed claim is where that distinction lives.
	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version: ProtocolVersion, Operation: OperationInspectToken, Token: undated,
	})
	if !response.Inspection.Claims.ExpiresAt.IsZero() {
		t.Fatalf("undated token reported an expiry: %+v", response.Inspection.Claims)
	}
}

// The container case is the one this operation exists to get right: icy's
// retired cache file wrapped a JWT in JSON, and a decoder that looked only at
// segment 1 would describe the envelope as if it were the token.
func TestInspectTokenRejectsAContainerWithoutEchoingIt(t *testing.T) {
	inner := testJWT(t, `{"upn":"user@contoso.com"}`)
	for _, value := range []string{
		`{"token":"` + inner + `"}`,
		"not a token at all",
		"onlyonesegment",
		"a..b",
	} {
		response := ExecuteProtocol(context.Background(), ProtocolRequest{
			Version: ProtocolVersion, Operation: OperationInspectToken, Token: value,
		})
		if response.OK || response.Error == nil || response.Error.Code != CodeNotAToken {
			t.Fatalf("value %q: %+v", value, response)
		}
		if response.Inspection != nil {
			t.Fatalf("value %q produced an inspection: %+v", value, response.Inspection)
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), inner) || strings.Contains(string(encoded), value) {
			t.Fatalf("the rejection quoted the rejected value back: %s", encoded)
		}
		if response.Display == "" {
			t.Fatalf("a failure must carry a rendering for a non-Go client: %+v", response)
		}
	}
}

func TestInspectTokenRejectsAcquisitionAndSecretFields(t *testing.T) {
	token := testJWT(t, `{"upn":"user@contoso.com"}`)
	for _, request := range []ProtocolRequest{
		{Version: ProtocolVersion, Operation: OperationInspectToken},
		{Version: ProtocolVersion, Operation: OperationInspectToken, Token: token, Client: "teams"},
		{Version: ProtocolVersion, Operation: OperationInspectToken, Token: token, CacheNamespace: "n"},
		{Version: ProtocolVersion, Operation: OperationInspectToken, Token: token, Path: "p"},
		{Version: ProtocolVersion, Operation: OperationInspectToken, Token: token, Refresh: true},
	} {
		response := ExecuteProtocol(context.Background(), request)
		if response.OK || response.Error == nil || response.Error.Code != CodeInvalidRequest {
			t.Fatalf("request=%+v response=%+v", request, response)
		}
	}
}

// A token supplied to an operation that does not read one must be refused
// rather than ignored. This is the assertion that would have caught the field
// being added to the struct and to nothing else.
func TestOtherOperationsRejectATokenField(t *testing.T) {
	token := testJWT(t, `{"upn":"user@contoso.com"}`)
	for _, operation := range []string{
		OperationCapabilities, OperationAcquireToken, OperationProtectSecret, OperationOpenSecret, OperationDiagnose,
	} {
		request := ProtocolRequest{Version: ProtocolVersion, Operation: operation, Token: token}
		switch operation {
		case OperationAcquireToken:
			request.Client = "teams"
			request.Audience = "https://graph.microsoft.com"
		case OperationProtectSecret, OperationOpenSecret:
			request.Path = filepath.Join(t.TempDir(), "secret.bin")
		}
		response := ExecuteProtocol(context.Background(), request)
		if response.OK || response.Error == nil || response.Error.Code != CodeInvalidRequest {
			t.Fatalf("%s accepted a token field: %+v", operation, response)
		}
		if !strings.Contains(response.Error.Message, "token") {
			t.Fatalf("%s: rejection does not name the offending field: %q", operation, response.Error.Message)
		}
	}
}

// Every JSON field this build decodes must be one the guard can see. A field
// added to ProtocolRequest and not to setRequestFields is accepted silently by
// every operation, which is the failure this test exists to make loud.
func TestFieldGuardCoversEveryRequestField(t *testing.T) {
	guarded := map[string]bool{"version": true, "operation": true}
	for _, name := range setRequestFields(ProtocolRequest{
		Client: "c", Tenant: "t", Scope: "s", Audience: "a", Policy: PolicyWAMFirst,
		Refresh: true, CacheNamespace: "n", Path: "p", Secret: "x", Token: "j",
		Artifacts: []string{"a.exe"}, Required: "abc1234", Foundation: "../msauth",
	}) {
		guarded[name] = true
	}
	for _, field := range RequestFields() {
		if !guarded[field] {
			t.Fatalf("request field %q is decoded but invisible to the operation field guard", field)
		}
	}
}

// The wire auditor exists so a non-Go client never grows a second copy of the
// one check whose value depends on being identical everywhere. These cases
// assert the two properties an adapter depends on: a stale fleet is a
// SUCCESSFUL response carrying a false verdict, and the answer is byte-identical
// to the Go API's.

func TestAuditArtifactReportsFailureAsASuccessfulResponse(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version:   ProtocolVersion,
		Operation: OperationAuditArtifact,
		Artifacts: []string{self, filepath.Join(t.TempDir(), "absent.exe")},
		Required:  "0000000",
	})
	if !response.OK {
		t.Fatalf("an audit that finds stale artifacts must still succeed; got error %+v", response.Error)
	}
	if response.Audit == nil {
		t.Fatal("response carries no audit report")
	}
	if response.Audit.OK {
		t.Error("audit.ok must be false: one artifact is missing and neither carries revision 0000000")
	}
	if len(response.Audit.Rebuild) != 2 {
		t.Errorf("rebuild = %v, want both artifacts listed", response.Audit.Rebuild)
	}
	if response.Audit.Required != "0000000" {
		t.Errorf("required = %q, want the premise echoed back", response.Audit.Required)
	}
}

func TestAuditArtifactAgreesWithTheGoAPI(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version:   ProtocolVersion,
		Operation: OperationAuditArtifact,
		Artifacts: []string{self},
	})
	direct := AuditArtifacts([]string{self}, "")
	viaWire, _ := json.Marshal(response.Audit)
	viaAPI, _ := json.Marshal(direct)
	if string(viaWire) != string(viaAPI) {
		t.Fatalf("wire and Go API disagree:\n wire %s\n  api %s", viaWire, viaAPI)
	}
}

func TestAuditArtifactRequiresAtLeastOnePath(t *testing.T) {
	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version:   ProtocolVersion,
		Operation: OperationAuditArtifact,
		Required:  "abc1234",
	})
	if response.OK || response.Error == nil || response.Error.Code != CodeInvalidRequest {
		t.Fatalf("an audit naming no artifact must be an invalid_request; got %+v", response)
	}
}

func TestAuditArtifactRejectsAcquisitionFields(t *testing.T) {
	response := ExecuteProtocol(context.Background(), ProtocolRequest{
		Version:   ProtocolVersion,
		Operation: OperationAuditArtifact,
		Artifacts: []string{"x.exe"},
		Client:    "icy",
	})
	if response.OK || response.Error == nil || response.Error.Code != CodeInvalidRequest {
		t.Fatalf("auditing carries no acquisition semantics; got %+v", response)
	}
	if !strings.Contains(response.Error.Message, "client") {
		t.Errorf("the rejection must name the offending field; got %q", response.Error.Message)
	}
}
