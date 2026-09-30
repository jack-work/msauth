package msauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The gate's failure modes matter more than its success: every way it can
// quietly measure nothing is a way convergence gets declared again without
// being delivered.

func writeFloor(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FloorFile), []byte(contents), 0o600); err != nil {
		t.Fatalf("write floor: %v", err)
	}
	return dir
}

func TestReadFloorAcceptsARevisionWithComments(t *testing.T) {
	dir := writeFloor(t, "# why this floor: needs auditArtifact\n\n7B52379\n")
	floor, err := ReadFloor(dir)
	if err != nil {
		t.Fatalf("ReadFloor: %v", err)
	}
	if floor != "7b52379" {
		t.Fatalf("floor = %q, want the lower-cased revision", floor)
	}
}

func TestReadFloorRefusesEveryFormOfNoFloor(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"only comment":       "# TODO: decide\n",
		"not a hex revision": "HEAD\n",
		"a path":             "../msauth\n",
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadFloor(writeFloor(t, contents)); err == nil {
				t.Fatal("a client that declares no usable floor must be an error, not a pass")
			}
		})
	}
	if _, err := ReadFloor(t.TempDir()); err == nil {
		t.Fatal("a missing floor file must be an error")
	} else if !strings.Contains(err.Error(), FloorFile) {
		t.Errorf("the error must name the file to create: %v", err)
	}
}

func TestGateRefusesToPassWithoutMeasuringSomething(t *testing.T) {
	if _, err := (Gate{Floor: "abc1234"}).Audit(); err == nil {
		t.Error("a gate naming no artifact must not report success")
	}
	if _, err := (Gate{Artifacts: []string{"x.exe"}}).Audit(); err == nil {
		t.Error("a gate with no floor must not report success")
	}
}

func TestLoadGateFindsTheSiblingFoundation(t *testing.T) {
	root := t.TempDir()
	client := filepath.Join(root, "client")
	foundation := filepath.Join(root, "msauth")
	for _, dir := range []string{client, filepath.Join(foundation, ".git")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(client, FloorFile), []byte("abc1234\n"), 0o600); err != nil {
		t.Fatalf("write floor: %v", err)
	}

	gate, err := LoadGate(client, "client.exe")
	if err != nil {
		t.Fatalf("LoadGate: %v", err)
	}
	if gate.Floor != "abc1234" {
		t.Errorf("floor = %q", gate.Floor)
	}
	if gate.FoundationDir == "" {
		t.Error("the sibling foundation worktree was not found, so the floor silently became an exact match")
	}

	// Without the sibling, the gate must still run -- stricter, and it must say
	// so. A SEPARATE root: a client under the same root would find the
	// foundation above and quietly pass this case.
	bare := filepath.Join(t.TempDir(), "client")
	if err := os.MkdirAll(bare, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bare, FloorFile), []byte("abc1234\n"), 0o600); err != nil {
		t.Fatalf("write floor: %v", err)
	}
	lonely, err := LoadGate(bare, "client.exe")
	if err != nil {
		t.Fatalf("LoadGate: %v", err)
	}
	if lonely.FoundationDir != "" {
		t.Errorf("FoundationDir = %q, want empty when no foundation sits beside the client", lonely.FoundationDir)
	}
	report, err := lonely.Audit()
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !strings.Contains(lonely.Explain(report), "EXACT equality") {
		t.Errorf("a gate running without an ordering must say so:\n%s", lonely.Explain(report))
	}
}

func TestExplainNamesTheArtifactTheReasonAndTheRemedy(t *testing.T) {
	gate := Gate{Floor: "abc1234", FoundationDir: ".", Artifacts: []string{"client.exe"}}
	report := AuditReport{
		Required: "abc1234",
		Artifacts: []ArtifactReport{{
			Path: "client.exe", Verdict: VerdictStale, OK: false,
			Reason: "foundation 0000000 is not the required abc1234: rebuild this client",
		}},
		Rebuild: []string{"client.exe"},
	}
	explanation := gate.Explain(report)
	for _, want := range []string{"client.exe", "abc1234", "status --porcelain", modulePath + ".Stamp"} {
		if !strings.Contains(explanation, want) {
			t.Errorf("explanation omits %q:\n%s", want, explanation)
		}
	}
	if (Gate{}).Explain(AuditReport{OK: true}) != "" {
		t.Error("a passing audit needs no explanation")
	}
}
