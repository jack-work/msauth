package msauth

import (
	"os"
	"path/filepath"
	"testing"
)

// A floor may name a version now, because a client consuming this module
// normally has no git revision to name. These tests pin both dialects and the
// boundary between them: a malformed floor must be an error, never a pass.

func TestPlausibleVersionAcceptsModuleVersionsAndRejectsTheRest(t *testing.T) {
	for _, good := range []string{"v0.1.0", "v1.0.0", "v0.2.0-rc.1", "v10.20.30"} {
		if !plausibleVersion(good) {
			t.Errorf("%q should be a plausible version", good)
		}
	}
	for _, bad := range []string{
		"0.1.0",               // no v
		"v0.1",                // two fields
		"v0.1.0.1",            // four fields
		"v0.1.0+incompatible", // build metadata
		"v0.1.0-",             // empty pre-release
		"v01.1.0",             // leading zero
		"vx.y.z",              // not numbers
		"29679c9",             // a git revision, the other dialect
		"",                    // nothing
	} {
		if plausibleVersion(bad) {
			t.Errorf("%q should not be a plausible version", bad)
		}
	}
}

func TestSemverOrderingPassesNewerAndFailsOlder(t *testing.T) {
	order := SemverOrdering()
	cases := []struct {
		required, carried string
		atLeast, known    bool
	}{
		{"v0.1.0", "v0.1.0", true, true},
		{"v0.1.0", "v0.2.0", true, true},
		{"v0.1.0", "v1.0.0", true, true},
		{"v0.2.0", "v0.1.9", false, true},
		{"v0.1.1", "v0.1.0", false, true},
		// A pre-release is older than the release it qualifies.
		{"v0.2.0", "v0.2.0-rc.1", false, true},
		{"v0.2.0-rc.1", "v0.2.0", true, true},
		// Two different pre-releases of one version: declined, not guessed.
		{"v0.2.0-rc.2", "v0.2.0-rc.1", false, false},
		// A git revision is not orderable by this comparison.
		{"29679c9", "v0.1.0", false, false},
		{"v0.1.0", "29679c9", false, false},
	}
	for _, c := range cases {
		atLeast, known := order(c.required, c.carried)
		if atLeast != c.atLeast || known != c.known {
			t.Errorf("order(%q, %q) = (%v, %v), want (%v, %v)",
				c.required, c.carried, atLeast, known, c.atLeast, c.known)
		}
	}
}

func TestReadFloorAcceptsBothDialectsAndRejectsNonsense(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, FloorFile), []byte(body), 0o644); err != nil {
			t.Fatalf("write floor: %v", err)
		}
		return dir
	}

	t.Run("version", func(t *testing.T) {
		floor, err := ReadFloor(write(t, "# a comment\nv0.1.0\n"))
		if err != nil {
			t.Fatalf("ReadFloor: %v", err)
		}
		if floor != "v0.1.0" {
			t.Errorf("floor = %q, want v0.1.0", floor)
		}
	})

	t.Run("revision still works", func(t *testing.T) {
		floor, err := ReadFloor(write(t, "29679C9\n"))
		if err != nil {
			t.Fatalf("ReadFloor: %v", err)
		}
		// Revisions are lowercased; versions are not, having no case to fold.
		if floor != "29679c9" {
			t.Errorf("floor = %q, want 29679c9", floor)
		}
	})

	t.Run("nonsense is an error, not a pass", func(t *testing.T) {
		if _, err := ReadFloor(write(t, "v0.1\n")); err == nil {
			t.Fatal("a malformed floor was accepted")
		}
	})
}

// The whole point of the version dialect: a module-linked artifact carries a
// version, so a gate must be able to judge it without a worktree to consult.
func TestVersionFloorNeedsNoFoundationWorktree(t *testing.T) {
	gate := Gate{Floor: "v0.1.0", Artifacts: []string{"irrelevant"}, FoundationDir: ""}
	if !plausibleVersion(gate.Floor) {
		t.Fatal("the fixture floor is not a version")
	}
	// AuditAtLeast is what Audit reaches with the ordering the gate selects;
	// exercising the decision directly keeps this test off the filesystem.
	report := AuditAtLeast(ArtifactReport{
		Linkage:            LinkageModule,
		FoundationVersion:  "v0.2.0",
		FoundationRevision: "v0.2.0",
	}, gate.Floor, SemverOrdering())
	if !report.OK {
		t.Fatalf("a newer module version failed a version floor: %s", report.Reason)
	}
	if report.Verdict != VerdictCurrent {
		t.Errorf("verdict = %q, want %q", report.Verdict, VerdictCurrent)
	}

	older := AuditAtLeast(ArtifactReport{
		Linkage:            LinkageModule,
		FoundationVersion:  "v0.0.9",
		FoundationRevision: "v0.0.9",
	}, gate.Floor, SemverOrdering())
	if older.OK {
		t.Fatal("an older module version passed a version floor")
	}
	if older.Verdict != VerdictStale {
		t.Errorf("verdict = %q, want %q", older.Verdict, VerdictStale)
	}
}
