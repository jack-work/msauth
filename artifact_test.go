package msauth

import (
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
)

// The stamp parser is the load-bearing part of the artifact gate: for a
// filesystem-replace build it is the ONLY provenance the binary carries. These
// cases are written in the direction that costs hours -- a FALSE PASS, where
// the auditor reports a revision the artifact does not actually contain.

func TestStampFromBuildInfoAcceptsTheDocumentedRecipe(t *testing.T) {
	info := buildInfoWithLdflags(`-X github.com/jack-work/msauth.Stamp=1dda0cc`)
	if got := stampFromBuildInfo(info); got != "1dda0cc" {
		t.Fatalf("stamp = %q, want %q", got, "1dda0cc")
	}
}

func TestStampFromBuildInfoRejectsALookalikeModule(t *testing.T) {
	// A module whose path merely ENDS with "msauth" is a different module. A
	// parser that matched a trailing "msauth.Stamp" would report this variable
	// as this foundation's revision: a false pass, and the artifact would be
	// certified against code it does not contain.
	for _, ldflags := range []string{
		`-X github.com/evil/not-jack-work/msauth.Stamp=deadbee`,
		`-X example.com/vendored/github.com/jack-work/msauth.Stamp=deadbee`,
		`-X msauth.Stamp=deadbee`,
		`-X github.com/jack-work/msauth2.Stamp=deadbee`,
		`-X github.com/jack-work/msauth.StampX=deadbee`,
		`-X github.com/jack-work/msauth.Version=deadbee`,
	} {
		info := buildInfoWithLdflags(ldflags)
		if got := stampFromBuildInfo(info); got != "" {
			t.Errorf("ldflags %q: stamp = %q, want empty (must not match a different variable)", ldflags, got)
		}
	}
}

func TestStampFromBuildInfoHandlesTheFormsTheLinkerAccepts(t *testing.T) {
	cases := map[string]struct {
		ldflags string
		want    string
	}{
		"joined -X=":       {`-X=github.com/jack-work/msauth.Stamp=abc1234`, "abc1234"},
		"separated -X":     {`-X github.com/jack-work/msauth.Stamp=abc1234`, "abc1234"},
		"double quoted":    {`-s -w "-X github.com/jack-work/msauth.Stamp=abc1234"`, "abc1234"},
		"single quoted":    {`'-X github.com/jack-work/msauth.Stamp=abc1234'`, "abc1234"},
		"among others":     {`-s -w -X main.build=7 -X github.com/jack-work/msauth.Stamp=abc1234 -X main.date=x`, "abc1234"},
		"dirty marker":     {`-X github.com/jack-work/msauth.Stamp=abc1234+dirty`, "abc1234+dirty"},
		"value with equal": {`-X github.com/jack-work/msauth.Stamp=abc=1234`, "abc=1234"},
		"last wins":        {`-X github.com/jack-work/msauth.Stamp=old -X github.com/jack-work/msauth.Stamp=new`, "new"},
		"absent":           {`-s -w -X main.buildVersion=1.2.3`, ""},
		"no ldflags":       {``, ""},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			info := buildInfoWithLdflags(testCase.ldflags)
			if got := stampFromBuildInfo(info); got != testCase.want {
				t.Fatalf("stamp = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestSplitRevisionSeparatesDirtFromRevision(t *testing.T) {
	cases := map[string]struct {
		version      string
		wantRevision string
		wantDirty    bool
	}{
		"replaced clean": {"replaced+6d60a6f", "6d60a6f", false},
		"replaced dirty": {"replaced+6d60a6f+dirty", "6d60a6f", true},
		"devel clean":    {"devel+1dda0cc238f1", "1dda0cc238f1", false},
		"devel dirty":    {"devel+1dda0cc238f1+dirty", "1dda0cc238f1", true},
		"tagged":         {"v0.1.0", "v0.1.0", false},
		// A pseudo-version's trailing segment IS the revision. This case read
		// the other way until the gate was pointed at msauth.exe itself, which
		// links the foundation as "self" and whose version Go derives from VCS
		// in exactly this form: it failed its own audit against the revision it
		// had just been built from.
		"pseudo":                        {"v0.0.0-20260802232209-1dda0cc238f1", "1dda0cc238f1", false},
		"pseudo dirty":                  {"v0.0.0-20260802232209-1dda0cc238f1+dirty", "1dda0cc238f1", true},
		"pseudo prerelease":             {"v0.1.1-0.20260802232209-1dda0cc238f1", "1dda0cc238f1", false},
		"not a pseudo, short hash":      {"v0.0.0-20260802232209-1dda0cc", "v0.0.0-20260802232209-1dda0cc", false},
		"not a pseudo, short stamp":     {"v0.0.0-2026080223220-1dda0cc238f1", "v0.0.0-2026080223220-1dda0cc238f1", false},
		"not a pseudo, tag with dashes": {"v1.2.3-rc.1", "v1.2.3-rc.1", false},
		"unstamped replace":             {"replaced=../msauth", "", false},
		"bare replaced":                 {"replaced", "", false},
		"bare devel":                    {"devel", "", false},
		"unknown":                       {"unknown", "", false},
		"unknown but dirty":             {"unknown+dirty", "", true},
		"empty":                         {"", "", false},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			revision, dirty := splitRevision(testCase.version)
			if revision != testCase.wantRevision || dirty != testCase.wantDirty {
				t.Fatalf("splitRevision(%q) = (%q, %v), want (%q, %v)",
					testCase.version, revision, dirty, testCase.wantRevision, testCase.wantDirty)
			}
		})
	}
}

// Go records a 40-character vcs.revision while the documented stamp recipe
// passes `git rev-parse --short HEAD`. Requiring equal length would fail on
// every correctly built artifact, so this is not a nicety.
func TestRevisionsAgreeAcrossShortAndFullForms(t *testing.T) {
	const full = "1dda0cc238f125101a96913797c685b7aec17c57"
	const short = "1dda0cc"

	if !revisionsAgree(short, full) {
		t.Error("short have / full required should agree")
	}
	if !revisionsAgree(full, short) {
		t.Error("full have / short required should agree")
	}
	if !revisionsAgree(strings.ToUpper(short), full) {
		t.Error("comparison should be case-insensitive")
	}
	if revisionsAgree("1dda0cc", "9999999") {
		t.Error("different revisions must not agree")
	}
	if revisionsAgree("", full) || revisionsAgree(full, "") {
		t.Error("an empty revision must never agree with anything")
	}
	// A prefix relationship must be a real one: "1dd" is a prefix of the full
	// revision and should agree, but an unrelated value must not.
	if revisionsAgree("1dda0cd", full) {
		t.Error("a near-miss revision must not agree")
	}
}

func TestAuditFailsClosedOnEveryUnprovenLinkage(t *testing.T) {
	const required = "1dda0cc"

	cases := map[string]struct {
		report      ArtifactReport
		wantVerdict string
	}{
		"no msauth at all": {
			ArtifactReport{Linkage: LinkageNone},
			VerdictUnlinked,
		},
		"replace with no stamp": {
			ArtifactReport{Linkage: LinkageReplaced, FoundationVersion: "replaced=../msauth"},
			VerdictUnstamped,
		},
		"dirty foundation": {
			ArtifactReport{Linkage: LinkageReplaced, FoundationVersion: "replaced+1dda0cc+dirty",
				FoundationRevision: "1dda0cc", FoundationDirty: true},
			VerdictDirty,
		},
		"stale foundation": {
			ArtifactReport{Linkage: LinkageReplaced, FoundationVersion: "replaced+6d60a6f",
				FoundationRevision: "6d60a6f"},
			VerdictStale,
		},
		"current foundation": {
			ArtifactReport{Linkage: LinkageReplaced, FoundationVersion: "replaced+1dda0cc",
				FoundationRevision: "1dda0cc"},
			VerdictCurrent,
		},
		"unreadable file": {
			ArtifactReport{Verdict: VerdictUnreadable, Reason: "no artifact"},
			VerdictUnreadable,
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			got := Audit(testCase.report, required)
			if got.Verdict != testCase.wantVerdict {
				t.Fatalf("verdict = %q, want %q", got.Verdict, testCase.wantVerdict)
			}
			wantOK := testCase.wantVerdict == VerdictCurrent
			if got.OK != wantOK {
				t.Fatalf("OK = %v, want %v for verdict %q", got.OK, wantOK, got.Verdict)
			}
			if got.Reason == "" {
				t.Error("every verdict must carry a reason a rebuild list can quote")
			}
			if got.Required != required {
				t.Errorf("Required = %q, want %q: a stored report must carry its own premise", got.Required, required)
			}
		})
	}
}

// A DIRTY artifact must fail even when its revision is exactly the required
// one. This is the case the estate came within one build of shipping: the
// stamp names HEAD, the content is not HEAD, and a gate that compared
// revisions alone would have passed it.
func TestAuditRejectsADirtyArtifactWhoseRevisionMatches(t *testing.T) {
	report := ArtifactReport{
		Linkage:            LinkageReplaced,
		FoundationVersion:  "replaced+1dda0cc+dirty",
		FoundationRevision: "1dda0cc",
		FoundationDirty:    true,
	}
	got := Audit(report, "1dda0cc")
	if got.OK {
		t.Fatal("a dirty artifact must fail even when its revision matches the required one")
	}
	if got.Verdict != VerdictDirty {
		t.Fatalf("verdict = %q, want %q", got.Verdict, VerdictDirty)
	}
}

// The client's own tree being dirty is worth reporting but is NOT a foundation
// verdict. Three of the four library-linked artifacts on this machine are
// client-dirty; failing them for that would make the gate useless on day one.
func TestAuditIgnoresClientDirtinessWhenJudgingTheFoundation(t *testing.T) {
	report := ArtifactReport{
		Linkage:            LinkageReplaced,
		MainModified:       true,
		FoundationVersion:  "replaced+1dda0cc",
		FoundationRevision: "1dda0cc",
	}
	got := Audit(report, "1dda0cc")
	if !got.OK {
		t.Fatalf("a client built from a dirty tree against a clean foundation must pass: %s", got.Reason)
	}
	if !got.MainModified {
		t.Error("client dirtiness must still be reported")
	}
}

// An empty required revision audits provenance only. It must still fail an
// artifact that cannot say what it contains -- otherwise "audit with no
// baseline" silently becomes "audit nothing".
func TestAuditWithNoRequiredRevisionStillEnforcesProvenance(t *testing.T) {
	unstamped := Audit(ArtifactReport{Linkage: LinkageReplaced, FoundationVersion: "replaced=../msauth"}, "")
	if unstamped.OK {
		t.Error("an unstamped artifact must fail even with no required revision")
	}
	unlinked := Audit(ArtifactReport{Linkage: LinkageNone}, "")
	if unlinked.OK {
		t.Error("an unlinked artifact must fail even with no required revision")
	}
	identified := Audit(ArtifactReport{
		Linkage: LinkageReplaced, FoundationVersion: "replaced+6d60a6f", FoundationRevision: "6d60a6f",
	}, "")
	if !identified.OK {
		t.Error("an identifiable foundation should pass when no revision was required")
	}
}

func TestAuditArtifactsProducesTheRebuildList(t *testing.T) {
	// A foundation change must mechanically name the clients it obliges. These
	// paths do not exist, so every one is unreadable and therefore in the list;
	// the point under test is that the list is produced, sorted, and that OK is
	// false when anything failed.
	result := AuditArtifacts([]string{"z-missing.exe", "a-missing.exe"}, "1dda0cc")
	if result.OK {
		t.Error("OK must be false when any artifact failed")
	}
	if len(result.Rebuild) != 2 {
		t.Fatalf("rebuild list has %d entries, want 2", len(result.Rebuild))
	}
	if result.Rebuild[0] != "a-missing.exe" || result.Rebuild[1] != "z-missing.exe" {
		t.Errorf("rebuild list not sorted: %v", result.Rebuild)
	}
	if result.Required != "1dda0cc" {
		t.Errorf("Required = %q, want the audited revision echoed back", result.Required)
	}
}

func TestInspectArtifactDistinguishesMissingFromUnparseable(t *testing.T) {
	missing := InspectArtifact("this-path-does-not-exist.exe")
	if missing.Verdict != VerdictUnreadable {
		t.Fatalf("verdict = %q, want %q", missing.Verdict, VerdictUnreadable)
	}
	if !strings.Contains(missing.Reason, "nothing is installed") {
		t.Errorf("a missing artifact should say so plainly, got: %s", missing.Reason)
	}

	// This source file is readable but is not a Go binary.
	notABinary := InspectArtifact("artifact_test.go")
	if notABinary.Verdict != VerdictUnreadable {
		t.Fatalf("verdict = %q, want %q", notABinary.Verdict, VerdictUnreadable)
	}
	if strings.Contains(notABinary.Reason, "nothing is installed") {
		t.Error("an unparseable file must not be reported as a missing one: they call for opposite responses")
	}
}

// The auditor and the self-report must not be able to disagree, which is why
// versionFrom is shared rather than reimplemented. This pins that they agree on
// the shape the whole gate depends on.
func TestVersionFromMatchesTheReplaceRulesTheAuditorRelies0n(t *testing.T) {
	replaced := &debug.BuildInfo{
		Main: debug.Module{Path: "github.com/jack-work/tomb"},
		Deps: []*debug.Module{{
			Path:    modulePath,
			Version: "v0.0.0",
			Replace: &debug.Module{Path: "../msauth", Version: "(devel)"},
		}},
	}
	if got := versionFrom(replaced, "1dda0cc"); got != "replaced+1dda0cc" {
		t.Fatalf("stamped replace = %q, want %q", got, "replaced+1dda0cc")
	}
	if got := versionFrom(replaced, ""); got != "replaced=../msauth" {
		t.Fatalf("unstamped replace = %q, want %q", got, "replaced=../msauth")
	}
	// "(devel)" must never be reported: it reads like a version and names no code.
	if strings.Contains(versionFrom(replaced, "1dda0cc"), "devel") {
		t.Error("a replaced dependency must never report the literal (devel)")
	}
}

func buildInfoWithLdflags(ldflags string) *debug.BuildInfo {
	info := &debug.BuildInfo{Main: debug.Module{Path: "github.com/jack-work/tomb"}}
	if ldflags != "" {
		info.Settings = append(info.Settings, debug.BuildSetting{Key: "-ldflags", Value: ldflags})
	}
	return info
}

// A FLOOR is not an exact revision. A client declares the foundation its source
// was written against; an artifact rebuilt against something NEWER satisfies
// that and must pass. Two hashes alone cannot say which is newer, so the
// ordering reads the foundation's own history -- and when it cannot, the audit
// must fall back to the STRICTER answer, never the looser one.

func gitRevision(t *testing.T, spec string) string {
	t.Helper()
	output, err := exec.Command("git", "-C", ".", "rev-parse", "--short", spec).Output()
	if err != nil {
		t.Skipf("git rev-parse %s: %v (no usable foundation history here)", spec, err)
	}
	return strings.TrimSpace(string(output))
}

func TestGitAncestryOrdersTheFoundationsOwnHistory(t *testing.T) {
	head := gitRevision(t, "HEAD")
	parent := gitRevision(t, "HEAD~1")
	order := GitAncestry(".")

	if atLeast, known := order(parent, head); !known || !atLeast {
		t.Errorf("HEAD must satisfy a floor of HEAD~1; got atLeast=%t known=%t", atLeast, known)
	}
	if atLeast, known := order(head, parent); !known || atLeast {
		t.Errorf("HEAD~1 must NOT satisfy a floor of HEAD; got atLeast=%t known=%t", atLeast, known)
	}
	if atLeast, known := order(head, head); !known || !atLeast {
		t.Errorf("a revision satisfies itself; got atLeast=%t known=%t", atLeast, known)
	}
}

func TestGitAncestryReportsUnknownRatherThanGuessing(t *testing.T) {
	head := gitRevision(t, "HEAD")
	cases := map[string][2]string{
		"revision this clone has never seen": {"0123456789abcdef0123", head},
		"not a hex object name":              {"v0.1.0", head},
		"empty":                              {"", head},
		"not a repository":                   {head, head},
	}
	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			dir := "."
			if name == "not a repository" {
				dir = t.TempDir()
			}
			if _, known := GitAncestry(dir)(pair[0], pair[1]); known {
				t.Errorf("an ordering that cannot place a revision must answer known=false, not a verdict")
			}
		})
	}
}

func TestAuditAtLeastAcceptsANewerFoundationOnlyWithAnOrdering(t *testing.T) {
	head := gitRevision(t, "HEAD")
	parent := gitRevision(t, "HEAD~1")
	artifact := ArtifactReport{
		Path:               "client.exe",
		Linkage:            LinkageReplaced,
		FoundationVersion:  "replaced+" + head,
		FoundationRevision: head,
	}

	withOrder := AuditAtLeast(artifact, parent, GitAncestry("."))
	if !withOrder.OK || withOrder.Verdict != VerdictCurrent {
		t.Errorf("an artifact newer than its floor must pass: %+v", withOrder)
	}
	if !strings.Contains(withOrder.Reason, "at or after") {
		t.Errorf("the reason must say why a non-matching revision passed: %q", withOrder.Reason)
	}

	exact := Audit(artifact, parent)
	if exact.OK || exact.Verdict != VerdictStale {
		t.Errorf("without an ordering the comparison is exact equality: %+v", exact)
	}
}

// An ordering must never rescue an artifact that failed on provenance. Being
// newer than the floor says nothing about an artifact whose stamp is dirty or
// missing, and a floor is exactly where someone would expect leniency.
func TestOrderingCannotRescueAnUnprovenArtifact(t *testing.T) {
	head := gitRevision(t, "HEAD")
	order := GitAncestry(".")
	cases := map[string]ArtifactReport{
		"dirty": {
			Linkage: LinkageReplaced, FoundationVersion: "replaced+" + head + "+dirty",
			FoundationRevision: head, FoundationDirty: true,
		},
		"unstamped": {Linkage: LinkageReplaced, FoundationVersion: "replaced=../msauth"},
		"unlinked":  {Linkage: LinkageNone},
	}
	for name, artifact := range cases {
		t.Run(name, func(t *testing.T) {
			report := AuditAtLeast(artifact, head, order)
			if report.OK || report.Verdict == VerdictCurrent {
				t.Fatalf("%s must fail whatever the ordering says: %+v", name, report)
			}
		})
	}
}
