package msauth

import (
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

// This file answers one question that nothing in this estate could answer
// mechanically: DOES AN INSTALLED BINARY CARRY A CURRENT AUTH FOUNDATION?
//
// It exists because the two linkage styles have different fix-propagation
// semantics. A client that EXECS msauth.exe self-heals the moment the shared
// binary is replaced. A client that LINKS this package as a Go library freezes
// the foundation at its own build time and inherits nothing until someone
// rebuilds it. Between 2026-07-28 and 2026-08-02 convergence was declared five
// times and delivered to exactly one of five clients -- the only one that ships
// no binary at all -- and each discovery run re-derived that by dependency
// closure archaeology against go.mod across commits.
//
// THE CHECK READS THE ARTIFACT, NOT THE SOURCE, AND DOES NOT RUN IT. Executing
// an authenticated tool to ask its version is the wrong instrument twice: it
// can trigger a real credential acquisition, and a tool too broken to start is
// exactly the one whose provenance you most need. debug/buildinfo reads the
// build metadata straight out of the file.
//
// TWO TRAPS THIS ENCODES, both learned the expensive way.
//
//  1. "Does the artifact match its own source" IS THE WRONG QUESTION. On
//     2026-08-02 tomb's installed binary matched tomb HEAD exactly and was
//     still five msauth commits stale. Every gate anybody had proposed passed
//     on it. The question is whether the artifact carries a foundation AT
//     LEAST AS NEW as the one it is required to have, which is why Audit takes
//     the required revision as an argument rather than inferring it.
//
//  2. A DIRTY STAMP IS A FAILURE, AND A CLEAN ONE PROVES NOTHING. The stamp is
//     whatever the builder passed; `git rev-parse --short HEAD` reports HEAD
//     regardless of worktree state, so an artifact built against MODIFIED
//     foundation code can carry a clean revision it does not contain. That is
//     strictly worse than being stale, because a stale artifact is detectable.
//     This package cannot see the tree a client was built from, so the absence
//     of "+dirty" is never treated as evidence of cleanliness -- only its
//     presence is treated as evidence of dirt. See the Stamp doc comment for
//     the dirty-aware build recipe that produces it.

// Foundation linkage styles, reported by ArtifactReport.Linkage.
const (
	// LinkageNone means the artifact does not reference this module at all. For
	// a client that is supposed to have converged, this is the loudest possible
	// answer: it still carries whatever auth chain it had before.
	LinkageNone = "none"
	// LinkageSelf means the artifact IS this module (msauth.exe itself).
	LinkageSelf = "self"
	// LinkageModule means a normal versioned module dependency. This is the
	// case the stamp exists to work around, and the case that needs no stamp.
	LinkageModule = "module"
	// LinkageReplaced means a filesystem replace directive, which carries no
	// module version, so provenance rests entirely on the link-time stamp.
	LinkageReplaced = "replaced"
)

// Audit verdicts, reported by ArtifactReport.Verdict. Only VerdictCurrent passes.
const (
	VerdictCurrent = "current"
	// VerdictStale means the artifact carries an identifiable foundation that
	// is not the required one. It is the ordinary "needs a rebuild" answer.
	VerdictStale = "stale"
	// VerdictDirty means the foundation revision is marked "+dirty": the
	// artifact contains uncommitted foundation code that no revision names.
	VerdictDirty = "dirty"
	// VerdictUnstamped means the foundation is linked by filesystem replace
	// with no stamp, so the artifact cannot say which code it contains. It is
	// unauditable rather than merely stale, and must not read as a pass.
	VerdictUnstamped = "unstamped"
	// VerdictUnlinked means the artifact does not carry this foundation at all.
	VerdictUnlinked = "unlinked"
	// VerdictUnreadable means the file could not be read as a Go binary.
	VerdictUnreadable = "unreadable"
)

// ArtifactReport is what one installed binary says about its auth foundation.
// Every field is derived from build metadata read out of the file; nothing here
// requires running the artifact, reaching a network, or touching a credential.
type ArtifactReport struct {
	Path string `json:"path"`

	// Module and MainVersion identify the artifact's own main module.
	Module      string `json:"module,omitempty"`
	MainVersion string `json:"mainVersion,omitempty"`
	// MainRevision and MainModified describe the artifact's OWN source tree,
	// not the foundation's. MainModified true means the client was built from a
	// dirty tree; that is worth reporting but is NOT a foundation verdict, and
	// deliberately does not fail the audit on its own.
	MainRevision string `json:"mainRevision,omitempty"`
	MainModified bool   `json:"mainModified,omitempty"`
	GoVersion    string `json:"goVersion,omitempty"`

	// Linkage is one of the Linkage* constants.
	Linkage string `json:"linkage"`
	// FoundationVersion is resolved by exactly the same rules this package uses
	// to report its own Version(), so an artifact's audited answer and its
	// self-reported answer cannot disagree.
	FoundationVersion string `json:"foundationVersion,omitempty"`
	// FoundationRevision is the bare revision the artifact carries, with any
	// "+dirty" marker removed. It is the value to compare against a required
	// revision; empty when the artifact names no revision at all.
	FoundationRevision string `json:"foundationRevision,omitempty"`
	// FoundationDirty is true only when the artifact ITSELF admits dirt. False
	// asserts nothing: see trap 2 above.
	FoundationDirty bool   `json:"foundationDirty,omitempty"`
	ReplacePath     string `json:"replacePath,omitempty"`

	// Required is the revision this artifact was audited against, echoed so a
	// stored report carries its own premise rather than a pointer to one.
	Required string `json:"required,omitempty"`
	Verdict  string `json:"verdict"`
	OK       bool   `json:"ok"`
	// Reason states, in one line, why the verdict is what it is. It is written
	// to be quoted verbatim into a rebuild list.
	Reason string `json:"reason"`
}

// AuditReport is the result of auditing a set of artifacts against one required
// foundation revision. Rebuild is the mechanical answer to "which clients does
// this foundation change oblige me to rebuild", which is the thing a foundation
// fix has never produced here.
type AuditReport struct {
	Required  string           `json:"required"`
	Artifacts []ArtifactReport `json:"artifacts"`
	Rebuild   []string         `json:"rebuild"`
	OK        bool             `json:"ok"`
}

// InspectArtifact reads one Go binary and reports what auth foundation it
// carries. It opens the file read-only and never executes it.
func InspectArtifact(path string) ArtifactReport {
	report := ArtifactReport{Path: path, Linkage: LinkageNone}

	info, err := buildinfo.ReadFile(path)
	if err != nil {
		report.Verdict = VerdictUnreadable
		report.Reason = unreadableReason(path, err)
		return report
	}

	report.Module = info.Main.Path
	report.MainVersion = info.Main.Version
	report.GoVersion = info.GoVersion
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			report.MainRevision = setting.Value
		case "vcs.modified":
			report.MainModified = setting.Value == "true"
		}
	}

	stamp := stampFromBuildInfo(info)

	switch {
	case info.Main.Path == modulePath:
		report.Linkage = LinkageSelf
	default:
		for _, dep := range info.Deps {
			if dep.Path != modulePath {
				continue
			}
			if dep.Replace != nil {
				report.Linkage = LinkageReplaced
				report.ReplacePath = dep.Replace.Path
			} else {
				report.Linkage = LinkageModule
			}
			break
		}
	}

	if report.Linkage == LinkageNone {
		return report
	}

	report.FoundationVersion = versionFrom(info, stamp)
	report.FoundationRevision, report.FoundationDirty = splitRevision(report.FoundationVersion)
	return report
}

// unreadableReason keeps the two unreadable cases apart, because they call for
// opposite responses: a missing artifact means the tool is not installed, and
// an unparseable one usually means it is not a Go binary at all.
func unreadableReason(path string, err error) string {
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Sprintf("no artifact at %s: nothing is installed at this path", path)
	}
	return fmt.Sprintf("cannot read Go build info from %s: %v", path, err)
}

// Ordering answers "is the revision this artifact CARRIES at least as new as
// the one it is REQUIRED to have". It exists because the two questions a gate
// asks are different: a fleet-wide delivery sweep after a foundation change
// wants exact equality ("which clients does this commit oblige me to rebuild"),
// while a client's own gate declares a FLOOR -- the foundation revision its
// source was written against -- and a client rebuilt against something newer
// must pass, not fail. Two revisions alone cannot answer that: a git hash
// carries no order, so an ordering needs the foundation's history.
//
// atLeast is meaningful only when known is true. An Ordering that cannot place
// either revision returns known false, and the audit falls back to exact
// equality -- the STRICTER answer, so an ordering that silently stops working
// can only produce spurious rebuilds, never a spurious pass.
type Ordering func(required, carried string) (atLeast bool, known bool)

// Audit judges one inspected artifact against a required foundation revision
// and fills in Required, Verdict, OK and Reason. Required is compared as a
// prefix in whichever direction is shorter, so a 7-character short revision and
// a 40-character full one agree; an empty required revision audits provenance
// only, which still fails an unlinked, unstamped or dirty artifact. Exact
// equality is the whole test: use AuditAtLeast for floor semantics.
func Audit(report ArtifactReport, required string) ArtifactReport {
	return AuditAtLeast(report, required, nil)
}

// AuditAtLeast is Audit with an ordering, so a revision NEWER than required
// passes. A nil ordering means exact equality.
func AuditAtLeast(report ArtifactReport, required string, order Ordering) ArtifactReport {
	report.Required = required

	switch report.Verdict {
	case VerdictUnreadable:
		report.OK = false
		return report
	}

	switch report.Linkage {
	case LinkageNone:
		report.Verdict = VerdictUnlinked
		report.OK = false
		report.Reason = "artifact links no " + modulePath + " at all: it still carries its own auth implementation"
		return report
	case LinkageReplaced:
		if report.FoundationRevision == "" {
			report.Verdict = VerdictUnstamped
			report.OK = false
			report.Reason = "foundation linked by filesystem replace with no link-time stamp (" +
				report.FoundationVersion + "): the artifact cannot say which foundation code it contains"
			return report
		}
	}

	if report.FoundationDirty {
		report.Verdict = VerdictDirty
		report.OK = false
		report.Reason = "foundation stamp " + report.FoundationVersion +
			" is marked dirty: the artifact contains uncommitted foundation code that no revision names"
		return report
	}

	if required == "" {
		report.Verdict = VerdictCurrent
		report.OK = true
		report.Reason = "foundation " + report.FoundationVersion + " is identifiable; no required revision was given to compare it against"
		return report
	}

	if revisionsAgree(report.FoundationRevision, required) {
		report.Verdict = VerdictCurrent
		report.OK = true
		report.Reason = "foundation " + report.FoundationRevision + " matches the required " + required
		return report
	}

	if order != nil {
		if atLeast, known := order(required, report.FoundationRevision); known && atLeast {
			report.Verdict = VerdictCurrent
			report.OK = true
			report.Reason = "foundation " + report.FoundationRevision + " is at or after the required " + required
			return report
		}
	}

	report.Verdict = VerdictStale
	report.OK = false
	report.Reason = "foundation " + report.FoundationRevision + " is not the required " + required + ": rebuild this client"
	return report
}

// AuditArtifacts inspects and audits every named path and returns the rebuild
// list. A foundation change can then produce the list of clients it obliges,
// which is the step this estate has never had.
func AuditArtifacts(paths []string, required string) AuditReport {
	return AuditArtifactsAtLeast(paths, required, nil)
}

// AuditArtifactsAtLeast is AuditArtifacts with floor semantics.
func AuditArtifactsAtLeast(paths []string, required string, order Ordering) AuditReport {
	result := AuditReport{Required: required, OK: true, Artifacts: make([]ArtifactReport, 0, len(paths)), Rebuild: []string{}}
	for _, path := range paths {
		report := AuditAtLeast(InspectArtifact(path), required, order)
		result.Artifacts = append(result.Artifacts, report)
		if !report.OK {
			result.OK = false
			result.Rebuild = append(result.Rebuild, path)
		}
	}
	sort.Strings(result.Rebuild)
	return result
}

// GitAncestry orders revisions by the foundation's own history, using the
// worktree at dir. It answers known=false for anything it cannot place --
// git missing, dir not a repository, or a revision this clone has never seen,
// which is the ordinary case for an artifact built on another machine -- and
// the audit then falls back to exact equality.
//
// It runs `git merge-base --is-ancestor`, which reads history and writes
// nothing. A revision is "at least" required when required is an ancestor of
// it, or when they are the same commit.
func GitAncestry(dir string) Ordering {
	return func(required, carried string) (bool, bool) {
		if required == "" || carried == "" || !plausibleRevision(required) || !plausibleRevision(carried) {
			return false, false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, revision := range []string{required, carried} {
			if exec.CommandContext(ctx, "git", "-C", dir, "cat-file", "-e", revision+"^{commit}").Run() != nil {
				return false, false
			}
		}
		err := exec.CommandContext(ctx, "git", "-C", dir, "merge-base", "--is-ancestor", required, carried).Run()
		if err == nil {
			return true, true
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			// A definite "no": required is not an ancestor, so the artifact is
			// genuinely behind or on a divergent line. That is a known answer.
			return false, true
		}
		return false, false
	}
}

// plausibleRevision keeps anything that is not a hex object name out of the
// argument list of a git command. A version string such as "v0.1.0" is a valid
// revision to git but is not what this ordering compares, and refusing it here
// means the fallback to exact equality happens for a clear reason.
func plausibleRevision(revision string) bool {
	if len(revision) < 4 || len(revision) > 40 {
		return false
	}
	for _, r := range revision {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// revisionsAgree compares two revisions of possibly different lengths. Go
// records a 40-character vcs.revision while the documented stamp recipe passes
// `git rev-parse --short HEAD`, so requiring equal length would fail on every
// correctly built artifact. A prefix match in the shorter direction is the only
// comparison that can succeed for both forms.
func revisionsAgree(have, required string) bool {
	if have == "" || required == "" {
		return false
	}
	have = strings.ToLower(have)
	required = strings.ToLower(required)
	if len(have) < len(required) {
		return strings.HasPrefix(required, have)
	}
	return strings.HasPrefix(have, required)
}

// splitRevision separates the bare revision from a "+dirty" marker. It reads
// the LAST path of a version string such as "replaced+6d60a6f+dirty" or
// "devel+abc123+dirty", so the marker is recognised wherever the version
// builders in capabilities.go can place it.
//
// It also unwraps a Go PSEUDO-VERSION, whose trailing segment is the revision:
// v0.0.0-20260804035314-29679c9418d6 carries 29679c9418d6. Without that, the
// first thing this gate was ever pointed at -- msauth.exe itself, whose linkage
// is "self" and whose version Go derives from VCS as a pseudo-version -- failed
// its own audit against the very revision it was built from. A false FAIL is
// the safe direction to be wrong in, and it is still wrong: a gate that cries
// stale about a current artifact is a gate people learn to ignore.
func splitRevision(version string) (revision string, dirty bool) {
	if version == "" {
		return "", false
	}
	if strings.HasSuffix(version, "+dirty") {
		dirty = true
		version = strings.TrimSuffix(version, "+dirty")
	}
	// "replaced=../msauth" names a directory, not code, and is not a revision.
	if strings.Contains(version, "=") {
		return "", dirty
	}
	if index := strings.LastIndex(version, "+"); index >= 0 {
		version = version[index+1:]
	}
	if version == "replaced" || version == "devel" || version == "unknown" {
		return "", dirty
	}
	if hash, ok := pseudoVersionRevision(version); ok {
		return hash, dirty
	}
	return version, dirty
}

// pseudoVersionRevision extracts the revision from a Go pseudo-version. Only
// the exact shape counts: a semantic version, then a 14-digit UTC build stamp,
// then a 12-character hex revision, as `go` itself constructs it. A TAG such as
// v0.1.0 is not a pseudo-version and its revision is the tag -- which is the
// right answer, because a tagged dependency needs no stamp at all.
func pseudoVersionRevision(version string) (string, bool) {
	parts := strings.Split(version, "-")
	if len(parts) < 3 || !strings.HasPrefix(parts[0], "v") {
		return "", false
	}
	stamp, hash := parts[len(parts)-2], parts[len(parts)-1]
	// The stamp segment is 14 digits, optionally prefixed by the base-version
	// bookkeeping go adds when the module already has a tag: "0." in
	// v0.1.1-0.20260802232209-1dda0cc238f1, or "rc.1.0." and friends.
	if dot := strings.LastIndex(stamp, "."); dot >= 0 {
		stamp = stamp[dot+1:]
	}
	if len(stamp) != 14 || !allDigits(stamp) {
		return "", false
	}
	if len(hash) != 12 || !plausibleRevision(hash) {
		return "", false
	}
	return hash, true
}

func allDigits(text string) bool {
	for _, r := range text {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(text) > 0
}

// stampFromBuildInfo recovers the link-time Stamp from an artifact's recorded
// -ldflags. The stamp is the only provenance a filesystem-replace build has, so
// this parser is the load-bearing part of the whole check.
//
// It is deliberately strict about which -X assignment it accepts. A match on a
// trailing "msauth.Stamp" would also accept a DIFFERENT module whose path
// merely ends that way, and would report another package's variable as this
// foundation's revision -- a false PASS, which is the direction that costs
// hours rather than minutes. The variable name must equal modulePath+".Stamp"
// exactly.
func stampFromBuildInfo(info *debug.BuildInfo) string {
	const variable = modulePath + ".Stamp"
	stamp := ""
	for _, setting := range info.Settings {
		if setting.Key != "-ldflags" {
			continue
		}
		for _, token := range splitLdflags(setting.Value) {
			name, value, ok := parseXFlag(token)
			if ok && name == variable {
				// Last assignment wins, matching the linker.
				stamp = value
			}
		}
	}
	return stamp
}

// parseXFlag reads one already-dequoted -X token. The linker accepts both
// "-X name=value" (as a single token after splitting, the value form) and
// "-X=name=value", and a value may itself contain "=", so only the FIRST "="
// after the name separates them.
//
// It also accepts the flag and its assignment still joined inside one token,
// as in `"-X github.com/jack-work/msauth.Stamp=abc1234"`. That form reaches
// here because a builder quoted the pair, so splitLdflags kept the space; the
// go command records -ldflags verbatim, and how much quoting survives depends
// on which shell ran the build. Accepting it cannot widen what matches: the
// variable name is still compared for exact equality afterwards.
func parseXFlag(token string) (name, value string, ok bool) {
	assignment := token
	switch {
	case strings.HasPrefix(token, "-X="):
		assignment = strings.TrimPrefix(token, "-X=")
	case strings.HasPrefix(token, "--X="):
		assignment = strings.TrimPrefix(token, "--X=")
	case hasFlagPrefixWithSpace(token, "-X"):
		assignment = strings.TrimLeft(strings.TrimPrefix(token, "-X"), " \t")
	case hasFlagPrefixWithSpace(token, "--X"):
		assignment = strings.TrimLeft(strings.TrimPrefix(token, "--X"), " \t")
	}
	name, value, found := strings.Cut(assignment, "=")
	if !found || name == "" {
		return "", "", false
	}
	return name, value, true
}

// hasFlagPrefixWithSpace reports whether token is the flag followed by at least
// one space or tab, which is the "still joined" form parseXFlag tolerates. It is
// deliberately not a bare strings.HasPrefix: that would also strip the prefix
// from "-Xsomething", which is a different flag.
func hasFlagPrefixWithSpace(token, flag string) bool {
	if !strings.HasPrefix(token, flag) {
		return false
	}
	rest := strings.TrimPrefix(token, flag)
	return strings.HasPrefix(rest, " ") || strings.HasPrefix(rest, "\t")
}

// splitLdflags splits a recorded -ldflags value into tokens, honouring single
// and double quotes and joining a bare "-X" to the token that follows it. Go
// records the flags as one string, so a naive strings.Fields both loses quoted
// values containing spaces and orphans the separated "-X value" form.
func splitLdflags(value string) []string {
	var tokens []string
	var current strings.Builder
	quote := rune(0)
	started := false

	flush := func() {
		if started {
			tokens = append(tokens, current.String())
			current.Reset()
			started = false
		}
	}

	for _, r := range value {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
			started = true
		case r == '\'' || r == '"':
			quote = r
			started = true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			current.WriteRune(r)
			started = true
		}
	}
	flush()

	// Join the separated form: a bare "-X" followed by its assignment.
	joined := make([]string, 0, len(tokens))
	for index := 0; index < len(tokens); index++ {
		if (tokens[index] == "-X" || tokens[index] == "--X") && index+1 < len(tokens) {
			joined = append(joined, tokens[index+1])
			index++
			continue
		}
		joined = append(joined, tokens[index])
	}
	return joined
}
