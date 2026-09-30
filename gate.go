package msauth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// A client's DELIVERY GATE is the test that fails when the binary a user
// actually runs does not carry the auth foundation the client's source was
// written against. Four clients asked for one independently on 07-30, 07-31,
// 08-01 and 08-02 and none was built, so this is the shared implementation:
// four repositories writing their own would produce four answers to one
// question, which is exactly how four private -X stamp variables happened.
//
// The client contributes two things and nothing else: a FLOOR file naming the
// foundation revision its source requires, and the paths of its own installed
// artifacts. Everything else -- reading build metadata, ordering revisions,
// judging dirt, wording the failure -- lives here.
//
// THE FLOOR FILE CARRIES NO PATHS. Several of these clients have public
// remotes, and a machine-specific install path committed into one of them
// leaks an internal account name. Artifact paths belong to the caller, which
// can derive them from the environment at run time.

// FloorFile is the conventional name of a client's floor file, at its repo root.
const FloorFile = ".msauth-floor"

// Gate is one client's delivery gate.
type Gate struct {
	// Floor is the foundation revision the client's source requires. An
	// artifact carrying this revision or any later one passes.
	Floor string
	// FoundationDir is the foundation worktree used to order revisions. When
	// empty, the comparison is exact equality, which is stricter.
	FoundationDir string
	// Artifacts are the installed binaries to judge. An empty list is an
	// error, not a pass: a gate that measures nothing must never look healthy.
	Artifacts []string
}

// LoadGate reads clientDir's floor file and returns a gate for the named
// artifacts. It resolves the foundation worktree the way every client in this
// estate links it -- a sibling directory named msauth, matching the ../msauth
// replace directive -- and leaves FoundationDir empty if that is not a
// repository, which downgrades the comparison to exact equality rather than
// skipping it.
func LoadGate(clientDir string, artifacts ...string) (Gate, error) {
	floor, err := ReadFloor(clientDir)
	if err != nil {
		return Gate{}, err
	}
	gate := Gate{Floor: floor, Artifacts: artifacts}
	sibling := filepath.Join(clientDir, "..", "msauth")
	if info, statErr := os.Stat(filepath.Join(sibling, ".git")); statErr == nil && (info.IsDir() || info.Mode().IsRegular()) {
		gate.FoundationDir = sibling
	}
	return gate, nil
}

// ReadFloor reads the foundation revision from clientDir's floor file. A
// missing or empty floor file is an error: "this client declares no floor" is
// the state the gate exists to eliminate, so it must never read as a pass.
func ReadFloor(clientDir string) (string, error) {
	path := filepath.Join(clientDir, FloorFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%s declares no auth foundation floor: create it containing the %s revision this client's source requires", path, modulePath)
		}
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		revision, _, _ := strings.Cut(line, " ")
		if !plausibleRevision(revision) {
			return "", fmt.Errorf("%s: %q is not a foundation revision; the file holds one git revision and optional # comments", path, revision)
		}
		return strings.ToLower(revision), nil
	}
	return "", fmt.Errorf("%s is empty: it must name the %s revision this client's source requires", path, modulePath)
}

// Audit judges the gate's artifacts. It reads them and never runs them.
func (g Gate) Audit() (AuditReport, error) {
	if len(g.Artifacts) == 0 {
		return AuditReport{}, errors.New("this gate names no artifact: a gate that measures nothing must not report success")
	}
	if g.Floor == "" {
		return AuditReport{}, errors.New("this gate declares no floor")
	}
	var order Ordering
	if g.FoundationDir != "" {
		order = GitAncestry(g.FoundationDir)
	}
	return AuditArtifactsAtLeast(g.Artifacts, g.Floor, order), nil
}

// Explain renders a failed audit as the message a client's gate should print.
// It is here rather than in each client because the useful part of the message
// is the REMEDY, and the remedy is a property of the foundation's build recipe,
// not of the client: an artifact fails this gate by being older than the floor,
// and the only fix is a rebuild with the dirty-aware stamp.
func (g Gate) Explain(report AuditReport) string {
	if report.OK {
		return ""
	}
	var message strings.Builder
	fmt.Fprintf(&message, "installed artifact does not carry the required auth foundation (floor %s)\n", g.Floor)
	for _, artifact := range report.Artifacts {
		if artifact.OK {
			continue
		}
		fmt.Fprintf(&message, "  %s: %s\n", artifact.Path, artifact.Reason)
	}
	message.WriteString("rebuild and reinstall it, stamping the foundation revision AND its dirty state:\n")
	message.WriteString("  STAMP=$(git -C <foundation> rev-parse --short HEAD)\n")
	message.WriteString("  [ -z \"$(git -C <foundation> status --porcelain)\" ] || STAMP=\"$STAMP+dirty\"\n")
	message.WriteString("  go build -ldflags \"-X " + modulePath + ".Stamp=$STAMP\"\n")
	if g.FoundationDir == "" {
		message.WriteString("no foundation worktree was found beside this client, so the floor was compared for EXACT equality; a newer foundation would also read as stale here\n")
	}
	return message.String()
}
