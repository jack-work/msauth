package msauth

import (
	"reflect"
	"runtime/debug"
	"strings"
)

// modulePath is this module's import path. It is used to recover this
// package's own version when msauth is linked into a client binary.
const modulePath = "github.com/jack-work/msauth"

// Capabilities describes what one msauth build supports. Non-Go clients invoke
// msauth as a separate process resolved by PATH, so the client and the binary
// version independently. Without a probe, an operation added later within
// protocol v1 is indistinguishable from a malformed request, and the adapter
// cannot tell "your msauth is too old" from "your request is wrong".
type Capabilities struct {
	ProtocolVersion int      `json:"protocolVersion"`
	Operations      []string `json:"operations"`
	Policies        []string `json:"policies"`
	Clients         []string `json:"clients"`
	RequestFields   []string `json:"requestFields"`
	Module          string   `json:"module"`
	Version         string   `json:"version"`

	// Tenant and DefaultClient report what this build resolved from its
	// configuration, not what it was compiled with. A client that omits the
	// client field gets DefaultClient, so a caller must be able to see which
	// one that is without acquiring a token.
	Tenant        string `json:"tenant"`
	DefaultClient string `json:"defaultClient"`
	ConfigPath    string `json:"configPath"`
}

// Operations lists every operation this build accepts, in protocol order.
func Operations() []string {
	return []string{
		OperationCapabilities,
		OperationAcquireToken,
		OperationProtectSecret,
		OperationOpenSecret,
		OperationDiagnose,
		OperationInspectToken,
		OperationAuditArtifact,
	}
}

// Policies lists every accepted credential-source policy.
func Policies() []string {
	return []string{string(PolicyWAMFirst), string(PolicyWAMOnly), string(PolicyAzureCLIOnly)}
}

// RequestFields lists the JSON field names this build decodes. It is derived
// from the request type so the capability report cannot drift from the decoder.
func RequestFields() []string {
	requestType := reflect.TypeOf(ProtocolRequest{})
	fields := make([]string, 0, requestType.NumField())
	for i := range requestType.NumField() {
		name, _, _ := strings.Cut(requestType.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			fields = append(fields, name)
		}
	}
	return fields
}

// Describe reports this build's capabilities. It performs no authentication,
// touches no cache, and never fails, so an adapter can call it to explain a
// rejection without risking a second failure.
func Describe() Capabilities {
	config := effectiveConfig()
	return Capabilities{
		ProtocolVersion: ProtocolVersion,
		Operations:      Operations(),
		Policies:        Policies(),
		Clients:         config.ClientNames(),
		RequestFields:   RequestFields(),
		Module:          modulePath,
		Version:         Version(),
		Tenant:          config.TenantID,
		DefaultClient:   config.DefaultClient,
		ConfigPath:      ConfigPath(),
	}
}

// Stamp names the msauth source this binary was built from. It exists because
// a client that links this package through a filesystem replace directive gets
// NO usable version from Go: the module has no released version, and the build
// info records the replacement as the literal string "(devel)". Four separate
// clients independently invented their own -X variable to work around that,
// which is four different answers to one question. There is exactly one now.
//
//	go build -ldflags "-X github.com/jack-work/msauth.Stamp=$(git -C ../msauth rev-parse --short HEAD)"
//
// It is only a crutch. The real fix is for this module to have a remote and
// tags, after which the dependency reports its own version and Stamp is unused.
//
// USE THE DIRTY-AWARE FORM. `git rev-parse --short HEAD` reports HEAD whatever
// the worktree contains, so building a client against a MODIFIED msauth stamps
// the artifact with a clean revision whose content it does not carry -- and
// every freshness check in the estate then PASSES on it. That is strictly worse
// than a stale artifact, because a stale one is detectable. Build clients with:
//
//	STAMP=$(git -C ../msauth rev-parse --short HEAD)
//	[ -z "$(git -C ../msauth status --porcelain)" ] || STAMP="$STAMP+dirty"
//	go build -ldflags "-X github.com/jack-work/msauth.Stamp=$STAMP"
//
// Write it as two statements. The one-liner form
// `STAMP=$(...)$(git status --porcelain | grep -q . && echo +dirty)` looks
// tidier and EXITS 1 ON A CLEAN TREE, because the assignment takes the status
// of its last substitution and grep found nothing. In a `set -e` script or a
// `&&` chain that aborts the build on precisely the healthy case.
//
// Nothing here can enforce that: the stamp is whatever the builder passes, and
// this package cannot see the tree it was built from. Version() reports
// vcs.modified for the MAIN module only, which is exactly the module that is
// never msauth in a client build.
var Stamp string

// Version reports the msauth code in this binary, and never reports a string
// that does not identify code. A tagged release reports its tag; a build from
// a working tree reports its VCS revision and whether that tree was dirty; a
// filesystem replace reports the link-time Stamp, or, failing that, the
// directive itself, which is honest about the build being reproducible on one
// machine only.
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return stampedWith("unknown", Stamp)
	}
	return versionFrom(info, Stamp)
}

// versionFrom resolves the msauth version recorded in ONE set of build info,
// given the link-time stamp that build carried. Version() passes its own
// compiled-in Stamp; the artifact auditor in artifact.go passes the stamp it
// recovered from another binary's recorded -ldflags. Both callers therefore
// share one implementation, so an artifact's AUDITED foundation version and the
// version that same artifact REPORTS about itself cannot disagree -- which is
// the whole reason this was factored out rather than reimplemented next door.
func versionFrom(info *debug.BuildInfo, stamp string) string {
	if info == nil {
		return stampedWith("unknown", stamp)
	}
	if info.Main.Path == modulePath {
		return mainVersion(info, stamp)
	}
	for _, dep := range info.Deps {
		if dep.Path != modulePath {
			continue
		}
		if dep.Replace != nil {
			return replacedVersion(dep.Replace, stamp)
		}
		if resolved(dep.Version) {
			return dep.Version
		}
		return stampedWith("unknown", stamp)
	}
	return stampedWith("unknown", stamp)
}

func mainVersion(info *debug.BuildInfo, stamp string) string {
	if resolved(info.Main.Version) {
		return info.Main.Version
	}
	var revision, modified string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}
	if revision == "" {
		return stampedWith("devel", stamp)
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified == "true" {
		return "devel+" + revision + "+dirty"
	}
	return "devel+" + revision
}

// A filesystem replace carries no module version. Go records "(devel)" there,
// which reads like a version and identifies nothing, so it is never reported.
func replacedVersion(replacement *debug.Module, stamp string) string {
	if resolved(replacement.Version) {
		return replacement.Version
	}
	if stamp != "" {
		return "replaced+" + stamp
	}
	if replacement.Path != "" {
		return "replaced=" + replacement.Path
	}
	return "replaced"
}

// resolved reports whether a build-info version string identifies real code.
// The empty string and "(devel)" do not.
func resolved(version string) bool {
	return version != "" && version != "(devel)"
}

// stampedWith appends a link-time stamp to an otherwise uninformative answer,
// so a build that supplies one is never told "unknown".
func stampedWith(base, stamp string) string {
	if stamp == "" {
		return base
	}
	return base + "+" + stamp
}
