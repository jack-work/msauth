package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/jack-work/msauth"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "clients":
		for _, client := range msauth.Clients() {
			fmt.Printf("%-10s %s  %s\n", client.Name, client.ID, client.Description)
		}
	case "config":
		err = configCommand(os.Args[2:], os.Stdout)
	case "capabilities":
		err = json.NewEncoder(os.Stdout).Encode(msauth.Describe())
	case "request":
		err = requestCommand(os.Stdin, os.Stdout)
	case "doctor":
		err = doctorCommand(os.Args[2:], os.Stdout)
	case "audit":
		err = auditCommand(os.Args[2:], os.Stdout)
	case "token", "status":
		err = tokenCommand(os.Args[1], os.Args[2:])
	case "help", "--help", "-h":
		usage(os.Stdout)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "msauth:", err)
		os.Exit(1)
	}
}

func requestCommand(input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(io.LimitReader(input, 1<<20))
	decoder.DisallowUnknownFields()
	var request msauth.ProtocolRequest
	if err := decoder.Decode(&request); err != nil {
		return writeProtocolError(output, decodeError(err))
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return writeProtocolError(output, &msauth.AuthError{
			Code:    msauth.CodeInvalidRequest,
			Message: "request must contain exactly one JSON object",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	response := msauth.ExecuteProtocol(ctx, request)
	if err := json.NewEncoder(output).Encode(response); err != nil {
		return err
	}
	if !response.OK {
		return errProtocol
	}
	return nil
}

var unknownFieldPattern = regexp.MustCompile(`unknown field "([^"]*)"`)

// decodeError separates "this build does not know that field" from "this is not
// a request". A client that added a field for a newer msauth must be able to
// recognize version skew instead of reporting its own request as malformed.
func decodeError(err error) *msauth.AuthError {
	if match := unknownFieldPattern.FindStringSubmatch(err.Error()); match != nil {
		return msauth.UnsupportedFieldError(match[1])
	}
	return &msauth.AuthError{
		Code:    msauth.CodeInvalidRequest,
		Message: "request must be one JSON object",
	}
}

func writeProtocolError(output io.Writer, authErr *msauth.AuthError) error {
	_ = json.NewEncoder(output).Encode(msauth.FailureResponse(authErr))
	return errProtocol
}

var errProtocol = errors.New("request failed")

// configCommand reports where tenant and client selection came from. It is
// non-authenticating and never touches the cache, so it is safe to run while
// diagnosing a failure, and it prints the resolved values rather than the
// compiled-in ones so a stale override is visible.
func configCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("config", flag.ContinueOnError)
	jsonOut := flags.Bool("json", false, "write the configuration report as JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	report := msauth.DescribeConfig()
	if *jsonOut {
		return json.NewEncoder(output).Encode(report)
	}
	state := "absent (built-in defaults apply)"
	if report.Exists {
		state = "present"
	}
	fmt.Fprintf(output, "file     %s  %s\n", report.Path, state)
	fmt.Fprintf(output, "tenant   %s\n", report.TenantID)
	fmt.Fprintf(output, "client   %s (default)\n", report.DefaultClient)
	for _, client := range msauth.Clients() {
		fmt.Fprintf(output, "  %-10s %s  policy %s\n", client.Name, client.ID, client.DefaultPolicy)
	}
	fmt.Fprintf(output, "env      %s, %s, %s\n", msauth.EnvTenant, msauth.EnvClient, msauth.EnvConfigFile)
	if report.Error != "" {
		fmt.Fprintf(output, "ERROR    %s\n", report.Error)
		return errBadConfig
	}
	return nil
}

var errBadConfig = errors.New("the configuration is not usable")

func doctorCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	jsonOut := flags.Bool("json", false, "write the full diagnostic report as JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	diagnostics := msauth.Diagnose(ctx)
	if *jsonOut {
		if err := json.NewEncoder(output).Encode(diagnostics); err != nil {
			return err
		}
	} else {
		writeDoctorReport(output, diagnostics)
	}
	if !diagnostics.Healthy {
		return errUnhealthy
	}
	return nil
}

var errUnhealthy = errors.New("the authentication environment is not usable")

// auditCommand answers "which installed binaries does this foundation change
// oblige me to rebuild". It reads each artifact's build metadata and never
// executes it: running an authenticated tool to ask its version can trigger a
// real credential acquisition, and a tool too broken to start is exactly the
// one whose provenance you most need.
//
// --required takes the revision the artifacts must carry, normally the
// foundation revision the clients' source was written against:
//
//	msauth audit --required $(git -C ~/dev/msauth rev-parse --short HEAD) ~/bin/*.exe
//
// Omitting it audits provenance only, which still fails an artifact that links
// no foundation, carries no stamp, or admits to being built from a dirty tree.
//
// --foundation names the foundation's own git worktree and makes --required a
// FLOOR rather than an exact revision, so a client rebuilt against something
// newer passes. Without it the comparison is exact equality; that is the
// stricter answer, which is the right default for a delivery sweep asking
// "which clients does THIS commit oblige me to rebuild".
func auditCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("audit", flag.ContinueOnError)
	required := flags.String("required", "", "foundation revision the artifacts must carry")
	foundation := flags.String("foundation", "", "foundation git worktree; makes --required a floor rather than an exact match")
	gateDir := flags.String("gate", "", "client directory whose "+msauth.FloorFile+" declares the floor")
	fleet := flags.Bool("fleet", false, "audit the artifacts listed in this machine's msauth config")
	jsonOut := flags.Bool("json", false, "write the audit report as JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	paths := flags.Args()
	if *fleet {
		if len(paths) > 0 {
			return errors.New("--fleet audits the configured artifacts; do not also name paths")
		}
		configured, err := msauth.LoadConfig()
		if err != nil {
			return err
		}
		paths = configured.Fleet
		if len(paths) == 0 {
			return fmt.Errorf("no fleet is configured in %s: add a \"fleet\" array of installed artifact paths. An audit of nothing must not report success", msauth.ConfigPath())
		}
	}
	if len(paths) == 0 {
		return errors.New("name at least one installed binary to audit, or pass --fleet")
	}
	if *gateDir != "" {
		if *required != "" || *foundation != "" {
			return errors.New("--gate reads the floor and the foundation itself; do not also pass --required or --foundation")
		}
		return runGate(*gateDir, paths, *jsonOut, output)
	}
	var order msauth.Ordering
	if *foundation != "" {
		order = msauth.GitAncestry(*foundation)
	}
	report := msauth.AuditArtifactsAtLeast(paths, *required, order)
	if *jsonOut {
		if err := json.NewEncoder(output).Encode(report); err != nil {
			return err
		}
	} else {
		writeAuditReport(output, report)
	}
	if !report.OK {
		return errStaleFoundation
	}
	return nil
}

var errStaleFoundation = errors.New("an installed artifact does not carry the required auth foundation")

// runGate is the client-side gate for a caller that is not a Go program. A Go
// client wires msauth.LoadGate into its own test suite; icy and anything else
// non-Go gets exactly the same judgement, from the same code, through here.
func runGate(clientDir string, artifacts []string, jsonOut bool, output io.Writer) error {
	gate, err := msauth.LoadGate(clientDir, artifacts...)
	if err != nil {
		return err
	}
	report, err := gate.Audit()
	if err != nil {
		return err
	}
	if jsonOut {
		if err := json.NewEncoder(output).Encode(report); err != nil {
			return err
		}
	} else {
		writeAuditReport(output, report)
		if explanation := gate.Explain(report); explanation != "" {
			fmt.Fprint(output, explanation)
		}
	}
	if !report.OK {
		return errStaleFoundation
	}
	return nil
}

// writeAuditReport prints the verdict for every artifact, not only the failing
// ones. A gate that reports only failures cannot be distinguished from a gate
// that measured nothing, which is how a path typo reads as a pass.
func writeAuditReport(output io.Writer, report msauth.AuditReport) {
	required := report.Required
	if required == "" {
		required = "(provenance only; no revision required)"
	}
	fmt.Fprintf(output, "required %s\n", required)
	for _, artifact := range report.Artifacts {
		mark := "ok"
		if !artifact.OK {
			mark = "FAIL"
		}
		carried := artifact.FoundationVersion
		if carried == "" {
			carried = "-"
		}
		fmt.Fprintf(output, "%-4s %-9s %-10s %-28s %s\n", mark, artifact.Verdict, artifact.Linkage, carried, artifact.Path)
		if artifact.Reason != "" {
			fmt.Fprintf(output, "       %s\n", artifact.Reason)
		}
	}
	if len(report.Rebuild) == 0 {
		return
	}
	fmt.Fprintf(output, "rebuild %d artifact(s):\n", len(report.Rebuild))
	for _, path := range report.Rebuild {
		fmt.Fprintf(output, "  %s\n", path)
	}
}

// writeDoctorReport prints every fact needed to explain an auth failure. It is
// deliberately verbose about rejected Az.Accounts installations: "the module
// you updated is not the module your broker loads" is the mistake this report
// exists to make obvious.
func writeDoctorReport(output io.Writer, diagnostics msauth.Diagnostics) {
	fmt.Fprintf(output, "msauth   %s (protocol v%d, %s)\n", diagnostics.Version, diagnostics.ProtocolVersion, diagnostics.OS)
	fmt.Fprintf(output, "tenant   %s (default client %s)\n", diagnostics.Config.TenantID, diagnostics.Config.DefaultClient)
	if diagnostics.Config.Exists {
		fmt.Fprintf(output, "config   %s\n", diagnostics.Config.Path)
	}
	if diagnostics.Config.Error != "" {
		fmt.Fprintf(output, "config   UNUSABLE %s\n", diagnostics.Config.Error)
	}
	fmt.Fprintf(output, "cache    %s\n", diagnostics.CacheDirectory)
	for _, entry := range diagnostics.CacheEntries {
		if entry.Exists {
			fmt.Fprintf(output, "  %-10s %s  %d bytes, written %s\n", entry.Client, entry.Path,
				entry.Bytes, entry.Modified.Local().Format(time.RFC3339))
			continue
		}
		fmt.Fprintf(output, "  %-10s %s  absent (next request acquires)\n", entry.Client, entry.Path)
	}

	if !diagnostics.Broker.Supported {
		fmt.Fprintln(output, "broker   not supported on this OS; azure-cli-only policy applies")
		return
	}
	// Under WSL the broker is the Windows host's, reached over interop, and it
	// has no PowerShell hosts or assembly set to report. Saying which broker is
	// in play matters: "wam failed" and "the WSL bridge failed" have completely
	// different remedies, and the second one is usually PATH.
	if diagnostics.Broker.SelectedHost == "wsl-broker" {
		if diagnostics.Broker.Error != nil {
			fmt.Fprintf(output, "broker   WSL bridge to the Windows broker UNAVAILABLE: %s (%s)\n",
				diagnostics.Broker.Error.Message, diagnostics.Broker.Error.Code)
			return
		}
		fmt.Fprintln(output, "broker   WSL bridge to the Windows broker; wam-first and wam-only apply")
		for name, value := range diagnostics.Broker.Overrides {
			fmt.Fprintf(output, "  %-16s %s\n", name, value)
		}
		return
	}
	for name, value := range diagnostics.Broker.Overrides {
		fmt.Fprintf(output, "override %s=%s\n", name, value)
	}
	for _, host := range diagnostics.Broker.Hosts {
		label := host.Name
		if host.Path != "" {
			label = host.Path
		}
		if host.Error != "" {
			fmt.Fprintf(output, "host     %s: %s\n", label, host.Error)
			continue
		}
		fmt.Fprintf(output, "host     %s (PowerShell %s)\n", label, host.Version)
		for _, module := range host.Modules {
			fmt.Fprintf(output, "  Az.Accounts %-8s %-12s %s\n", module.Version, module.Verdict, module.Directory)
			if module.Reason != "" {
				fmt.Fprintf(output, "      %s\n", module.Reason)
			}
		}
	}
	if diagnostics.Broker.Error != nil {
		fmt.Fprintf(output, "broker   UNUSABLE [%s] %s\n", diagnostics.Broker.Error.Code, diagnostics.Broker.Error.Message)
		return
	}
	if selected := diagnostics.Broker.Selected; selected != nil {
		fmt.Fprintf(output, "selected Az.Accounts %s (%s) via %s\n", selected.Version, selected.Verdict, diagnostics.Broker.SelectedHost)
		fmt.Fprintf(output, "         %s\n", selected.Directory)
		if selected.Reason != "" {
			fmt.Fprintf(output, "         %s\n", selected.Reason)
		}
	}
	if check := diagnostics.Broker.LoadCheck; check != nil {
		if check.OK {
			fmt.Fprintln(output, "load     broker assemblies load and bind (no token requested)")
		} else {
			fmt.Fprintf(output, "load     FAILED %s\n", check.Error)
		}
	}
}

func tokenCommand(command string, args []string) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	client := flags.String("client", "", "client name or application id (default: configured client)")
	tenant := flags.String("tenant", "", "Entra tenant ID (default: configured tenant)")
	scope := flags.String("scope", "", "single OAuth scope")
	audience := flags.String("audience", "https://graph.microsoft.com", "resource audience (converted to /.default)")
	policy := flags.String("policy", "", "wam-first, wam-only, or azure-cli-only (default: client policy)")
	namespace := flags.String("cache-namespace", "", "isolate the cache for one signed-in identity")
	refresh := flags.Bool("refresh", false, "ignore a reusable cached token")
	jsonOut := flags.Bool("json", false, "write result JSON (includes the token for token command)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *scope != "" {
		*audience = ""
	}
	provider, err := msauth.NewForClient(*client)
	if err != nil {
		return err
	}
	if *tenant != "" {
		provider.TenantID = *tenant
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	result, err := provider.Acquire(ctx, msauth.TokenRequest{
		Scope: *scope, Audience: *audience, Policy: msauth.Policy(*policy),
		ForceRefresh: *refresh, CacheNamespace: *namespace,
	})
	if err != nil {
		return err
	}
	if command == "token" && !*jsonOut {
		fmt.Println(result.AccessToken)
		return nil
	}
	if *jsonOut {
		if command == "status" {
			result.AccessToken = ""
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	fmt.Printf("client:  %s\ntenant:  %s\nscope:   %s\nsource:  %s\ncached:  %t\nexpires: %s\n",
		result.ClientID, result.TenantID, result.Scope, result.Source, result.Cached, result.ExpiresAt.Local().Format(time.RFC3339))
	return nil
}

func usage(output io.Writer) {
	fmt.Fprint(output, `msauth - shared Microsoft Entra authentication

Usage:
  msauth clients
  msauth config [--json]                 # resolved tenant/client selection; no sign-in
  msauth capabilities                    # what this build supports, as JSON
  msauth doctor [--json]                 # explain the auth environment; no sign-in
  msauth audit [--required REV] [--foundation DIR] [--json] PATH...
  msauth audit --fleet --required REV [--foundation DIR]   # every configured artifact
  msauth audit --gate CLIENTDIR [--json] PATH...   # judge against the client's .msauth-floor
  msauth request                         # versioned JSON request on stdin/stdout
  msauth status [--client NAME] [--audience URI]
  msauth token  [--client NAME] [--audience URI] [--refresh]

Tenant and client selection is configuration, not code, and resolves from the
built-in defaults, then MSAUTH_CONFIG (default auth.json beside the token
cache), then MSAUTH_TENANT and MSAUTH_CLIENT, then explicit arguments. A bare
application GUID may be used as a client name without any configuration. Run
"msauth config" to see what a build actually resolved.

Non-Go clients should use "msauth request", whose protocol v1 operations are
capabilities, acquireToken, protectSecret, openSecret, diagnose, inspectToken,
and auditArtifact. protectSecret and openSecret give adapters the same current-user
protection for the service bearers they issue. inspectToken reads the claims of
a token the caller already holds -- including a service bearer msauth did not
issue -- so an adapter never needs its own JWT decoder; the token goes in the
stdin JSON and must never be passed as an argument, because argv is readable by
other processes. capabilities answers at any requested protocol version and
performs no authentication, so a client that receives unsupported_version,
unsupported_operation, or unsupported_field can probe it to report exactly which
msauth build it found. The token command is intentionally explicit because its
output is a credential.

doctor reports the PowerShell host, every Az.Accounts installation found, which
one the broker would load and why the others were rejected, whether that
assembly set actually loads, and whether each cache entry is warm. It never
signs in and never touches the network; it exits non-zero when the environment
cannot authenticate. MSAUTH_POWERSHELL pins the host and MSAUTH_BROKER_MODULE
pins the assembly directory.

audit reads each named Go binary's build metadata -- it never runs them -- and
reports which auth foundation each one actually carries. A client that EXECS
this binary self-heals when it is replaced; a client that LINKS the package
freezes the foundation at its own build time, so "the artifact matches its own
source" is the wrong question and a matching artifact can still be many
foundation commits stale. A "+dirty" stamp fails: it names a revision whose
content the artifact does not carry. Its absence proves nothing, because the
stamp is whatever the builder passed.

--fleet audits the artifacts listed under "fleet" in the config file, which is
where machine-specific install paths belong: nothing in a client repository may
carry them, because several of these repositories are public. After committing a
foundation change, "msauth audit --fleet --required $(git rev-parse --short
HEAD)" prints exactly which installed binaries that commit obliges you to
rebuild. A configured fleet of nothing is an error, not a pass.
`)
}
