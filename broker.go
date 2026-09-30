package msauth

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
)

// The four assemblies the WAM broker path loads. Broker and MSAL are required;
// NativeInterop is what MSAL's broker extension P/Invokes into and is the
// assembly whose version drifted in the outage this selection logic prevents.
const (
	assemblyBroker        = "Microsoft.Identity.Client.Broker"
	assemblyMSAL          = "Microsoft.Identity.Client"
	assemblyNativeInterop = "Microsoft.Identity.Client.NativeInterop"
	assemblyAbstractions  = "Microsoft.IdentityModel.Abstractions"
)

// brokerLoadOrder is the order the acquisition script adds the assemblies in.
// Dependencies first so a load failure names the assembly that is actually
// missing rather than the type that could not be created.
var brokerLoadOrder = []string{assemblyAbstractions, assemblyMSAL, assemblyNativeInterop, assemblyBroker}

// EnvPowerShell overrides the host the broker runs in; EnvBrokerModule pins the
// assembly directory and skips discovery entirely. Both exist so an operator can
// recover from a bad environment without a rebuild.
const (
	EnvPowerShell   = "MSAUTH_POWERSHELL"
	EnvBrokerModule = "MSAUTH_BROKER_MODULE"
)

// powerShellHosts are tried in order. powershell.exe is first because it is
// always present on Windows and its .NET Framework loader can read assembly
// references, which is what makes the consistency check possible.
var powerShellHosts = []string{"powershell.exe", "pwsh.exe"}

// candidateHosts lists the PowerShell hosts to try, honoring an operator
// override. Host choice is policy, not an implementation detail: the outage
// this replaces was caused by a hard-coded host that could not see the current
// Az.Accounts.
func candidateHosts() []string {
	if override := strings.TrimSpace(os.Getenv(EnvPowerShell)); override != "" {
		return []string{override}
	}
	return powerShellHosts
}

// brokerSelection is the resolved host and module this process will use.
type brokerSelection struct {
	Host      string
	Inventory BrokerInventory
	Module    BrokerModule
}

// BrokerVerdict classifies one candidate Az.Accounts assembly set.
type BrokerVerdict string

const (
	// VerdictUsable means every assembly the broker references is shipped in
	// the same directory at exactly the referenced version.
	VerdictUsable BrokerVerdict = "usable"
	// VerdictUnverified means the host could not read the broker's references,
	// so consistency is unknown. Such a module is a last resort, never a
	// preference.
	VerdictUnverified BrokerVerdict = "unverified"
	// VerdictIncomplete means a required assembly is absent.
	VerdictIncomplete BrokerVerdict = "incomplete"
	// VerdictInconsistent means a shipped assembly's version does not match the
	// version the broker binds to. Loading it throws
	// ReflectionTypeLoadException at Add-Type time.
	VerdictInconsistent BrokerVerdict = "inconsistent"
)

// BrokerModule is one candidate Az.Accounts installation on disk.
type BrokerModule struct {
	Version       string            `json:"version"`
	ModuleBase    string            `json:"moduleBase"`
	Directory     string            `json:"directory"`
	Shipped       map[string]string `json:"shipped,omitempty"`
	Required      map[string]string `json:"required,omitempty"`
	RequiredError string            `json:"requiredError,omitempty"`

	// Verdict and Reason are filled in by classification, not by the probe.
	Verdict BrokerVerdict `json:"verdict,omitempty"`
	Reason  string        `json:"reason,omitempty"`
}

// BrokerInventory is what one PowerShell host can see. It contains no
// credential material: only module paths and assembly version numbers.
type BrokerInventory struct {
	Host        string         `json:"host"`
	HostVersion string         `json:"hostVersion"`
	Modules     []BrokerModule `json:"modules"`
}

// UnmarshalJSON tolerates Windows PowerShell's ConvertTo-Json, which emits a
// single-element collection as a bare object rather than as an array. Without
// this the whole broker path would break on a machine that happens to have
// exactly one Az.Accounts installation, which is the common case.
func (inventory *BrokerInventory) UnmarshalJSON(data []byte) error {
	var raw struct {
		Host        string          `json:"host"`
		HostVersion string          `json:"hostVersion"`
		Modules     json.RawMessage `json:"modules"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	inventory.Host, inventory.HostVersion, inventory.Modules = raw.Host, raw.HostVersion, nil
	trimmed := bytes.TrimSpace(raw.Modules)
	switch {
	case len(trimmed) == 0, bytes.Equal(trimmed, []byte("null")), bytes.Equal(trimmed, []byte(`""`)):
		return nil
	case trimmed[0] == '[':
		return json.Unmarshal(trimmed, &inventory.Modules)
	case trimmed[0] == '{':
		var single BrokerModule
		if err := json.Unmarshal(trimmed, &single); err != nil {
			return err
		}
		inventory.Modules = []BrokerModule{single}
		return nil
	default:
		return nil
	}
}

// classifyBrokerModule decides whether one candidate can be loaded. It is pure
// so the rule that guards every client's authentication is unit-testable
// without a PowerShell host, an Az.Accounts installation, or a network.
func classifyBrokerModule(module BrokerModule) BrokerModule {
	var missing []string
	for _, name := range []string{assemblyBroker, assemblyMSAL, assemblyNativeInterop} {
		if module.Shipped[name] == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		module.Verdict = VerdictIncomplete
		module.Reason = "does not ship " + strings.Join(missing, ", ")
		return module
	}

	// Deterministic order: a mismatch report must not depend on map iteration.
	var mismatches []string
	for _, name := range brokerLoadOrder {
		required, ok := module.Required[name]
		if !ok || required == "" {
			continue
		}
		if shipped := module.Shipped[name]; shipped != required {
			mismatches = append(mismatches, "ships "+name+" "+shipped+" but its "+assemblyBroker+" binds to "+required)
		}
	}
	if len(mismatches) > 0 {
		module.Verdict = VerdictInconsistent
		module.Reason = strings.Join(mismatches, "; ")
		return module
	}
	if len(module.Required) == 0 {
		module.Verdict = VerdictUnverified
		module.Reason = "assembly references could not be read"
		if module.RequiredError != "" {
			module.Reason += ": " + sanitizeDiagnostic(module.RequiredError)
		}
		return module
	}
	module.Verdict = VerdictUsable
	return module
}

// classifyBrokerModules classifies every candidate and orders them the way
// selection prefers them: usable before unverified, newest first.
func classifyBrokerModules(modules []BrokerModule) []BrokerModule {
	classified := make([]BrokerModule, 0, len(modules))
	for _, module := range modules {
		classified = append(classified, classifyBrokerModule(module))
	}
	sort.SliceStable(classified, func(i, j int) bool {
		left, right := classified[i], classified[j]
		if rank := verdictRank(left.Verdict) - verdictRank(right.Verdict); rank != 0 {
			return rank < 0
		}
		if cmp := compareVersions(left.Version, right.Version); cmp != 0 {
			return cmp > 0
		}
		return left.Directory < right.Directory
	})
	return classified
}

func verdictRank(verdict BrokerVerdict) int {
	switch verdict {
	case VerdictUsable:
		return 0
	case VerdictUnverified:
		return 1
	case VerdictInconsistent:
		return 2
	default:
		return 3
	}
}

// selectBrokerModule picks the module the broker will be loaded from, or
// returns a deterministic, actionable error. The error distinguishes "you have
// no Az.Accounts" from "the Az.Accounts you have cannot load", because those
// have different fixes and a caller must be able to tell them apart without
// parsing a PowerShell stack trace.
func selectBrokerModule(inventory BrokerInventory) (BrokerModule, *AuthError) {
	candidates, err := acceptableBrokerModules(inventory)
	if err != nil {
		return BrokerModule{}, err
	}
	return candidates[0], nil
}

// acceptableBrokerModules returns every candidate worth trying, in preference
// order, so a caller that can verify a candidate (by actually loading it) can
// fall through to the next one instead of committing to the first guess. A
// host that cannot read assembly references -- PowerShell 7 has no
// ReflectionOnly load -- produces only unverified candidates, and on such a
// host guessing once is exactly how the 0.16.1.0/0.16.2.0 mismatch would be
// selected again.
func acceptableBrokerModules(inventory BrokerInventory) ([]BrokerModule, *AuthError) {
	modules := classifyBrokerModules(inventory.Modules)
	var candidates []BrokerModule
	for _, module := range modules {
		if module.Verdict == VerdictUsable || module.Verdict == VerdictUnverified {
			candidates = append(candidates, module)
		}
	}
	if len(candidates) > 0 {
		return candidates, nil
	}
	return nil, rejectionError(modules)
}

// rejectionError explains why nothing was selectable.
func rejectionError(modules []BrokerModule) *AuthError {
	if len(modules) == 0 {
		return &AuthError{
			Code:    CodeBrokerUnavailable,
			Message: "no Az.Accounts installation with MSAL broker assemblies was found; install it with: Install-Module Az.Accounts -Scope CurrentUser",
		}
	}
	rejected := make([]string, 0, len(modules))
	for _, module := range modules {
		rejected = append(rejected, describeRejectedModule(module))
	}
	return &AuthError{
		Code: CodeBrokerAssemblyMismatch,
		Message: "every Az.Accounts installation has an unusable MSAL broker assembly set (" +
			strings.Join(rejected, "; ") +
			"); install a current Az.Accounts with: Install-Module Az.Accounts -Scope CurrentUser",
	}
}

func describeRejectedModule(module BrokerModule) string {
	label := "Az.Accounts"
	if module.Version != "" {
		label += " " + module.Version
	}
	if module.Directory != "" {
		label += " at " + module.Directory
	}
	if module.Reason == "" {
		return label + " is " + string(module.Verdict)
	}
	return label + " " + module.Reason
}

// compareVersions orders dotted numeric versions. Non-numeric segments compare
// as text so an unexpected preview suffix cannot panic the auth path.
func compareVersions(left, right string) int {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	for i := 0; i < len(leftParts) || i < len(rightParts); i++ {
		var leftPart, rightPart string
		if i < len(leftParts) {
			leftPart = leftParts[i]
		}
		if i < len(rightParts) {
			rightPart = rightParts[i]
		}
		leftNumber, leftErr := strconv.Atoi(leftPart)
		rightNumber, rightErr := strconv.Atoi(rightPart)
		if leftErr == nil && rightErr == nil {
			if leftNumber != rightNumber {
				if leftNumber < rightNumber {
					return -1
				}
				return 1
			}
			continue
		}
		if leftPart != rightPart {
			if leftPart < rightPart {
				return -1
			}
			return 1
		}
	}
	return 0
}
