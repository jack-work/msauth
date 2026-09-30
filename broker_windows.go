//go:build windows

package msauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// brokerProbeScript inventories every Az.Accounts installation on disk and
// reports assembly versions. It authenticates nothing, opens no cache, and
// makes no network call, so it is safe to run from a diagnostic command.
//
// It deliberately does not use Get-Module -ListAvailable alone. That returns
// only the modules on the spawning host's PSModulePath, which is exactly how
// the 2026-07-30 outage happened: the current Az.Accounts was installed in the
// PowerShell 7 user scope while the broker ran under powershell.exe, which
// cannot see it. The assemblies load fine from any path, so discovery searches
// the well-known roots of both hosts.
const brokerProbeScript = `$ErrorActionPreference = 'Stop'
$roots = New-Object System.Collections.Generic.List[string]
function Add-Root([string]$p) { if ($p -and (Test-Path -LiteralPath $p)) { $roots.Add((Resolve-Path -LiteralPath $p).Path) } }
foreach ($p in ($env:PSModulePath -split ';')) { Add-Root $p }
$docs = [Environment]::GetFolderPath('MyDocuments')
if ($docs) { Add-Root (Join-Path $docs 'PowerShell\Modules'); Add-Root (Join-Path $docs 'WindowsPowerShell\Modules') }
if ($env:ProgramFiles) {
  Add-Root (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
  Add-Root (Join-Path $env:ProgramFiles 'PowerShell\Modules')
  Add-Root (Join-Path $env:ProgramFiles 'PowerShell\7\Modules')
}
$names = @('Microsoft.Identity.Client.Broker','Microsoft.Identity.Client','Microsoft.Identity.Client.NativeInterop','Microsoft.IdentityModel.Abstractions')
$seen = New-Object System.Collections.Generic.HashSet[string]
$referenceCache = @{}
$modules = New-Object System.Collections.Generic.List[object]
foreach ($root in $roots) {
  $moduleRoot = Join-Path $root 'Az.Accounts'
  if (-not (Test-Path -LiteralPath $moduleRoot)) { continue }
  $candidates = @(Get-ChildItem -LiteralPath $moduleRoot -Directory -ErrorAction SilentlyContinue)
  if (-not $candidates) { $candidates = @(Get-Item -LiteralPath $moduleRoot) }
  foreach ($candidate in $candidates) {
    $lib = Join-Path $candidate.FullName 'lib\netstandard2.0'
    if (-not (Test-Path -LiteralPath $lib)) { continue }
    $lib = (Resolve-Path -LiteralPath $lib).Path
    if (-not $seen.Add($lib.ToLowerInvariant())) { continue }
    $shipped = @{}
    foreach ($name in $names) {
      $path = Join-Path $lib ($name + '.dll')
      if (Test-Path -LiteralPath $path) {
        try { $shipped[$name] = [System.Reflection.AssemblyName]::GetAssemblyName($path).Version.ToString() } catch { }
      }
    }
    $required = @{}
    $requiredError = $null
    foreach ($subject in @('Microsoft.Identity.Client.Broker','Microsoft.Identity.Client')) {
      $path = Join-Path $lib ($subject + '.dll')
      if (-not (Test-Path -LiteralPath $path)) { continue }
      $identity = $subject + '|' + $shipped[$subject]
      if (-not $referenceCache.ContainsKey($identity)) {
        try {
          $entry = @{}
          foreach ($reference in [System.Reflection.Assembly]::ReflectionOnlyLoadFrom($path).GetReferencedAssemblies()) {
            if ($names -contains $reference.Name) { $entry[$reference.Name] = $reference.Version.ToString() }
          }
          $referenceCache[$identity] = $entry
        } catch {
          $referenceCache[$identity] = $null
          if (-not $requiredError) { $requiredError = $_.Exception.Message }
        }
      }
      $entry = $referenceCache[$identity]
      if ($null -eq $entry) { continue }
      foreach ($key in $entry.Keys) { $required[$key] = $entry[$key] }
    }
    if ($required.Count -eq 0) { $required = $null }
    $version = $candidate.Name
    if ($version -notmatch '^\d') { $version = '' }
    $modules.Add([pscustomobject]@{
      version = $version
      moduleBase = $candidate.FullName
      directory = $lib
      shipped = $shipped
      required = $required
      requiredError = $requiredError
    })
  }
}
[pscustomobject]@{
  host = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
  hostVersion = $PSVersionTable.PSVersion.ToString()
  modules = $modules.ToArray()
} | ConvertTo-Json -Depth 6 -Compress
`

var (
	brokerMu      sync.Mutex
	brokerCached  *brokerSelection
	brokerCachedE *AuthError
)

// resolveBroker finds a loadable Az.Accounts assembly set once per process.
// The probe costs one short PowerShell start; a warm token never reaches here.
func resolveBroker(ctx context.Context) (*brokerSelection, *AuthError) {
	brokerMu.Lock()
	defer brokerMu.Unlock()
	if brokerCached != nil || brokerCachedE != nil {
		return brokerCached, brokerCachedE
	}
	selection, err := discoverBroker(ctx)
	brokerCached, brokerCachedE = selection, err
	return selection, err
}

func discoverBroker(ctx context.Context) (*brokerSelection, *AuthError) {
	if pinned := strings.TrimSpace(os.Getenv(EnvBrokerModule)); pinned != "" {
		module, err := pinnedBrokerModule(pinned)
		if err != nil {
			return nil, err
		}
		host, hostErr := resolveHost()
		if hostErr != nil {
			return nil, hostErr
		}
		return &brokerSelection{Host: host, Module: module}, nil
	}

	var firstErr *AuthError
	for _, host := range candidateHosts() {
		resolved, lookErr := exec.LookPath(host)
		if lookErr != nil {
			continue
		}
		inventory, probeErr := probeBrokerHost(ctx, resolved)
		if probeErr != nil {
			if firstErr == nil {
				firstErr = probeErr
			}
			continue
		}
		selection, selectErr := selectVerifiedModule(ctx, resolved, inventory)
		if selectErr != nil {
			if firstErr == nil {
				firstErr = selectErr
			}
			continue
		}
		return selection, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, &AuthError{
		Code:    CodeBrokerUnavailable,
		Message: "no PowerShell host was found on PATH; the Windows broker requires powershell.exe or pwsh.exe",
	}
}

// verifyBrokerModule is a seam so the fallback logic can be tested without a
// PowerShell host. It proves a candidate by loading it.
var verifyBrokerModule = func(ctx context.Context, host string, module BrokerModule) error {
	check := brokerLoadCheck(ctx, &brokerSelection{Host: host, Module: module})
	if check.OK {
		return nil
	}
	return errors.New(check.Error)
}

// selectVerifiedModule takes the first candidate whose assembly set is proven
// consistent from metadata, and otherwise proves a candidate by loading it.
//
// The distinction matters on a host that cannot read assembly references at
// all: PowerShell 7 has no ReflectionOnly load, so on a pwsh-only machine every
// candidate is merely "unverified" and picking the newest would happily pick a
// module whose broker binds to an assembly version it does not ship. A load
// probe costs about a second, is paid only when metadata could not decide, and
// requests no token.
func selectVerifiedModule(ctx context.Context, host string, inventory BrokerInventory) (*brokerSelection, *AuthError) {
	candidates, err := acceptableBrokerModules(inventory)
	if err != nil {
		return nil, err
	}
	rejected := make([]BrokerModule, 0, len(candidates))
	for _, module := range candidates {
		if module.Verdict == VerdictUsable {
			return &brokerSelection{Host: host, Inventory: inventory, Module: module}, nil
		}
		if loadErr := verifyBrokerModule(ctx, host, module); loadErr != nil {
			module.Verdict = VerdictInconsistent
			module.Reason = "did not load: " + sanitizeDiagnostic(loadErr.Error())
			rejected = append(rejected, module)
			continue
		}
		module.Reason = "verified by load probe"
		return &brokerSelection{Host: host, Inventory: inventory, Module: module}, nil
	}
	return nil, rejectionError(rejected)
}

func resolveHost() (string, *AuthError) {
	for _, host := range candidateHosts() {
		if resolved, err := exec.LookPath(host); err == nil {
			return resolved, nil
		}
	}
	return "", &AuthError{
		Code:    CodeBrokerUnavailable,
		Message: "no PowerShell host was found on PATH; the Windows broker requires powershell.exe or pwsh.exe",
	}
}

// pinnedBrokerModule accepts either the assembly directory or the module base
// and never fails silently: an operator who pins the wrong path is told which
// path was tried.
func pinnedBrokerModule(path string) (BrokerModule, *AuthError) {
	candidates := []string{path, filepath.Join(path, "lib", "netstandard2.0")}
	for _, candidate := range candidates {
		if _, err := os.Stat(filepath.Join(candidate, assemblyBroker+".dll")); err == nil {
			return BrokerModule{
				Directory: candidate,
				Verdict:   VerdictUnverified,
				Reason:    "pinned by " + EnvBrokerModule,
			}, nil
		}
	}
	return BrokerModule{}, &AuthError{
		Code:    CodeBrokerUnavailable,
		Message: EnvBrokerModule + " does not contain " + assemblyBroker + ".dll: " + path,
	}
}

// ProbeBrokerHost runs the inventory probe in one PowerShell host. It is
// exported for diagnostics; it performs no authentication.
func ProbeBrokerHost(ctx context.Context, host string) (BrokerInventory, error) {
	inventory, err := probeBrokerHost(ctx, host)
	if err != nil {
		return inventory, err
	}
	return inventory, nil
}

func probeBrokerHost(ctx context.Context, host string) (BrokerInventory, *AuthError) {
	cmd := exec.CommandContext(ctx, host, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", brokerProbeScript)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return BrokerInventory{}, &AuthError{
			Code:    CodeBrokerUnavailable,
			Message: "broker inventory failed in " + host + ": " + sanitizeDiagnostic(err.Error()+": "+stderr.String()),
		}
	}
	var inventory BrokerInventory
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &inventory); err != nil {
		return BrokerInventory{}, &AuthError{
			Code:    CodeBrokerUnavailable,
			Message: "broker inventory from " + host + " was not valid JSON: " + sanitizeDiagnostic(err.Error()),
		}
	}
	if inventory.Host == "" {
		inventory.Host = host
	}
	inventory.Modules = classifyBrokerModules(inventory.Modules)
	return inventory, nil
}
