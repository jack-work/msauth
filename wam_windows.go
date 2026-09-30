package msauth

// Kept as an embedded command rather than a sidecar file so every consumer gets
// the same WAM behavior. PowerShell is used only at the Windows broker boundary.
//
// The script no longer discovers Az.Accounts itself. Discovery and the
// consistency rule live in Go (broker.go) where they are unit-testable and
// where a rejected module produces a stable error code instead of a
// ReflectionTypeLoadException whose default message names nothing useful. The
// script is told exactly which directory to load from, and loads the broker's
// native-interop dependency explicitly rather than hoping the loader finds it.
const wamScript = `$ErrorActionPreference = 'Stop'
$ClientId = $env:MSAUTH_BROKER_CLIENT_ID
$TenantId = $env:MSAUTH_BROKER_TENANT_ID
$Scope = $env:MSAUTH_BROKER_SCOPE
$Dir = $env:MSAUTH_BROKER_DIR
if (-not $ClientId -or -not $TenantId -or -not $Scope) { throw 'msauth broker environment is incomplete' }
if (-not $Dir -or -not (Test-Path -LiteralPath $Dir)) { throw "msauth broker assembly directory is missing: $Dir" }

foreach ($name in @('Microsoft.IdentityModel.Abstractions','Microsoft.Identity.Client','Microsoft.Identity.Client.NativeInterop','Microsoft.Identity.Client.Broker')) {
  $path = Join-Path $Dir ($name + '.dll')
  if (-not (Test-Path -LiteralPath $path)) {
    if ($name -eq 'Microsoft.IdentityModel.Abstractions') { continue }
    throw "msauth broker assembly is missing: $path"
  }
  try {
    Add-Type -Path $path
  } catch [System.Reflection.ReflectionTypeLoadException] {
    $detail = ($_.Exception.LoaderExceptions | ForEach-Object { $_.Message }) | Select-Object -Unique
    throw "msauth broker assembly $name could not load from $Dir : " + ($detail -join ' | ')
  }
}

$builder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($ClientId)
$builder = $builder.WithAuthority("https://login.microsoftonline.com/$TenantId")
$options = [Microsoft.Identity.Client.BrokerOptions]::new(
  [Microsoft.Identity.Client.BrokerOptions+OperatingSystems]::Windows)
[Microsoft.Identity.Client.Broker.BrokerExtension]::WithBroker($builder, $options) | Out-Null
$app = $builder.Build()
if ($env:MSAUTH_BROKER_LOAD_ONLY -eq '1') {
  # Diagnostic mode: prove the assembly set loads and the broker extension
  # binds, then stop. No account is touched and no token is requested.
  [pscustomobject]@{ loaded = $true } | ConvertTo-Json -Compress
  exit 0
}
$result = $app.AcquireTokenSilent(
  [string[]]@($Scope),
  [Microsoft.Identity.Client.PublicClientApplication]::OperatingSystemAccount
).ExecuteAsync().GetAwaiter().GetResult()
[pscustomobject]@{
  accessToken = $result.AccessToken
  expiresOn = $result.ExpiresOn.UtcDateTime.ToString('o')
} | ConvertTo-Json -Compress
`
