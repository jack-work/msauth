# msauth

`msauth` is the shared Microsoft Entra authentication foundation for local CLI tools.
It owns the managed-device-specific behavior that must not drift across clients:

- one token-request model with explicit scope or audience semantics;
- WAM-first acquisition with explicit WAM-only and Azure CLI-only policies;
- tenant and client selection as configuration, not compiled-in constants;
- per-client, per-tenant, per-scope refresh and caching rules, with an explicit
  namespace for callers that hold more than one identity;
- current-user DPAPI protection for the Windows disk cache;
- protected storage that adapters reuse for the service bearers they issue;
- capability negotiation so a client can tell an old binary from a bad request;
- sanitized diagnostics and stable error codes.

It deliberately does **not** know about Microsoft Graph, SharePoint, Teams Skype-token
exchange, IcM STS exchange, or product APIs. Those remain adapters in capability tools.

## Go API

```go
provider, err := msauth.NewForClient("office")
if err != nil { /* handle */ }
result, err := provider.Acquire(ctx, msauth.TokenRequest{
    Audience: "https://graph.microsoft.com",
    Policy:   msauth.PolicyWAMFirst,
})
```

Exactly one of `Scope` or `Audience` is required. An audience is normalized to its
`/.default` scope. One request represents one resource; mixed-resource or whitespace-
separated scopes are rejected. Cached tokens are reused only while more than two minutes
remain unless `ForceRefresh` is set.

Policies:

- `wam-first` (default): WAM, then Azure CLI fallback;
- `wam-only`: for adapters such as IcM whose first-party client relationship cannot fall back;
- `azure-cli-only`: for workloads intentionally bound to the current Azure CLI login.

Known clients are `office`, `teams`, and `azure-cli`, and those are defaults rather than
limits — see Configuration below. `NewForClient("")` selects the configured default
client, and a bare application GUID may be used as a client name.

## Configuration

Tenant and client selection is configuration. The identifiers this package ships with are
publicly documented and carry no credential, but they are still choices, and a caller in a
different tenant, or one who registered their own application, must be able to override
them without editing this package or rebuilding every client that links it. That need is
why forks of this package existed.

Resolution order, lowest precedence first:

1. the built-in defaults;
2. the JSON config file — `MSAUTH_CONFIG`, else `auth.json` beside the token cache;
3. `MSAUTH_TENANT` and `MSAUTH_CLIENT`;
4. explicit arguments: a named client, `tenant` in the protocol, `Provider` fields.

Every layer is optional. A machine with no config file and no environment overrides
resolves exactly what this package shipped with, so adding configuration changed no
existing caller's behavior.

```json
{
  "tenant": "00000000-0000-0000-0000-000000000000",
  "defaultClient": "office",
  "clients": [
    { "name": "office", "id": "<your registration>", "broker": true },
    { "name": "internal", "id": "<another>", "broker": false }
  ]
}
```

An entry whose name matches a built-in replaces it; any other entry is appended. A client
with no explicit `defaultPolicy` derives one from `broker`, so a client that cannot use
the broker never silently attempts it.

A missing config file is not an error, because the defaults are usable as shipped. A
**malformed** one is, and it does not degrade into "authenticate with the defaults":
silently authenticating against an unintended tenant as an unintended application is
worse than failing. The diagnostic paths never fail — `msauth config` and `msauth doctor`
report the fault as a field, and `capabilities` reports `tenant`, `defaultClient` and
`configPath` so a non-Go client can see what a build resolved without acquiring a token.

The wire protocol still requires an explicit `client` on `acquireToken`, even though the
Go API accepts an empty name. A request crossing a process boundary without naming its
client is a bug far more often than it is an intent.

## Identifying the linked foundation

`msauth.Version()` reports the msauth code in a binary, and `capabilities`,
`msauth doctor` and every client that surfaces it report the same string. It never
returns a value that identifies no code.

A client that links this package through a filesystem `replace` directive gets no
usable version from Go: the module has no released version and the build info records
the replacement as the literal `(devel)`. Such a client should stamp the foundation at
link time:

```
STAMP=$(git -C ../msauth rev-parse --short HEAD)
[ -z "$(git -C ../msauth status --porcelain)" ] || STAMP="$STAMP+dirty"
go build -ldflags "-X github.com/jack-work/msauth.Stamp=$STAMP"
```

Write it as two statements. The tidier-looking one-liner
`STAMP=$(...)$(git status --porcelain | grep -q . && echo +dirty)` **exits 1 on a clean
tree** — the assignment takes the status of its last substitution, and `grep -q` found
nothing — so under `set -e`, or in an `&&` chain, it aborts the build on exactly the
healthy case. Measured here on 2026-08-02, one commit after this guidance was written.

**Stamp the dirty state, and do not shorten this to `rev-parse --short HEAD`.**
`rev-parse` reports HEAD whatever the worktree contains, so a client built against a
MODIFIED msauth is stamped with a clean revision whose content it does not carry, and
every freshness check in the estate then *passes* on it. That is strictly worse than a
stale artifact, because a stale one is detectable — an artifact that misreports itself
is not. The estate came within one build of shipping exactly that on 2026-08-02, when a
remediation run edited this module while a discovery run was rebuilding clients against
it; it was avoided only by committing first, which is a habit rather than a mechanism.
Nothing in this package can enforce it: the stamp is whatever the builder passes, and
`Version()` can only see `vcs.modified` for the MAIN module, which is never msauth in a
client build.

`Version()` then reports `replaced+<commit>`; an unstamped build reports
`replaced=../msauth`, which names the directory and honestly admits the build is
reproducible on one machine only. A real module version always wins over the stamp, so
the crutch disappears by itself once this module has a remote and tags — which is the
actual fix, and is still outstanding.

Do not invent a per-client `-X` variable for this. Four clients did, and produced four
different answers to one question.

## Auditing installed artifacts: the delivery step

Stamping identifies a foundation. It does not deliver one. The two linkage styles have
different fix-propagation semantics, and only one of them self-heals:

| Linkage | Example | What happens when msauth is fixed |
|---|---|---|
| subprocess (`msauth.exe` on PATH) | icy | inherits the fix the moment the binary is replaced |
| Go library (`replace` directive) | goop, jacques, tomb, divest | inherits **nothing** until someone rebuilds it |

Between 2026-07-28 and 2026-08-02 convergence was declared five times and delivered to
exactly one of five clients — the only one that ships no binary at all. `msauth audit`
is the missing step:

```
msauth audit --required $(git -C ~/dev/msauth rev-parse --short HEAD) \
  ~/bin/tomb.exe ~/go/bin/jacques.exe ~/go/bin/divest.exe ~/dev/goop/loop.exe
```

It reads each artifact's build metadata with `debug/buildinfo` and **never runs it**.
Executing an authenticated tool to ask its version is the wrong instrument twice: it can
trigger a real credential acquisition, and a tool too broken to start is exactly the one
whose provenance you most need. It exits non-zero and prints a rebuild list when any
artifact fails. The same answer is on the wire for non-Go callers as the `auditArtifact`
operation, and `AuditArtifacts` is the Go API; a test asserts all three agree byte for
byte, because a check whose value is being identical everywhere must not be reimplemented
per client.

Two traps this encodes, both learned the expensive way:

1. **"Does the artifact match its own source" is the wrong question.** On 2026-08-02
   tomb's installed binary matched tomb HEAD exactly and still carried a foundation five
   commits stale. Every gate anyone had proposed passed on it. The question is whether the
   artifact carries the foundation its source was *written against*, which is why
   `--required` is an argument rather than something inferred from the artifact.
2. **A dirty stamp fails, and a clean one proves nothing.** `+dirty` names a revision
   whose content the artifact does not carry, so it is a `dirty` verdict, not a pass. Its
   *absence* is never treated as evidence of cleanliness: the stamp is whatever the
   builder passed, and this package cannot see the tree a client was built from.

Verdicts: `current` (the only pass), `stale`, `dirty`, `unstamped` (linked by `replace`
with no stamp — unauditable, not merely old), `unlinked` (does not reference msauth at
all: the client still carries its own auth implementation), `unreadable` (absent, or not
a Go binary — a path typo must never read as a pass).

### The client-side gate

**The floor is the COMPILE floor**: the oldest foundation revision this client's source
can be built against. It moves when the client starts depending on new foundation API,
and not otherwise. Four clients adopted this convention on 2026-08-04 and immediately
split two ways, half of them declaring the revision they had last been *verified*
against; that reading is rejected, because it makes every foundation commit turn every
client's suite red until somebody rebuilds, and a permanently red gate is one people
learn to ignore. "Which artifacts does this commit oblige a rebuild of" is a different
question with its own answer (`--fleet`, below). The cost is real and deliberate: a
foundation *security* fix does not move a compile floor and therefore does not turn a
client's gate red. The sweep is the instrument for that; the gate is not.

A client declares the foundation revision its source requires in a `.msauth-floor` file
at its repo root — one git revision, plus `#` comments if you want to say why. The file
carries **no paths**: several of these clients have public remotes, and a machine-specific
install path committed into one of them leaks an internal account name. Artifact paths
belong to the caller, derived from the environment at run time.

A Go client wires the gate into its own test suite, so `go test` fails when the binary a
user actually runs is behind the floor:

```go
gate, err := msauth.LoadGate(repoRoot, installedPath)
report, err := gate.Audit()
if !report.OK {
	t.Fatal(gate.Explain(report))
}
```

A non-Go client gets the identical judgement from the identical code:

```
msauth audit --gate ~/dev/icy "$(command -v msauth.exe)"
```

`LoadGate` finds the foundation worktree the way every client links it — a sibling
directory named `msauth`, matching the `../msauth` replace directive — and falls back to
exact equality, saying so, when there is none. A missing floor file, an empty one, or a
gate naming no artifact is an **error**: "this client measured nothing" must never render
as a pass, because that is precisely the state the gate exists to end.

`Explain` renders the failure with the remedy, and the remedy lives here rather than in
four client repositories because it is a property of the foundation's build recipe.


#### The fleet list

The client-side gate is one half. The other is the foundation author's: after
committing a change, which installed binaries does it oblige a rebuild of?

```
msauth audit --fleet --required $(git rev-parse --short HEAD)
```

`--fleet` reads a `"fleet"` array of installed artifact paths from the config file
(`msauth config` reports it as a COUNT, never as paths). Machine-specific install paths
belong there and nowhere else: nothing in a client repository may carry them, because
several of those repositories are public. A configured fleet of nothing is an error, not
a pass, and `msauth config` showing `fleet 0` is the honest way to find that out.

#### Exact revision, or a floor

The two gates ask different questions, so `--required` means different things depending
on whether you pass `--foundation`:

| Gate | Command | Question |
|---|---|---|
| fleet delivery sweep | `msauth audit --required <HEAD> ...` | which clients does *this commit* oblige me to rebuild? |
| a client's own gate | `msauth audit --required <floor> --foundation ~/dev/msauth <its artifact>` | is the installed artifact at least as new as the foundation my source was written against? |

A client's gate needs the second: a client rebuilt against something *newer* than its
floor must pass. Two git hashes carry no order, so the floor form reads the foundation's
history (`git merge-base --is-ancestor`, which writes nothing). When it cannot place a
revision — no git, wrong directory, or an artifact built on another machine from a commit
this clone has never seen — it says so, and the audit falls back to **exact equality**,
which is the stricter answer. An ordering that silently stops working can therefore only
produce spurious rebuilds, never a spurious pass. An ordering never rescues an artifact
that failed on provenance: `dirty`, `unstamped` and `unlinked` are decided before any
revision is compared.

`MSAUTH_TENANT`, `MSAUTH_CLIENT` and `MSAUTH_CONFIG` are the configuration surface.
`MSAUTH_BROKER_CLIENT_ID`, `MSAUTH_BROKER_TENANT_ID` and `MSAUTH_BROKER_SCOPE` are this
package's private channel to the PowerShell broker and are not configuration; a test
asserts the two namespaces stay disjoint.

### The WSL branch: reaching the Windows broker from Linux

A broker is a **platform** concept here, not a Windows one. `wam-first` and `wam-only`
are satisfied by WAM on Windows, by the Windows host's broker inside a WSL distro, and
by nothing on bare Linux or macOS — which still degrade to `azure-cli-only`.

This closes a dead end rather than adding a convenience. An account whose passkey is
Windows Hello cannot be satisfied by a Linux browser: Firefox on Linux has no platform
authenticator, its only WebAuthn path is a roaming CTAP2 key over USB HID, and a WSL VM
has no USB at all. The user is asked to touch a key that cannot exist. Meanwhile the
Windows broker is one interop hop away, already holding the signed-in account.

Microsoft ships the bridge: MSAL detects the WSL context and proxies acquisition to the
host through an executable located with `wslinfo --msal-proxy-path`. This package speaks
that protocol directly.

```
$ msauth doctor
broker   WSL bridge to the Windows broker; wam-first and wam-only apply
  msal-proxy-path  /mnt/c/Program Files/WSL/msal.wsl.proxy.exe

$ msauth status --audience https://help.kusto.windows.net
source:  wsl-broker
expires: 2026-08-27T19:47:22Z
```

The source is reported as `wsl-broker`, never as `wam`. They are the same credential
reached by different machinery, and an operator needs to know which hop was involved —
a proxy fault and a WAM fault have different remedies. A cached `wsl-broker` token
satisfies `wam-only`, because it is a broker token.

Acquisition is **silent only**. The host already holds the account and its refresh
material, which is exactly the case Linux could not reach before. An interactive
fallback would put a Windows dialog in front of someone who may be looking at a terminal
on another display; a caller who is genuinely signed out gets an error naming the remedy.

Two things are worth knowing before changing this code:

- **`wsl_proxy_unavailable` is almost always a PATH fault.** `wslinfo` is `/bin/wslinfo`
  → `/init`, and `/bin` is absent from the PATH of D-Bus-activated and systemd-managed
  processes even when a login shell has it. It gets its own error code because it
  otherwise presents as a network failure, which is where an afternoon went before it
  was named.
- **`expiresOn` is epoch milliseconds.** Read as seconds it becomes the year 58620, every
  token looks valid forever, `MinValidity` stops meaning anything, and expired tokens are
  served from cache until something downstream returns 401. `parseWSLExpiry` refuses a
  value too small to be milliseconds rather than reinterpreting it.

The request shape was established by experiment: four flatter arrangements were rejected
with `Invalid requestJson` before the accepted one. Parameters nest under
`authParameters`, the account object appears **both** at the top level and inside it, and
`authorizationType` is `8`. A test asserts that shape, because a wire contract with no
test is a thing someone tidies away.

The unit tests substitute the whole environment, so none of them spawns a Windows binary,
reaches a network, or touches a credential — the suite is identical on a Mac, on CI, and
on the one machine where the real proxy exists. The wire contract itself cannot be proven
that way, so there is an env-gated integration test that acquires a real token and skips
loudly when it cannot:

```bash
MSAUTH_WSL_INTEGRATION=1 go test -run TestWSLBrokerAgainstTheRealProxy -v .
```

### Azure CLI policy properties

The `azure-cli` source always passes `--tenant <TenantID>` to
`az account get-access-token`. A request is therefore pinned to the tenant the caller
asked for, not to whatever tenant `az` currently defaults to. That is deliberate and is
part of the policy contract: two machines with different `az` defaults must resolve the
same request the same way. Callers that need a different tenant must set `TenantID` or
the `tenant` protocol field explicitly.

### Cache namespaces

The cache is keyed by client, tenant, and scope. That triple cannot distinguish two
signed-in identities, so a caller that deliberately runs more than one login — for
example by pointing `AZURE_CONFIG_DIR` at a per-profile directory — must pass a
`CacheNamespace` (`cacheNamespace` in the JSON protocol). It is an opaque, caller-chosen
label of at most 128 bytes with no control characters; msauth gives it no meaning beyond
isolation.

```go
result, err := provider.Acquire(ctx, msauth.TokenRequest{
    Audience:       "https://graph.microsoft.com",
    Policy:         msauth.PolicyAzureCLIOnly,
    CacheNamespace: "sp-profile:contoso",
})
```

Each namespace is a separate protected file, so one identity's cache can be discarded on
its own. The empty namespace is the shared default and keeps its historical cache file.
Without a namespace, such a caller's only safe option is `ForceRefresh` on every request,
which gives up caching and is invisible to the next tool that copies the pattern.

## Stable CLI JSON protocol

Non-Go tools should invoke `msauth request`, write exactly one JSON object to stdin, and
read exactly one response object from stdout. Protocol version 1:

```json
{
  "version": 1,
  "operation": "acquireToken",
  "client": "teams",
  "tenant": "72f988bf-86f1-41af-91ab-2d7cd011db47",
  "audience": "11111111-2222-3333-4444-666666666666",
  "policy": "wam-only",
  "refresh": false
}
```

Success includes `ok: true` and `result.accessToken` plus non-secret metadata. Failure
includes `ok: false` and a stable error with `code`, `message`, and sanitized per-source
`attempts`. The process exits nonzero on failure, but the JSON response remains the
machine contract. Never log or persist `result.accessToken` outside a protected cache.

## Capability negotiation

A non-Go client invokes `msauth` as a separate process resolved by `PATH`, so the client
and the binary version independently. An operation or field added later within protocol
v1 is not discoverable from the version number alone, and without a probe a client cannot
tell *your msauth is too old* from *your request is wrong*.

```json
{"version": 1, "operation": "capabilities"}
```

The response carries `capabilities` with `protocolVersion`, `operations`, `policies`,
`clients`, `requestFields`, `module`, and `version`. It performs no authentication,
touches no cache, and answers at **any** requested protocol version, so a client built
for a later protocol can still ask this build what it speaks. `msauth capabilities`
prints the same document for humans.

Three error codes mean version skew rather than a bad request:

| Code | Raised when |
|------|-------------|
| `unsupported_version` | The request's protocol version is not this build's |
| `unsupported_operation` | This build does not implement the named operation |
| `unsupported_field` | This build does not decode the named request field |

Each message names the rejected input, the msauth version that rejected it, and what that
build does support. The recommended adapter pattern is *lazy* diagnosis: send the real
request, and only if it fails with one of these codes send `capabilities` and report
which build was found and where it came from. That costs nothing on the happy path, and
an msauth too old to answer `capabilities` at all is itself the diagnosis.

## Windows broker selection and `msauth doctor`

The Windows broker runs MSAL inside a PowerShell host and loads its assemblies out of
Az.Accounts. Both halves of that sentence are environment, not code, and both have broken
in production:

- the host was hard-coded to `powershell.exe`, which searches only the Windows PowerShell
  module scopes, so a current Az.Accounts installed in the PowerShell 7 user scope was
  invisible to the very path that needed it;
- the module was chosen by highest version alone, and Az.Accounts 3.0.4 ships
  `Microsoft.Identity.Client.NativeInterop` 0.16.2.0 while its
  `Microsoft.Identity.Client.Broker` binds to 0.16.1.0, so `Add-Type` throws
  `ReflectionTypeLoadException` and every client with `wam-only` policy goes down.

That combination caused a total IcM outage on 2026-07-30, roughly a day after the change
in the environment, because a warm DPAPI cache hid it until the entry expired.

msauth now discovers every Az.Accounts installation on disk — not just the ones on the
spawning host's `PSModulePath` — reads each candidate's shipped and referenced assembly
versions, and selects the newest installation whose assembly set is internally
consistent. Assemblies load from an explicit directory, including the native-interop
dependency, so a module the host cannot *see* is still usable if it is *sound*. When no
candidate is loadable the failure is a stable code (`broker_assembly_mismatch` or
`broker_unavailable`) whose message names each rejected installation, the exact version
disagreement, and the remedy, instead of a PowerShell stack trace.

`MSAUTH_POWERSHELL` pins the host and `MSAUTH_BROKER_MODULE` pins the assembly directory,
so an operator can recover from a bad environment without a rebuild.

```powershell
msauth doctor          # human report; exits nonzero when the environment cannot authenticate
msauth doctor --json   # the same report as JSON
```

`doctor` reports the msauth build, the cache directory and whether each entry is warm
(paths and timestamps only — protected contents are never opened), every PowerShell host
tried, every Az.Accounts found with its verdict and the reason for a rejection, the
selected module, and a load check that binds the broker extension and stops before any
token is requested. It performs no authentication and no network I/O. Non-Go clients get
the same report from the `diagnose` protocol operation, which answers `ok: true` even
when the environment is unhealthy — health is a field, not an exit status.

## Protected storage for adapter-issued bearers

An adapter that exchanges an Entra token for a service-issued bearer (icy's IcM STS
token, for example) owns that exchange, but it must not invent its own at-rest
protection. `protectSecret` and `openSecret` seal and unseal opaque bytes with the same
current-user DPAPI protection msauth uses for its own cache. msauth never parses the
payload and learns no service semantics.

```json
{"version": 1, "operation": "protectSecret", "path": "C:\\Users\\me\\.icm\\icm_token.json", "secret": "<base64>"}
{"version": 1, "operation": "openSecret",    "path": "C:\\Users\\me\\.icm\\icm_token.json"}
```

`protectSecret` reports `secret.bytes` and never echoes the payload. `openSecret`
returns standard base64 in `secret.secret`. A path with no stored secret, and a legacy
unprotected file left by an earlier prototype, both fail with code `not_found`: the
legacy file is removed rather than read, so the adapter re-acquires instead of
inheriting unprotected credential material. Token-acquisition fields and
protected-secret fields may not be mixed in one request. The Go API is
`msauth.ProtectSecret` and `msauth.OpenSecret`.

`openSecret` also dates the secret when it can. If the sealed bytes are a JWT with an
`exp` claim, the response carries `secret.expiresAt` (RFC 3339) and, when that expiry is
within the foundation's `DefaultMinValidity`, `secret.stale: true`. **The absence of
`expiresAt` means this build could not date the secret — never that it is fresh**, so an
adapter that requires an expiry must treat a missing `expiresAt` as unusable. This
exists so a non-Go adapter never decodes a JWT or maintains a refresh skew of its own:
icy kept both, and its 120-second skew governed the same chain as `DefaultMinValidity`
and agreed with it only by coincidence. Reading the standard `exp` claim of a JWT is not
service semantics; what the bearer authorizes still belongs entirely to the adapter.
The Go API for the same reading is `msauth.TokenClaims` / `msauth.TokenExpiry`.

## Inspecting a token the caller already holds

`openSecret` dates a bearer msauth sealed. `inspectToken` describes any JWT the caller
has, including a service bearer msauth never issued and cannot re-issue — icy's IcM STS
token is the reference case, and no `acquireToken` result can describe it.

```json
{"version": 1, "operation": "inspectToken", "token": "<jwt>"}
```

```json
{"version":1,"ok":true,"inspection":{
  "claims":{"userPrincipalName":"user@contoso.com","tenantId":"...","audience":"...","expiresAt":"..."},
  "rawClaims":{"upn":"user@contoso.com","amr":["pwd","mfa"],"exp":1785712345},
  "stale":false}}
```

`claims` is the same registered-claim set `msauth.TokenClaims` returns. `rawClaims` is
the entire payload, each value exactly as the issuer wrote it, so a client that shows a
user *every* claim (`icy token --decode`) does not need a decoder for that one command —
which is how a private decoder survives an otherwise complete convergence. `stale` uses
the foundation's `DefaultMinValidity`, so an adapter never maintains a refresh margin of
its own; its absence, like `openSecret`'s, asserts nothing.

**The operation authenticates nothing, caches nothing, and writes nothing**, so it still
answers while the broker is broken. It rejects a container that merely wraps a JWT with
code `not_a_token`, for the reason `TokenClaims` documents, and it does **not** quote the
rejected value back: that value is the one field of this protocol that may be a live
credential. Send it on stdin with the rest of the request and never as an argument —
argv is readable by other processes on the machine.

Read `rawClaims`, not `claims`, when the point is to show a user what a token says.
`claims` is a fixed struct: it models `audience` as one string, so a two-audience token
reports one of them; it omits empty fields entirely rather than emitting `""`; and it
will never carry `iss`, `preferred_username`, or a URI-named claim such as
`http://sts.msft.net/user/upn`. All three cost a real client real output — measured on
the live IcM STS bearer, whose 30 claims include 3 URI-named ones and whose `aud` array
would have lost `https://prod.microsofticm.com` had icy read the typed field.

### An older msauth reports `unsupported_field`, not `unsupported_operation`

A new operation that carries a new request field is rejected by an older build on the
**field**, because the command decodes stdin with `DisallowUnknownFields` before the
protocol executor ever sees the operation name. Measured against the immediately
previous build: `{"operation":"inspectToken","token":"..."}` answers
`unsupported_field: request field "token" is not supported by msauth <version>;
supported fields are ...`, and never mentions `inspectToken` at all.

So a client's version-skew handling must treat **all three** of `unsupported_version`,
`unsupported_operation` and `unsupported_field` as skew (`UnsupportedCodes()` returns
exactly those). A client that watches only for `unsupported_operation` will report a
genuinely old msauth as a malformed request of its own — which is the failure mode this
whole family of codes was introduced to prevent.

## Shared helpers for adapters

Three things every adapter needed, which four of them therefore wrote four times:

| Go API | Replaces |
|--------|----------|
| `msauth.FormatError(headline, err)` | jacques `auth.FormatError`, divest `newAuthError`, goop `Error.Error`, icy `_msauth_failure_text` |
| `msauth.FormatErrorLine(headline, err)` | tomb `authDiagnostic` |
| `msauth.TokenClaims(token)` / `msauth.TokenPayload(token)` / `msauth.TokenExpiry(token)` | goop `upnFromJWT`, icy `jwt_payload`/`token_expired`, msauth's own private `jwtExpiry` |
| `msauth.SanitizeDiagnostic(text)` | goop `redact`, icy `_safe_auth_text` |

`FormatError` renders `<headline> [<code>]: <message>` followed by one indented line per
attempted credential source, and passes foreign errors through, so a caller can route
every failure through it without classifying it first. `Hint(err)` returns the single
remediation implied by the codes — `Run: msauth doctor` for a broken broker environment,
`Run: az login` for a cold CLI, and `""` when this package cannot name one, because a
hint that sends a signed-in user to re-run an irrelevant login is worse than silence.

`TokenClaims` reads registered, non-secret claims only, and the token is deliberately not
a field of the result. **The signature is not verified and cannot be**: a public client
holds no issuer key. The claims are usable for cache lifetime, diagnostics, and display,
and are not usable as an authorization decision. `TokenPayload` returns the remaining
claims verbatim for the caller that must show all of them.

`FormatErrorLine` is the same rendering on one line, joining attempts with `; `. It
exists because the indented form cannot go in a structured-log attribute or a span error
without breaking line-oriented consumption, which is precisely why tomb kept a private
renderer through four convergences. Both forms read the same fields in the same order and
differ only in the separator; a test asserts one is the other with the separator swapped,
so they cannot drift. The line form additionally guarantees no newline survives, even
from a foreign error carrying a stack trace.

A persistence failure returns code `protect_failed` and must stay visible to the
operator; silently degrading to no caching is how a broken cache goes unnoticed for
weeks.

## Failure responses carry the rendering, not just the parts

A non-Go client cannot call `FormatError` or `Hint` — they are ordinary Go functions
with no operation of their own — so every failure response also carries:

```json
{"version":1,"ok":false,
 "error":{"code":"acquisition_failed","message":"...","attempts":[...]},
 "display":"[acquisition_failed]: ...\n  wam [broker_assembly_mismatch]: ...",
 "hint":"Run: msauth doctor"}
```

`display` is `FormatError("", error)` and `hint` is `Hint(error)`. A client SHOULD
print `display`, optionally prefixed with what it was doing, rather than composing its
own line from `code`, `message`, and `attempts[]`; `error` stays populated so a client
that needs to branch on a code still can. Both fields are absent on success, so
presence is testable rather than being an empty string that also means success.

Human-oriented commands remain available:

```powershell
msauth clients
msauth config
msauth capabilities
msauth doctor
msauth status --client office --audience 'https://graph.microsoft.com'
msauth token --client office --audience 'https://graph.microsoft.com'
```

On Windows, bearer caches under `%APPDATA%\msauth` are encrypted with current-user
DPAPI. On other platforms, persistent bearer caching is disabled.

## Error codes

| Code | Meaning |
|------|---------|
| `invalid_request` | The request violates the protocol contract |
| `unsupported_version` | This build does not speak the requested protocol version |
| `unsupported_operation` | This build does not implement the requested operation |
| `unsupported_field` | This build does not decode a field the request carries |
| `acquisition_failed` | No permitted source produced a token; see `attempts` |
| `wam_unavailable` | The broker cannot run in this environment |
| `broker_unavailable` | No PowerShell host or no Az.Accounts to load the broker from |
| `broker_assembly_mismatch` | Az.Accounts is installed but its MSAL assembly set cannot load |
| `wam_failed` | The broker ran and refused |
| `wsl_proxy_unavailable` | The WSL bridge to the Windows broker could not be located; usually `wslinfo` is not on PATH |
| `wsl_broker_failed` | The WSL bridge worked and the Windows broker declined |
| `azure_cli_failed` | The Azure CLI ran and refused |
| `protect_failed` | Protected storage could not seal or unseal |
| `not_found` | No protected secret is stored at the path |
| `internal_error` | Unexpected failure |

The three `unsupported_*` codes are the version-skew family: they mean the client and the
binary disagree about the protocol, not that the request was malformed. `invalid_request`
is reserved for a request this build understands and rejects.
