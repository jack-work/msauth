//go:build linux

package msauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// The Linux protected store: the freedesktop Secret Service, reached through
// libsecret's secret-tool.
//
// WHY THIS EXISTS. cache_other.go refuses to persist anything, on the grounds
// that a bearer token written without an OS-bound protection primitive is
// credential sprawl. That reasoning is sound and is kept for platforms that
// have no such primitive. Linux does have one: the Secret Service stores
// secrets encrypted under a keyring that a session unlocks, and reaches them
// over the session bus rather than the filesystem, which is the same shape of
// guarantee DPAPI gives on Windows.
//
// The cost of not having it is not theoretical. Every msauth-backed one-shot
// process re-acquired from scratch: measured 2026-09-08, a native `icy me` on
// this box took ~6s and `icy mine` ~8.4s against ~2.2s for the same commands
// when Windows DPAPI was doing the sealing, because both the upstream token and
// the service bearer had to be re-fetched on every invocation.
//
// WHY secret-tool AND NOT A D-BUS LIBRARY. msauth's go.mod carries no direct
// dependencies at all, and it is the shared foundation that jacques, tomb and
// the NixOS flake all link. A keyring library would be the first, and would
// land in every one of those closures. Spawning a helper is also the pattern
// this package already uses for the two other credential paths it does not
// implement in-process: msal.wsl.proxy.exe for the WSL broker and az for the
// Azure CLI. So the helper stays a process and the module stays dependency free.
//
// WHY THE PATH ARGUMENT SURVIVES. writeProtected and readProtected are a
// platform seam with a path-shaped signature, because Windows really does write
// a file. Nothing is written here; the path is hashed into a lookup attribute so
// that callers (cache.go, secrets.go) need no change and every namespace keeps
// its own item. The path is also still used for one filesystem operation: an
// older build, or a copy of this cache from a machine that had no Secret
// Service, may have left a plaintext file exactly there. It is removed rather
// than read, which is what cache_windows.go does with the same case.

// secretToolCommand is the helper this file spawns. It is a variable, not a
// constant, so tests can point it at a stub and never touch the real keyring.
var secretToolCommand = "secret-tool"

// errNoSecretService reports a host with no reachable Secret Service. Callers
// treat any write failure as "keep the in-memory cache", which is exactly the
// behaviour of cache_other.go, so a machine without a keyring degrades to the
// old semantics instead of failing an acquisition.
var errNoSecretService = errors.New("no reachable Secret Service; persistent token cache disabled")

// secretAttributes derives the lookup attributes for one cache path.
//
// The absolute path is hashed rather than stored, for the same reason
// Provider.cachePath hashes client and tenant into its filename: the attribute
// is an index, and an index has no business carrying an account identifier that
// anything reading the keyring can see.
func secretAttributes(path string) []string {
	sum := sha256.Sum256([]byte(path))
	return []string{"service", "msauth", "cache", hex.EncodeToString(sum[:])}
}

// removeLegacyPlaintext deletes an unprotected cache file left at path by an
// earlier build. Mirrors the '{' check in cache_windows.go: a JSON file there
// is a prototype artifact, not something to read.
func removeLegacyPlaintext(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return false
	}
	if data[0] != '{' {
		return false
	}
	_ = os.Remove(path)
	return true
}

func writeProtected(path string, plain []byte) error {
	// A file at this path can only be a legacy artifact now, protected or not,
	// because this platform stores nothing on disk. Remove it either way.
	_ = os.Remove(path)

	attributes := secretAttributes(path)
	if len(plain) == 0 {
		// An empty payload means "forget this cache". Clearing a missing item is
		// not an error, so a failure here is a real one worth reporting.
		if err := runSecretTool(nil, append([]string{"clear"}, attributes...)...); err != nil {
			return fmt.Errorf("clear token cache from the Secret Service: %w", err)
		}
		return nil
	}

	arguments := append([]string{"store", "--label=msauth token cache"}, attributes...)
	if err := runSecretTool(plain, arguments...); err != nil {
		return fmt.Errorf("store token cache in the Secret Service: %w", err)
	}
	return nil
}

func readProtected(path string) ([]byte, error) {
	if removeLegacyPlaintext(path) {
		return nil, errLegacyPlaintext
	}

	out, err := outputSecretTool(append([]string{"lookup"}, secretAttributes(path)...)...)
	if err != nil {
		// secret-tool exits nonzero for "no such item" and for a dead bus alike,
		// and the two are the same answer to the caller: nothing to read. A cold
		// cache is not a failure, so this must return ErrNotExist rather than a
		// wrapped error, which is what loadCache treats as "acquire instead".
		return nil, os.ErrNotExist
	}
	if len(out) == 0 {
		return nil, os.ErrNotExist
	}
	return out, nil
}

// runSecretTool spawns the helper with plain on stdin and discards its output.
var runSecretTool = func(stdin []byte, args ...string) error {
	command := exec.Command(secretToolCommand, args...)
	if stdin != nil {
		command.Stdin = strings.NewReader(string(stdin))
	}
	output, err := command.CombinedOutput()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return errNoSecretService
		}
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// outputSecretTool spawns the helper and returns its stdout verbatim.
//
// Verbatim matters: secret-tool round-trips the stored bytes exactly, adding no
// trailing newline of its own (measured 2026-09-09, "abc" returns "abc" and
// "abc\n" returns "abc\n"). Trimming here would silently corrupt any secret
// whose last byte is whitespace, and secrets.go seals raw bearer tokens through
// this same primitive.
var outputSecretTool = func(args ...string) ([]byte, error) {
	command := exec.Command(secretToolCommand, args...)
	out, err := command.Output()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, errNoSecretService
		}
		return nil, err
	}
	return out, nil
}

// protectedSize reports the size of the stored payload without reading it into
// the caller's hands and without the purge that readProtected performs.
//
// diagnostics.go advertises itself as a read-only report, and on this platform
// the cache is not a file, so a stat-based check would report every warm cache
// as cold. That is precisely the "a warm cache is why a broken broker can stay
// invisible" trap CacheEntryReport was written to avoid, inverted.
func protectedSize(path string) (int64, bool) {
	out, err := outputSecretTool(append([]string{"lookup"}, secretAttributes(path)...)...)
	if err != nil || len(out) == 0 {
		return 0, false
	}
	return int64(len(out)), true
}
