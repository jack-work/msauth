//go:build linux

package msauth

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubSecretTool replaces the two helper seams with an in-memory keyring for the
// duration of one test. No test in this package may touch the real Secret
// Service: a developer's own credentials are not test fixtures.
func stubSecretTool(t *testing.T) map[string][]byte {
	t.Helper()

	store := map[string][]byte{}
	realRun, realOutput := runSecretTool, outputSecretTool
	t.Cleanup(func() { runSecretTool, outputSecretTool = realRun, realOutput })

	key := func(args []string) string { return strings.Join(args, "\x00") }

	runSecretTool = func(stdin []byte, args ...string) error {
		switch args[0] {
		case "store":
			// Drop the verb and the label, keep the attribute pairs.
			store[key(args[2:])] = append([]byte(nil), stdin...)
			return nil
		case "clear":
			delete(store, key(args[1:]))
			return nil
		}
		return errors.New("unexpected verb: " + args[0])
	}

	outputSecretTool = func(args ...string) ([]byte, error) {
		value, ok := store[key(args[1:])]
		if !ok {
			return nil, errors.New("no such item")
		}
		return value, nil
	}

	return store
}

func TestSecretServiceRoundTripLeavesNothingOnDisk(t *testing.T) {
	stubSecretTool(t)

	path := filepath.Join(t.TempDir(), "cache.bin")
	plain := []byte(`{"access_token":"not-a-real-token"}`)

	if err := writeProtected(path, plain); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("writeProtected created a file; the Secret Service is the only store on this platform")
	}

	got, err := readProtected(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

// A bearer token is sealed through this same primitive (secrets.go), so a
// payload whose last byte is whitespace must survive byte for byte. Trimming
// would corrupt a credential rather than fail loudly.
func TestSecretServicePreservesTrailingWhitespace(t *testing.T) {
	stubSecretTool(t)

	path := filepath.Join(t.TempDir(), "cache.bin")
	plain := []byte("token-with-trailing-newline\n")

	if err := writeProtected(path, plain); err != nil {
		t.Fatal(err)
	}
	got, err := readProtected(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("payload was altered: %q", got)
	}
}

func TestSecretServiceMissingItemIsColdNotFailure(t *testing.T) {
	stubSecretTool(t)

	_, err := readProtected(filepath.Join(t.TempDir(), "absent.bin"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing item must read as ErrNotExist so loadCache re-acquires, got %v", err)
	}
}

func TestSecretServiceEmptyPayloadClearsTheItem(t *testing.T) {
	store := stubSecretTool(t)

	path := filepath.Join(t.TempDir(), "cache.bin")
	if err := writeProtected(path, []byte(`{"access_token":"x"}`)); err != nil {
		t.Fatal(err)
	}
	if len(store) != 1 {
		t.Fatalf("expected one stored item, got %d", len(store))
	}
	if err := writeProtected(path, nil); err != nil {
		t.Fatal(err)
	}
	if len(store) != 0 {
		t.Fatalf("empty payload must clear the item, %d left", len(store))
	}
	if _, err := readProtected(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleared item must read cold, got %v", err)
	}
}

// Namespaced caches must not collide: Provider.cachePath gives each namespace
// its own file name, and each must map to its own keyring item.
func TestSecretServiceSeparatesPaths(t *testing.T) {
	stubSecretTool(t)

	dir := t.TempDir()
	first, second := filepath.Join(dir, "a.bin"), filepath.Join(dir, "b.bin")

	if err := writeProtected(first, []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	if err := writeProtected(second, []byte("beta")); err != nil {
		t.Fatal(err)
	}

	got, err := readProtected(first)
	if err != nil || string(got) != "alpha" {
		t.Fatalf("first path returned %q, %v", got, err)
	}
	got, err = readProtected(second)
	if err != nil || string(got) != "beta" {
		t.Fatalf("second path returned %q, %v", got, err)
	}
}

// An unprotected file from an older build is removed rather than read, the same
// decision cache_windows.go makes for the same case.
func TestSecretServicePurgesLegacyPlaintext(t *testing.T) {
	stubSecretTool(t)

	path := filepath.Join(t.TempDir(), "cache.bin")
	if err := os.WriteFile(path, []byte(`{"access_token":"leaked"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := readProtected(path)
	if !errors.Is(err, errLegacyPlaintext) {
		t.Fatalf("expected errLegacyPlaintext, got %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("legacy plaintext file survived the read")
	}
}

// A host with no secret-tool degrades to the old behaviour: nothing persists and
// the caller keeps its in-memory cache, rather than an acquisition failing.
func TestSecretServiceAbsentHelperDegrades(t *testing.T) {
	stubSecretTool(t)

	realRun, realOutput := runSecretTool, outputSecretTool
	t.Cleanup(func() { runSecretTool, outputSecretTool = realRun, realOutput })
	runSecretTool = func(stdin []byte, args ...string) error { return errNoSecretService }
	outputSecretTool = func(args ...string) ([]byte, error) { return nil, errNoSecretService }

	path := filepath.Join(t.TempDir(), "cache.bin")
	if err := writeProtected(path, []byte("x")); err == nil {
		t.Fatal("a write with no Secret Service must report failure so the caller stays in memory")
	}
	if _, err := readProtected(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a read with no Secret Service must be cold, got %v", err)
	}
}
