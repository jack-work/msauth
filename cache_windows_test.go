//go:build windows

package msauth

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDPAPIRoundTripAndCiphertextAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.bin")
	plain := []byte(`{"access_token":"not-a-real-token"}`)
	if err := writeProtected(path, plain); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("not-a-real-token")) {
		t.Fatal("cache contains plaintext token")
	}
	got, err := readProtected(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}
