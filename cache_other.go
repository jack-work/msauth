//go:build !windows && !linux

package msauth

import (
	"errors"
	"os"
)

// Persisting bearer tokens without an OS-bound protection primitive would turn
// convenience into credential sprawl. Platforms with no such primitive keep the
// in-memory cache. Windows seals with DPAPI (cache_windows.go) and Linux with the
// Secret Service (cache_linux.go); everything else lands here.
func writeProtected(path string, plain []byte) error {
	_ = os.Remove(path)
	return errors.New("persistent token cache is disabled on this platform")
}

func readProtected(path string) ([]byte, error) {
	return nil, os.ErrNotExist
}

// protectedSize: nothing is persisted on this platform, so nothing is warm.
func protectedSize(path string) (int64, bool) {
	return 0, false
}
