//go:build windows

package msauth

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const cryptprotectUIForbidden = 0x1

func writeProtected(path string, plain []byte) error {
	if len(plain) == 0 {
		return os.WriteFile(path, nil, 0o600)
	}
	input := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, nil, 0, nil, cryptprotectUIForbidden, &output); err != nil {
		return fmt.Errorf("protect token cache with Windows DPAPI: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	ciphertext := unsafe.Slice(output.Data, int(output.Size))
	return os.WriteFile(path, append([]byte(nil), ciphertext...), 0o600)
}

func readProtected(path string) ([]byte, error) {
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, nil
	}
	input := windows.DataBlob{Size: uint32(len(ciphertext)), Data: &ciphertext[0]}
	var output windows.DataBlob
	if err := windows.CryptUnprotectData(&input, nil, nil, 0, nil, cryptprotectUIForbidden, &output); err != nil {
		// Old prototypes stored plaintext JSON. Remove rather than perpetuate it.
		if ciphertext[0] == '{' {
			_ = os.Remove(path)
			return nil, errLegacyPlaintext
		}
		return nil, fmt.Errorf("unprotect token cache with Windows DPAPI: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return append([]byte(nil), unsafe.Slice(output.Data, int(output.Size))...), nil
}

// protectedSize is the file-backed answer: diagnostics.go already stats the
// path, so this exists only to keep the seam total across platforms.
func protectedSize(path string) (int64, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	return info.Size(), true
}
