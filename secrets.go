package msauth

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
)

// Adapters such as icy exchange an Entra token for a service-issued bearer
// (for example an IcM STS token). Those bearers are not Entra tokens and their
// exchanges must stay in the owning tool, but they need exactly the same
// at-rest protection as msauth's own cache. This file is that narrow shared
// facility: seal and unseal opaque bytes with current-user protection. It
// deliberately knows nothing about any service's token semantics.

// ProtectSecret seals arbitrary credential material at path with current-user
// protection, replacing any existing content.
func ProtectSecret(path string, secret []byte) error {
	if err := validateSecretPath(path); err != nil {
		return err
	}
	if len(secret) == 0 {
		return newRequestError("secret is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return &AuthError{Code: CodeProtectFailed, Message: sanitizeDiagnostic(err.Error())}
	}
	if err := writeProtected(path, secret); err != nil {
		return &AuthError{Code: CodeProtectFailed, Message: sanitizeDiagnostic(err.Error())}
	}
	return nil
}

// OpenSecret unseals material previously written by ProtectSecret. A missing
// secret is reported as CodeNotFound so callers can distinguish a cold cache
// from a real protection failure and re-acquire instead of failing the command.
func OpenSecret(path string) ([]byte, error) {
	if err := validateSecretPath(path); err != nil {
		return nil, err
	}
	plain, err := readProtected(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, errLegacyPlaintext) {
			return nil, &AuthError{Code: CodeNotFound, Message: "no protected secret is stored at the requested path"}
		}
		return nil, &AuthError{Code: CodeProtectFailed, Message: sanitizeDiagnostic(err.Error())}
	}
	if len(plain) == 0 {
		return nil, &AuthError{Code: CodeNotFound, Message: "no protected secret is stored at the requested path"}
	}
	return plain, nil
}

func validateSecretPath(path string) error {
	if path == "" {
		return newRequestError("path is required")
	}
	if !filepath.IsAbs(path) {
		return newRequestError("path must be absolute")
	}
	return nil
}

func decodeSecret(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, newRequestError("secret is required")
	}
	secret, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, newRequestError("secret must be standard base64")
	}
	if len(secret) == 0 {
		return nil, newRequestError("secret is required")
	}
	return secret, nil
}
