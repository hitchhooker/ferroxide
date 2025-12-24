package tpm

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/acheong08/ferroxide/config"
)

// keyring file path for a user
func keyringPath(username string) (string, error) {
	dir, err := config.Path("keyring")
	if err != nil {
		return "", err
	}
	// sanitize username for filesystem
	safe := base64.URLEncoding.EncodeToString([]byte(username))
	return filepath.Join(dir, safe+".tpm"), nil
}

// SealKey seals a secret key to the TPM for a user.
func SealKey(username string, key *[32]byte) error {
	sealed, err := Seal(key[:])
	if err != nil {
		return err
	}

	path, err := keyringPath(username)
	if err != nil {
		return err
	}

	return os.WriteFile(path, sealed, 0600)
}

// UnsealKey recovers a user's secret key from TPM.
func UnsealKey(username string) (*[32]byte, error) {
	path, err := keyringPath(username)
	if err != nil {
		return nil, err
	}

	blob, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("no sealed key for user %q", username)
	} else if err != nil {
		return nil, err
	}

	data, err := Unseal(blob)
	if err != nil {
		return nil, err
	}

	if len(data) != 32 {
		return nil, fmt.Errorf("invalid key size: got %d, want 32", len(data))
	}

	var key [32]byte
	copy(key[:], data)
	return &key, nil
}

// HasSealedKey checks if a user has a TPM-sealed key.
func HasSealedKey(username string) bool {
	path, err := keyringPath(username)
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// DeleteSealedKey removes a user's TPM-sealed key.
func DeleteSealedKey(username string) error {
	path, err := keyringPath(username)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// ListSealedUsers returns usernames that have TPM-sealed keys.
func ListSealedUsers() ([]string, error) {
	dir, err := config.Path("keyring")
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	var users []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) < 5 || name[len(name)-4:] != ".tpm" {
			continue
		}
		// decode username
		encoded := name[:len(name)-4]
		decoded, err := base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		users = append(users, string(decoded))
	}
	return users, nil
}
