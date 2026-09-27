package tpm

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// errNoState signals that no signer state exists at the configured path.
var errNoState = errors.New("tpm: no signer state")

// loadStateFile reads the state file. errNoState when it does not exist.
func loadStateFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoState
	}
	if err != nil {
		return nil, fmt.Errorf("tpm: read state file: %w", err)
	}
	return data, nil
}

// saveStateFile writes the state file atomically and durably, skipping
// unchanged content. A software key lives only in this file, so a torn write
// after a power cut would lose the machine identity.
func saveStateFile(path string, data []byte) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".signer-*.tmp")
	if err != nil {
		return fmt.Errorf("tpm: create temp state file: %w", err)
	}
	tmpName := tmp.Name()

	// CreateTemp makes the file 0600, which the rename keeps.
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("tpm: write temp state file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("tpm: close temp state file: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("tpm: replace state file: %w", err)
	}
	return nil
}
