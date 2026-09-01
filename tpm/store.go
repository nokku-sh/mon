package tpm

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrNoState signals that no signer state exists yet in a [Store].
var ErrNoState = errors.New("tpm: no signer state")

// Store persists the signer state as opaque bytes. Load returns ErrNoState
// when no state exists yet. Implementations must be safe for the single
// goroutine NewSigner runs on.
type Store interface {
	Load() ([]byte, error)
	Save(data []byte) error
}

// FileStore is a [Store] backed by a single file. Save writes atomically
// (temp file in the same directory, then rename) and skips the write when
// the content is unchanged.
type FileStore struct {
	path string
}

// NewFileStore returns a [Store] persisting to path.
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// Load reads the state file. ErrNoState when it does not exist.
func (s *FileStore) Load() ([]byte, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoState
	}
	if err != nil {
		return nil, fmt.Errorf("tpm: read state file: %w", err)
	}
	return data, nil
}

// Save writes the state file atomically, skipping unchanged content.
func (s *FileStore) Save(data []byte) error {
	if old, err := os.ReadFile(s.path); err == nil && bytes.Equal(old, data) {
		return nil
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".signer-*.tmp")
	if err != nil {
		return fmt.Errorf("tpm: create temp state file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("tpm: write temp state file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("tpm: close temp state file: %w", err)
	}
	// State files hold public material for TPM keys and wrapped private
	// material for software keys. CreateTemp already created the file with
	// 0600; keep it that way across the rename.
	if err = os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("tpm: chmod state file: %w", err)
	}
	if err = os.Rename(tmpName, s.path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("tpm: replace state file: %w", err)
	}
	return nil
}
