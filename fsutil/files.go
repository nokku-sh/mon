// Package fsutil provides atomic file write helpers shared by the Nokku
// binaries. A write lands through a temp file in the same directory and a
// rename, and the parent directory is fsynced so the rename survives a crash.
package fsutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// WriteFile atomically writes data to filename with perm, replacing any
// existing regular file. It refuses to replace anything that is not a regular
// file.
func WriteFile(filename string, data []byte, perm os.FileMode) error {
	if filename == "" {
		return fmt.Errorf("empty filename")
	}

	filename = filepath.Clean(filename)
	if fi, err := os.Stat(filename); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", filename)
	}

	f, err := os.CreateTemp(filepath.Dir(filename), filepath.Base(filename)+".tmp")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = f.Write(data); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err = f.Chmod(perm); err != nil {
			return err
		}
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}

	if err = os.Rename(tmpName, filename); err != nil {
		return err
	}
	syncDir(filename)
	return nil
}

// WriteIfChanged writes data only when it differs from the file's current
// content, so a no-op save does not churn the filesystem or its mtime.
func WriteIfChanged(filename string, data []byte, perm os.FileMode) error {
	filename = filepath.Clean(filename)
	fi, err := os.Stat(filename)
	if err == nil {
		// Fast path: a size difference means the content differs.
		if fi.Size() != int64(len(data)) {
			return WriteFile(filename, data, perm)
		}
		// Slow path: sizes match, so compare the bytes.
		var existing []byte
		if existing, err = os.ReadFile(filename); err == nil && bytes.Equal(existing, data) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return WriteFile(filename, data, perm)
}

// FileExists reports whether path exists and is a regular file.
func FileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// syncDir fsyncs the directory holding filename so the rename is durable.
// Best effort: the file is already in place, and some filesystems (and
// Windows) cannot sync a directory.
func syncDir(filename string) {
	if runtime.GOOS == "windows" {
		return
	}
	if dir, err := os.Open(filepath.Dir(filename)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
}
