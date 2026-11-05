//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Flags of CreateFile that syscall doesn't name.
const (
	fileAttributeTemporary = 0x00000100
	fileFlagDeleteOnClose  = 0x04000000
)

// openCGITempFile creates a temporary file for a CGI (a request body, or its output waiting for the client) in
// Turbo's temporary folder, deleted by Windows when its handle is closed, also if Turbo stops without closing it.
func openCGITempFile(pattern string) (*os.File, error) {
	dir := os.TempDir()
	for attempt := 0; attempt < 16; attempt++ {
		random := make([]byte, 8)
		_, _ = rand.Read(random) // Never fails (crypto/rand)
		name := filepath.Join(dir, strings.Replace(pattern, "*", hex.EncodeToString(random), 1))
		path, err := syscall.UTF16PtrFromString(name)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: name, Err: err}
		}
		handle, err := syscall.CreateFile(path, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.CREATE_NEW,
			fileAttributeTemporary|fileFlagDeleteOnClose, 0)
		if errors.Is(err, syscall.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: name, Err: err}
		}
		return os.NewFile(uintptr(handle), name), nil
	}
	return nil, &os.PathError{Op: "open", Path: filepath.Join(dir, pattern), Err: os.ErrExist}
}
