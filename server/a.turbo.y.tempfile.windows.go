//go:build windows

/*
Turbo - A cross-platform, high-performance HTTP web server with a real-time, visual management interface. Manage unlimited domains and multi-level wildcard subdomains, SSL certificates, URI rewrites, request preprocessing, fine-grained request rate and size limiting, as well as custom aliases, headers, MIMEs, and indexes.
Copyright (C) 2026 OKZGN

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please visit one of the following:
- https://okzgn.com/#contact
- https://okzgn.github.io/#contact
*/

package server

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
// Turbo's temporary folder, deleted by Windows when its handle is closed, also if Turbo stops without closing it. No
// other handle can open it while it lives (no sharing): it has a name there, which another process of the same user
// could open to read the bodies and the answers of other clients, or write them while they wait. Turbo uses only its
// own handle.
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
		handle, err := syscall.CreateFile(path, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.CREATE_NEW,
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
