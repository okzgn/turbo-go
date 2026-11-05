//go:build !windows

package main

import "os"

// openCGITempFile creates a temporary file for a CGI (a request body, or its output waiting for the client) in
// Turbo's temporary folder, with 0600 and without a name: its name is removed as soon as it is created, so the file
// goes when it is closed, also if Turbo stops without closing it.
func openCGITempFile(pattern string) (*os.File, error) {
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(file.Name()); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, err
	}
	return file, nil
}
