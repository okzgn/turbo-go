//go:build windows

package server

// The tests of the findings of the external review of v2.5.2 (GGCH) that only Windows has.

import (
	"io"
	"os"
	"testing"
)

// GGCH H-04: no other handle opens a temporary file of a CGI while it lives: it has a name in the temporary folder,
// which another process of the same user could open to read, or write, the body or the answer that it holds. Turbo
// reads and writes it by its own handle, and Windows deletes it when that handle closes.
func TestGGCH_H04_TheTemporaryFilesOfTheCGIsAreNotShared(t *testing.T) {
	file, err := openCGITempFile("turbo-cgi-ggch-*")
	if err != nil {
		t.Fatal(err)
	}
	name := file.Name()
	defer file.Close()
	if _, err := file.WriteString("the body of a client"); err != nil {
		t.Fatal(err)
	}
	if other, err := os.Open(name); err == nil {
		other.Close()
		t.Error("another handle opened the temporary file to read it")
	}
	if other, err := os.OpenFile(name, os.O_WRONLY, 0); err == nil {
		other.Close()
		t.Error("another handle opened the temporary file to write it")
	}
	if _, err := os.Stat(name); err != nil { // Its name is there while it lives, as the tests of the CGIs look for it
		t.Errorf("stat of the temporary file: %v", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if data, err := io.ReadAll(file); err != nil || string(data) != "the body of a client" {
		t.Errorf("read by its own handle: %q %v", data, err)
	}
	file.Close()
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Errorf("after closing it: %v; expected it gone", err)
	}
}
