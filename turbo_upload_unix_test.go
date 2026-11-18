//go:build unix

package main

import (
	"os"
	"testing"
)

// R6 P-08: hardUpload leaves the new public folder with the permissions of the one it replaces. It was the folder
// MkdirTemp made, 0700: whoever could read the site besides Turbo (a backup, a deployment by its group) no longer
// could.
func TestR6_P08_HardUploadKeepsTheFolderPermissions(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, mode := range []os.FileMode{0755, 0750, 0775} {
		if err := os.Chmod(dir+"localhost/@", mode); err != nil {
			t.Fatal(err)
		}
		if code, body := hardUploadFiles(t, base, tok, [][2]string{{"site/index.html", "uploaded"}}); code != 200 {
			t.Fatalf("hardUpload: %d %q", code, body)
		}
		info, err := os.Stat(dir + "localhost/@")
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("@ was %v and the uploaded one is %v", mode, info.Mode().Perm())
		}
	}
}
