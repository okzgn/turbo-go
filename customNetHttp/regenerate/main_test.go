package main

// B8 (H14): -check also verifies Turbo's own files (0.*.go) and the Go sources
// the package is regenerated from, and a patch hunk that matches in more than
// one place is not applied.

import (
	"go/build"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forkCopy copies customNetHttp (without regenerate/) to a temporary directory.
func forkCopy(t *testing.T) string {
	t.Helper()
	target := t.TempDir()
	err := filepath.WalkDir("..", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel("..", p)
		if d.IsDir() {
			if d.Name() == "regenerate" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(target, relative), 0o755)
		}
		content, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(target, relative), content, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(target, "regenerate"), 0o755)
	return target
}

func checkIn(dir string) error {
	return run(dir, "", -1, true, false, false, func(string, ...any) {})
}

func TestB8_CheckOwnFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("regenerates the fork")
	}
	dir := forkCopy(t)
	if err := checkIn(dir); err != nil {
		t.Fatalf("the copy of the fork doesn't pass -check: %v", err)
	}

	os.WriteFile(filepath.Join(dir, "0.zz.go"), []byte("package customNetHttp\n\nfunc init() {}\n"), 0o644)
	if err := checkIn(dir); err == nil {
		t.Error("-check accepts an added 0.zz.go")
	}
	os.Remove(filepath.Join(dir, "0.zz.go"))

	own := filepath.Join(dir, "0.turbo.patches.go")
	original, _ := os.ReadFile(own)
	os.WriteFile(own, append(original, []byte("\nfunc turboAdded() {}\n")...), 0o644)
	if err := checkIn(dir); err == nil {
		t.Error("-check accepts a modified 0.turbo.patches.go")
	}
}

// A Go source different from the manifest's is detected.
func TestB8_GoSources(t *testing.T) {
	sources := map[string][]byte{"net/http/a.go": []byte("package http\n"), "mime/multipart/b.go": []byte("package multipart\n")}
	manifest := manifestOf(sources)
	if err := compareManifest(manifest, sources); err != nil {
		t.Fatalf("the same sources don't match: %v", err)
	}
	altered := map[string][]byte{"net/http/a.go": []byte("package http\nfunc init() {}\n"), "mime/multipart/b.go": sources["mime/multipart/b.go"]}
	if err := compareManifest(manifest, altered); err == nil || !strings.Contains(err.Error(), "net/http/a.go") {
		t.Errorf("an altered source is not detected: %v", err)
	}
	if err := compareManifest(manifest, map[string][]byte{"net/http/a.go": sources["net/http/a.go"]}); err == nil {
		t.Error("a missing source is not detected")
	}
}

// A hunk whose context appears in two places is applied in neither.
func TestB8_AmbiguousHunk(t *testing.T) {
	files := map[string]string{"x.go": "a\nb\nc\nx\na\nb\nc\n"}
	patch := "--- a/x.go\n+++ b/x.go\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"
	if err := applyPatch(files, patch); err == nil {
		t.Errorf("ambiguous hunk applied: %q", files["x.go"])
	}
	files = map[string]string{"x.go": "a\nb\nc\nx\n"}
	if err := applyPatch(files, patch); err != nil || files["x.go"] != "a\nB\nc\nx\n" {
		t.Errorf("unique hunk: %v %q", err, files["x.go"])
	}
}

// N50: -output deletes nothing it didn't generate: a directory with other files
// is refused, and in one marked by an earlier output only its names are touched.
func TestN50_OutputDeletesNothingElse(t *testing.T) {
	if testing.Short() {
		t.Skip("regenerates the fork")
	}
	output := t.TempDir()
	foreign := filepath.Join(output, "a.turbo.main.go")
	os.WriteFile(foreign, []byte("package main\n"), 0o644)
	if err := run("..", output, 1, false, false, false, func(string, ...any) {}); err == nil {
		t.Error("-output accepted a directory with other files")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("a foreign file was deleted: %v", err)
	}
	os.Remove(foreign)
	if err := run("..", output, 1, false, false, false, func(string, ...any) {}); err != nil {
		t.Fatalf("-output in an empty directory: %v", err)
	}
	os.WriteFile(foreign, []byte("package main\n"), 0o644) // Added after the first output: not one of its names
	if err := run("..", output, 2, false, false, false, func(string, ...any) {}); err != nil {
		t.Fatalf("-output over an earlier output: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("the second output deleted a file it didn't generate: %v", err)
	}
}

// N50: -patches needs -output, and -update combines with neither and doesn't
// downgrade without -allow-downgrade.
func TestN50_IncompatibleOptions(t *testing.T) {
	none := func(string, ...any) {}
	if err := run("..", "", 3, false, false, false, none); err == nil || !strings.Contains(err.Error(), "-output") {
		t.Errorf("-patches without -output: %v", err)
	}
	if err := run("..", t.TempDir(), -1, false, true, false, none); err == nil || !strings.Contains(err.Error(), "-update") {
		t.Errorf("-update with -output: %v", err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "UPSTREAM"), []byte("go1.99.0\n"), 0o644)
	if err := run(dir, "", -1, false, true, false, none); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Errorf("-update to an earlier version: %v", err)
	}
}

// N51: the patch reader checks the @@ counts, treats "-- " as content, refuses
// hunks without context and any line that is neither in a hunk nor in the git
// header of a file (N71).
func TestN51_PatchReader(t *testing.T) {
	files := func() map[string]string { return map[string]string{"x.go": "a\n-- b\nc\nd\n"} }
	cases := []struct {
		name, patch string
		ok          bool
	}{
		{"right counts", "--- a/x.go\n+++ b/x.go\n@@ -1,3 +1,3 @@\n a\n--- b\n+B\n c\n", true},
		{"counts that don't add up", "--- a/x.go\n+++ b/x.go\n@@ -1,4 +1,3 @@\n a\n--- b\n+B\n c\n", false},
		{"no context", "--- a/x.go\n+++ b/x.go\n@@ -2,1 +2,1 @@\n--- b\n+B\n", false},
		// An extra line after a hunk is not skipped, nor is the hunk that follows it (N71)
		{"extra line after the hunk", "--- a/x.go\n+++ b/x.go\n@@ -1,3 +1,3 @@\n a\n--- b\n+B\n c\n+X\n@@ -4,1 +4,1 @@\n-d\n+D\n", false},
		{"git headers before the file", "diff --git a/x.go b/x.go\nindex 1..2 100644\n--- a/x.go\n+++ b/x.go\n@@ -1,3 +1,3 @@\n a\n--- b\n+B\n c\n", true},
		{"loose text before the file", "Subject: something\n--- a/x.go\n+++ b/x.go\n@@ -1,3 +1,3 @@\n a\n--- b\n+B\n c\n", false},
	}
	for _, c := range cases {
		f := files()
		err := applyPatch(f, c.patch)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
		if c.ok && f["x.go"] != "a\nB\nc\nd\n" {
			t.Errorf("%s: %q", c.name, f["x.go"])
		}
	}
}

// N51: without any patch there is nothing to check, and -check stops.
func TestN51_WithoutPatches(t *testing.T) {
	if testing.Short() {
		t.Skip("regenerates the fork")
	}
	dir := forkCopy(t)
	entries, _ := os.ReadDir(filepath.Join(dir, "patches"))
	for _, e := range entries {
		os.Remove(filepath.Join(dir, "patches", e.Name()))
	}
	if err := checkIn(dir); err == nil || !strings.Contains(err.Error(), "patch") {
		t.Errorf("-check without any patch: %v", err)
	}
}

// N108: a patch only changes generated files in place. A "new file" patch over one that exists (it replaced
// it whole, without any context checked), a patch that touches an own file of Turbo (0.*) and a rename (it
// copied the file under another name and kept the old one) are refused.
func TestN108_RefusedPatches(t *testing.T) {
	cases := []struct{ name, patch string }{
		{"new file over a generated one", "--- /dev/null\n+++ b/x.go\n@@ -0,0 +1,1 @@\n+other\n"},
		{"new own file", "--- /dev/null\n+++ b/0.turbo.new.go\n@@ -0,0 +1,1 @@\n+package customNetHttp\n"},
		{"change of an own file", "--- a/0.turbo.x.go\n+++ b/0.turbo.x.go\n@@ -1,2 +1,2 @@\n a\n-b\n+B\n"},
		{"rename", "diff --git a/x.go b/y.go\nsimilarity index 90%\nrename from x.go\nrename to y.go\n--- a/x.go\n+++ b/y.go\n@@ -1,3 +1,3 @@\n a\n--- b\n+B\n c\n"},
		{"rename without git headers", "--- a/x.go\n+++ b/y.go\n@@ -1,3 +1,3 @@\n a\n--- b\n+B\n c\n"},
	}
	for _, c := range cases {
		files := map[string]string{"x.go": "a\n-- b\nc\nd\n", "0.turbo.x.go": "a\nb\n"}
		if err := applyPatch(files, c.patch); err == nil {
			t.Errorf("%s: applied (%d files: %q)", c.name, len(files), files)
		}
	}
	files := map[string]string{"x.go": "a\n"}
	if err := applyPatch(files, "--- /dev/null\n+++ b/z.go\n@@ -0,0 +1,1 @@\n+new\n"); err != nil || files["z.go"] != "new\n" {
		t.Errorf("a new file that didn't exist: %v %q", err, files["z.go"])
	}
}

// R6-04 (production review of 2026-11-04): the "go" line of go.mod is the version of UPSTREAM. With "go 1.26", a
// build with an older Go 1.26.x mixed the fork's net/http with that Go's own crypto/tls and net/url.
func TestRP3_R604_GoModVersion(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "UPSTREAM"), []byte("go1.26.10\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	goMod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(goMod, []byte("module turbo\r\n\r\ngo 1.26\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := goModVersion(goMod, dir, true); err == nil || !strings.Contains(err.Error(), `"go 1.26.10"`) {
		t.Errorf("-check with go 1.26: %v; expected that it must say go 1.26.10", err)
	}
	if err := goModVersion(goMod, dir, false); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(goMod); string(data) != "module turbo\r\n\r\ngo 1.26.10\r\n" {
		t.Errorf("go.mod written: %q", data)
	}
	if err := goModVersion(goMod, dir, true); err != nil {
		t.Errorf("-check after writing it: %v", err)
	}
	os.WriteFile(goMod, []byte("module turbo\n"), 0o644)
	if err := goModVersion(goMod, dir, true); err == nil {
		t.Error("a go.mod without a go line passed")
	}
	// The repository's own go.mod says the version of its UPSTREAM.
	if err := goModVersion(filepath.Join("..", "..", "go.mod"), "..", true); err != nil {
		t.Error(err)
	}
}

// R6 N-10: a deletion that doesn't remove the whole file, a name with folders, and the line break at the end of a
// file as "\ No newline at end of file" says. A deletion deleted the file whatever its hunks covered, only the last
// part of a path was taken ("sub/x.go" changed "x.go"), and the marker was skipped: the result kept the ending of the
// original.
func TestR6_N10_WhatAPatchSays(t *testing.T) {
	cases := []struct {
		name, patch string
		ok          bool
		file        string // x.go after the patch; "-" if it was deleted
	}{
		{"a deletion of part of the file", "--- a/x.go\n+++ /dev/null\n@@ -1,2 +0,1 @@\n-a\n b\n", false, ""},
		{"a deletion of the whole file", "--- a/x.go\n+++ /dev/null\n@@ -1,3 +0,0 @@\n-a\n-b\n-c\n", true, "-"},
		{"a name with folders", "--- a/sub/x.go\n+++ b/sub/x.go\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n", false, ""},
		{"a name with folders, Windows style", "--- a/sub\\x.go\n+++ b/sub\\x.go\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n", false, ""},
		{"the result without a final line break", "--- a/x.go\n+++ b/x.go\n@@ -2,2 +2,2 @@\n b\n-c\n+C\n\\ No newline at end of file\n", true, "a\nb\nC"},
		{"the original without one, said of a file that has one", "--- a/x.go\n+++ b/x.go\n@@ -2,2 +2,2 @@\n b\n-c\n\\ No newline at end of file\n+C\n", false, ""},
	}
	for _, c := range cases {
		files := map[string]string{"x.go": "a\nb\nc\n"}
		err := applyPatch(files, c.patch)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !c.ok {
			continue
		}
		if got, kept := files["x.go"]; c.file == "-" && kept || c.file != "-" && got != c.file {
			t.Errorf("%s: x.go is %q (there %v); expected %q", c.name, got, kept, c.file)
		}
	}
	// A file without a final line break: a hunk that reaches its end says so, and the result ends as it says
	for _, c := range []struct {
		name, patch string
		ok          bool
		file        string
	}{
		{"it says nothing", "--- a/x.go\n+++ b/x.go\n@@ -2,2 +2,2 @@\n b\n-c\n+C\n", false, ""},
		{"it keeps it so", "--- a/x.go\n+++ b/x.go\n@@ -2,2 +2,2 @@\n b\n-c\n\\ No newline at end of file\n+C\n\\ No newline at end of file\n", true, "a\nb\nC"},
		{"it adds the line break", "--- a/x.go\n+++ b/x.go\n@@ -2,2 +2,2 @@\n b\n-c\n\\ No newline at end of file\n+C\n", true, "a\nb\nC\n"},
		{"a hunk before the end", "--- a/x.go\n+++ b/x.go\n@@ -1,2 +1,2 @@\n-a\n+A\n b\n", true, "A\nb\nc"},
	} {
		files := map[string]string{"x.go": "a\nb\nc"}
		err := applyPatch(files, c.patch)
		if (err == nil) != c.ok {
			t.Errorf("without a final line break, %s: %v", c.name, err)
			continue
		}
		if c.ok && files["x.go"] != c.file {
			t.Errorf("without a final line break, %s: %q; expected %q", c.name, files["x.go"], c.file)
		}
	}
}

// R6 N-10: a patch that leaves customNetHttp with a type error stops the regeneration. Only the syntax and the
// format were checked: the error was found when building.
func TestR6_N10_TypesAfterThePatches(t *testing.T) {
	if testing.Short() {
		t.Skip("regenerates the fork")
	}
	dir := forkCopy(t)
	const name = "1.net.http.server.go"
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(normalize(string(data)), "\n"), "\n")
	context := 3
	for ; context < len(lines) && occurrences(lines, lines[len(lines)-context:]) > 1; context++ {
	}
	start := len(lines) - context + 1
	patch := "--- a/" + name + "\n+++ b/" + name + "\n@@ -" + strconv.Itoa(start) + "," + strconv.Itoa(context) + " +" + strconv.Itoa(start) + "," + strconv.Itoa(context+2) + " @@\n"
	for _, line := range lines[len(lines)-context:] {
		patch += " " + line + "\n"
	}
	patch += "+\n+var _ int = \"not an int\"\n"
	if err := os.WriteFile(filepath.Join(dir, "patches", "99-broken-type.patch"), []byte(patch), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkIn(dir); err == nil || !strings.Contains(err.Error(), "type-check") {
		t.Errorf("-check with a patch that breaks a type: %v", err)
	}
}

// R6 N-11: NOTICE names the Go release of UPSTREAM and the versions of golang.org/x/net and golang.org/x/text that it
// vendors; -check verifies them and -update writes them, keeping the lines of NOTICE.
func TestR6_N11_NoticeVersions(t *testing.T) {
	dir := t.TempDir()
	notice := "taken from the Go release\nnamed in the UPSTREAM file (go1.26.10: golang.org/x/net\nv0.47.0 and golang.org/x/text v0.31.0,\nas vendored by that release).\n"
	os.WriteFile(filepath.Join(dir, "NOTICE"), []byte(notice), 0o644)
	vendored := map[string]string{"golang.org/x/net": "v0.47.1-0.20261008201845-026a91c07857", "golang.org/x/text": "v0.32.0"}
	if err := checkNotice(dir, "go1.26.11", vendored); err == nil {
		t.Error("NOTICE with older versions passes the check")
	}
	if err := updateNotice(dir, "go1.26.11", vendored); err != nil {
		t.Fatal(err)
	}
	updated, _ := os.ReadFile(filepath.Join(dir, "NOTICE"))
	want := "taken from the Go release\nnamed in the UPSTREAM file (go1.26.11: golang.org/x/net\nv0.47.1-0.20261008201845-026a91c07857 and golang.org/x/text v0.32.0,\nas vendored by that release).\n"
	if string(updated) != want {
		t.Errorf("NOTICE after the update:\n%s\nexpected:\n%s", updated, want)
	}
	if err := checkNotice(dir, "go1.26.11", vendored); err != nil {
		t.Errorf("NOTICE after the update: %v", err)
	}
	if err := checkNotice("..", strings.TrimSpace(strings.SplitN(readFile(t, "../UPSTREAM"), "\n", 2)[0]), mustVendored(t)); err != nil {
		t.Errorf("the NOTICE of customNetHttp: %v", err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return normalize(string(data))
}

// mustVendored is vendoredVersions of the GOROOT in use, which must be the release of UPSTREAM.
func mustVendored(t *testing.T) map[string]string {
	t.Helper()
	versions, err := vendoredVersions(build.Default.GOROOT)
	if err != nil {
		t.Fatal(err)
	}
	return versions
}
