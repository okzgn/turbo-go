package server

// The tests of the findings about the rewrites of the review of v2.5.1: each failed before its fix.

import (
	"strings"
	"testing"
)

// V2.5.1 review SR-1: where names fold (Windows, macOS, a sites directory that folds them), rewrite() folds the path
// once and looks each of its folders up as a prefix of what it gave. It folded each folder by itself, a text as long
// as it for each one with a capital: a path of 10 KiB in capitals made thousands of them, some 27 MiB, with the
// global lock held.
func TestR251_SR1_ALongPathInCapitalsIsFoldedOnce(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates on its own")
	}
	initForTest(t)
	foldForTest(t, true)
	previousCheck := keptViewCheck
	keptViewCheck = nil // What is kept is compared with the state at each use, and that allocates
	t.Cleanup(func() { keptViewCheck = previousCheck })
	foldSite(t, "/private/")
	path := strings.Repeat("/A", 5120)[:10238]
	for _, normalize := range []bool{false, true} {
		normalizeForTest(t, normalize)
		var allocations float64
		withReadLock(func() {
			if target, key := rewrite(path, "fold.test", ""); target != "" || key != "" {
				t.Errorf("a path of %d bytes in capitals: rewritten by %q", len(path), key)
			}
			allocations = testing.AllocsPerRun(10, func() { rewrite(path, "fold.test", "") })
		})
		if allocations > 4 {
			t.Errorf("normalizing %v, a path of %d bytes in capitals: %.0f allocations; expected 4 at most", normalize, len(path), allocations)
		}
	}
}

// V2.5.1 review SR-1: for any path, folded as on macOS and not, the key of each of its folders is the start of the
// key of the whole path, up to the "/" of that folder, when both have as many "/" (rewrite() looks each folder up
// so, and otherwise folds each as before): folding goes character by character, none folds to "/", and "/" composes
// with nothing in NFC.
func FuzzFoldKeyPrefixes(f *testing.F) {
	for _, sample := range foldSamples {
		f.Add("/" + sample + "/" + strings.ToUpper(sample) + "/x")
	}
	f.Add("/café/CAFÉ/\xff/K/")
	f.Add("/́/á́/\xcc/\x81")
	f.Fuzz(func(t *testing.T, path string) {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path // As every path of a request
		}
		for _, normalize := range []bool{false, true} {
			normalizeForTest(t, normalize)
			folded := foldKey(path)
			if strings.Count(folded, "/") != strings.Count(path, "/") {
				continue
			}
			foldedAt := 0
			for i := 0; i < len(path); i++ {
				if path[i] != '/' {
					continue
				}
				foldedAt += strings.IndexByte(folded[foldedAt:], '/')
				if prefix := foldKey(path[:i+1]); prefix != folded[:foldedAt+1] {
					t.Fatalf("normalizing %v, %q: the key of %q is %q; the start of the key of the path, %q", normalize, path, path[:i+1], prefix, folded[:foldedAt+1])
				}
				foldedAt++
			}
		}
	})
}
