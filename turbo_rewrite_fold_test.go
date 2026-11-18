package main

// Review of 6046dbe (R6), O-8: where names fold, the rewrite that a path takes in other capitals is found by a key
// that is the same for both (foldKey), among those of its site kept by that key. Before, each lookup compared the
// path with every rewrite of the site, and a request makes one for each folder of its path. Those folders are looked
// up as parts of the path, without a text made for each, and a site without rewrites looks nothing up.

import (
	"strings"
	"testing"
)

// foldSamples are texts that strings.EqualFold takes for equal to others here, in every way it does: ASCII letters,
// the characters outside ASCII that fold to one (the Kelvin sign, the long s), those with three forms, those that
// change length, and what isn't UTF-8.
var foldSamples = []string{
	"", "/", "/a", "/A", "/section/", "/Section/", "/SECTION/", "/sectioN/x", "k", "K", "K", "s", "S", "ſ",
	"Ǆ", "ǅ", "ǆ", "σ", "ς", "Σ", "ß", "ẞ", "ss", "İ", "i", "I", "ı",
	"\xff", "\xfe", "�", "/café", "/CAFÉ", "/café", "a\x00b", "A\x00B", "/a/b", "/a/B/", "µ", "μ", "Μ",
}

// linearRewriteKey is how a rewrite was looked up before: as written, or else the first, in byte order, of those
// that strings.EqualFold takes for the key.
func linearRewriteKey(rewrites map[string]string, key string, fold bool) (string, bool) {
	if _, found := rewrites[key]; found || !fold {
		return key, found
	}
	match := ""
	for candidate := range rewrites {
		if strings.EqualFold(candidate, key) && (match == "" || candidate < match) {
			match = candidate
		}
	}
	return match, match != ""
}

// linearRewrite is how the rewrite of a path was found before: the path, the folder named without its final "/",
// each folder that contains it and "/", each a text made for it and looked up by linearRewriteKey.
func linearRewrite(rewrites map[string]string, path string, fold bool) (string, string) {
	if key, found := linearRewriteKey(rewrites, path, fold); found {
		return rewrites[key], key
	}
	if path == "/" {
		return "", ""
	}
	if !strings.HasSuffix(path, "/") {
		if key, found := linearRewriteKey(rewrites, path+"/", fold); found {
			return rewrites[key], key
		}
	}
	path = path[1:]
	for {
		slash := strings.LastIndexByte(path, '/')
		if slash == -1 {
			break
		}
		slash++
		if key, found := linearRewriteKey(rewrites, "/"+path[:slash], fold); found {
			return rewrites[key], key
		}
		path = path[:slash-1]
	}
	if key, found := linearRewriteKey(rewrites, "/", fold); found {
		return rewrites[key], key
	}
	return "", ""
}

// foldForTest sets whether names fold, whatever the system and the sites directory of the test, until it ends.
func foldForTest(tb testing.TB, fold bool) {
	previous, previousDir := foldRewrites, sitesDirFolds.Load()
	withGlobalLock(func() { foldRewrites = fold })
	sitesDirFolds.Store(fold)
	tb.Cleanup(func() {
		withGlobalLock(func() { foldRewrites = previous })
		sitesDirFolds.Store(previousDir)
	})
}

// R6 O-8: two texts have the same foldKey exactly when strings.EqualFold takes them for equal, and ASCII without
// capitals is its own, without a copy.
func TestR6_O8_FoldKeyIsEqualFold(t *testing.T) {
	for _, a := range foldSamples {
		for _, b := range foldSamples {
			if same, equal := foldKey(a) == foldKey(b), strings.EqualFold(a, b); same != equal {
				t.Errorf("%q and %q: foldKey %q and %q, the same %v; EqualFold says %v", a, b, foldKey(a), foldKey(b), same, equal)
			}
		}
	}
	for text, expected := range map[string]string{"/Section/": "/section/", "K": "k", "ſ": "s", "\xff": "�", "/CAFÉ": "/cafÉ"} {
		if key := foldKey(text); key != expected {
			t.Errorf("foldKey(%q) = %q; expected %q", text, key, expected)
		}
	}
	if raceEnabled {
		return // The race detector allocates on its own
	}
	path := "/a/long/path/of/a/site/in/lower/case.html"
	if allocations := testing.AllocsPerRun(100, func() { foldKey(path) }); allocations != 0 {
		t.Errorf("foldKey of a path without capitals: %.0f allocations; expected none", allocations)
	}
}

// R6 O-8: any two texts.
func FuzzFoldKey(f *testing.F) {
	for i, a := range foldSamples {
		f.Add(a, foldSamples[(i+1)%len(foldSamples)])
		f.Add(a, strings.ToUpper(a))
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		if same, equal := foldKey(a) == foldKey(b), strings.EqualFold(a, b); same != equal {
			t.Fatalf("%q and %q: foldKey %q and %q, the same %v; EqualFold says %v", a, b, foldKey(a), foldKey(b), same, equal)
		}
	})
}

// foldSite leaves fold.test with the rewrites given (to "N/target-<key>") and returns its lookup of one key.
func foldSite(tb testing.TB, keys ...string) func(key string) (string, bool) {
	rewrites := make(map[string]string, len(keys))
	for _, key := range keys {
		rewrites[key] = "N/target-" + key
	}
	withGlobalLock(func() { sitesMap["fold.test"] = map[string]map[string]string{"": rewrites} })
	return foldSiteKey
}

// foldSiteKey looks key up among the rewrites of fold.test, as rewrite() looks up each key of a request.
func foldSiteKey(key string) (match string, found bool) {
	withReadLock(func() {
		match, found = rewriteKey(sitesMap["fold.test"][""], rewriteFolds("fold.test", ""), key)
	})
	return match, found
}

// R6 O-8: where names fold, a path takes the rewrite written like it, or else the first in byte order of those that
// differ from it only in case; where they don't, only the one written like it. A rewrite added or removed counts
// from the next request, and for who has the write lock, at once.
func TestR6_O8_RewriteInOtherCapitals(t *testing.T) {
	initForTest(t)
	foldForTest(t, true)
	lookup := foldSite(t, "/section/", "/Section/", "/SECTION/", "/other/", "/Kelvin/")
	for key, expected := range map[string]string{
		"/section/": "/section/", "/Section/": "/Section/", "/SECTION/": "/SECTION/", // As written
		"/sEcTiOn/": "/SECTION/", "/sectioN/": "/SECTION/", // The first in byte order
		"/OTHER/": "/other/", "/kelvin/": "/Kelvin/", "/KELVIN/": "/Kelvin/",
		"/section": "", "/sections/": "", "": "",
	} {
		if match, found := lookup(key); found != (expected != "") || found && match != expected {
			t.Errorf("%q where names fold: %q, found %v; expected %q", key, match, found, expected)
		}
	}
	// Through the whole lookup of a request path, with its folders
	withReadLock(func() {
		if target, key := rewrite("/OTHER/a/b.html", "fold.test", ""); target != "N/target-/other/" || key != "/other/" {
			t.Errorf("/OTHER/a/b.html: %q by %q; expected the rewrite of /other/", target, key)
		}
	})

	withGlobalLock(func() {
		sitesMap["fold.test"][""]["/New/"] = "N/new"
		delete(sitesMap["fold.test"][""], "/SECTION/")
		if target, key := rewrite("/NEW/x", "fold.test", ""); target != "N/new" || key != "/New/" { // With the write lock: as the state is now
			t.Errorf("/NEW/x with the write lock, right after adding /New/: %q by %q", target, key)
		}
	})
	if match, found := lookup("/new/"); !found || match != "/New/" {
		t.Errorf("/new/ after adding /New/: %q, found %v", match, found)
	}
	if match, found := lookup("/sEcTiOn/"); !found || match != "/Section/" {
		t.Errorf("/sEcTiOn/ after removing /SECTION/: %q, found %v; expected /Section/, the first that is left", match, found)
	}

	foldForTest(t, false)
	for key, expected := range map[string]string{"/section/": "/section/", "/sEcTiOn/": "", "/OTHER/": "", "/other/": "/other/"} {
		if match, found := lookup(key); found != (expected != "") || found && match != expected {
			t.Errorf("%q where names don't fold: %q, found %v; expected %q", key, match, found, expected)
		}
	}
}

// R6 O-8: the rewrite of a path is the one that was found before, when each of its folders was a text made for it
// and compared with every rewrite: with names that fold and that don't, in a site without rewrites, and for paths
// that are a rewrite, are under one, differ from one in case, or end in "/".
func TestR6_O8_RewriteOfAPathAsBefore(t *testing.T) {
	initForTest(t)
	sites := [][]string{
		nil, {"/"}, {"/a/"}, {"/a/b/", "/a/"}, {"/A/b/", "/a/B/", "/x"}, {"/file.html", "/dir/file.html/"},
		{"/Section/", "/SECTION/", "/section/x/"}, {"/café/", "/K/"},
	}
	paths := []string{
		"/", "/a", "/a/", "/A", "/a/b", "/a/b/", "/a/B/c", "/A/B/c/d.html", "/x", "/x/", "/X/y", "/file.html",
		"/FILE.html", "/dir/file.html", "/dir/file.html/", "/section/x/y/z", "/SECTION/X", "/sEcTiOn/x/", "/CAFÉ/menu",
		"/k/kelvin", "/other/deep/path/of/a/site.css", "//", "/a//b",
	}
	for _, fold := range []bool{false, true} {
		foldForTest(t, fold)
		for _, keys := range sites {
			foldSite(t, keys...)
			for _, path := range paths {
				var rewrites map[string]string
				var target, matched string
				withReadLock(func() {
					rewrites = sitesMap["fold.test"][""]
					target, matched = rewrite(path, "fold.test", "")
				})
				if expectedTarget, expectedMatch := linearRewrite(rewrites, path, fold); target != expectedTarget || matched != expectedMatch {
					t.Errorf("%q among %q, folding %v: %q by %q; before, %q by %q", path, keys, fold, target, matched, expectedTarget, expectedMatch)
				}
			}
		}
	}
}

// R6 O-8: a site without rewrites looks nothing up, and the folders of a path are looked up as parts of it. Before,
// each was a text made for it, in every site and for every request: only the path with a "/" added is one now.
func TestR6_O8_RewriteMakesNoTextForAFolder(t *testing.T) {
	if raceEnabled {
		return // The race detector allocates on its own
	}
	initForTest(t)
	foldForTest(t, false) // Where names fold, the tests compare what is kept with the state at each use, and that allocates
	count := func(path string) (allocations float64) {
		withReadLock(func() {
			allocations = testing.AllocsPerRun(100, func() { rewrite(path, "fold.test", "") })
		})
		return allocations
	}
	foldSite(t)
	if allocations := count("/a/b/c/d/e/f.html"); allocations != 0 {
		t.Errorf("a site without rewrites: %.0f allocations for a path; expected none", allocations)
	}
	foldSite(t, "/other/", "/else/")
	if allocations := count("/a/b/c/d/e/"); allocations != 0 {
		t.Errorf("a site with rewrites, a folder six deep: %.0f allocations; expected none", allocations)
	}
	if allocations := count("/a/b/c/d/e/f.html"); allocations > 1 {
		t.Errorf("a site with rewrites, a file six deep: %.0f allocations; expected one, its path with a \"/\"", allocations)
	}
}

// R6 O-8: for any rewrites and any key, with names that fold and that don't, the lookup gives what comparing the key
// with each rewrite gave, and so does the lookup of the key as a whole request path.
func FuzzRewriteLookup(f *testing.F) {
	f.Add("/section/\n/Section/\n/SECTION/\n/other/", "/sEcTiOn/", true)
	f.Add("/a\n/A\n/K\n/k\n/K", "/k", true)
	f.Add("/a/\n/b/", "/A/", false)
	f.Add("", "/x", true)
	f.Add("\xff\n\xfe\n�", "\xfd", true)
	for i, sample := range foldSamples {
		f.Add(strings.Join(foldSamples, "\n"), sample, i%3 != 0)
	}
	initForTest(f)
	f.Fuzz(func(t *testing.T, joined string, key string, fold bool) {
		keys := strings.Split(joined, "\n")
		if len(keys) > 64 {
			keys = keys[:64]
		}
		foldForTest(t, fold)
		lookup := foldSite(t, keys...)
		var rewrites map[string]string
		withReadLock(func() { rewrites = sitesMap["fold.test"][""] })
		for _, asked := range append(keys, key, strings.ToUpper(key), strings.ToLower(key)) {
			match, found := lookup(asked)
			expected, expectedFound := linearRewriteKey(rewrites, asked, fold)
			if found != expectedFound || found && match != expected {
				t.Fatalf("%q among %q, folding %v: %q, found %v; comparing with each gives %q, found %v", asked, keys, fold, match, found, expected, expectedFound)
			}
			path := asked
			if !strings.HasPrefix(path, "/") {
				path = "/" + path // As every path of a request
			}
			var target, matched string
			withReadLock(func() { target, matched = rewrite(path, "fold.test", "") })
			if expectedTarget, expectedMatch := linearRewrite(rewrites, path, fold); target != expectedTarget || matched != expectedMatch {
				t.Fatalf("the path %q among %q, folding %v: %q by %q; before, %q by %q", path, keys, fold, target, matched, expectedTarget, expectedMatch)
			}
		}
	})
}
