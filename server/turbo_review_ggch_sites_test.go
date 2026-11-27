package server

// The tests of the findings about the sites of the external review of v2.5.2 (GGCH): each failed before its fix, but
// those that say they keep what already worked.

import (
	"os"
	"strings"
	"testing"
)

// GGCH H-09: each label of a name is up to 63 bytes, as DNS limits them: the labels above the third level were limited
// to 63 together, and a name of one label to 31.
func TestGGCH_H09_LabelsAreLimitedOneByOne(t *testing.T) {
	label := func(c string, n int) string { return strings.Repeat(c, n) }
	for name, want := range map[string]bool{
		label("a", 20) + "." + label("b", 20) + "." + label("c", 20) + "." + label("d", 20) + ".sub.example.com": true,
		label("h", 40):                       true, // A host of a local network
		"xn--" + label("v", 40):              true,
		label("a", 64) + ".a.b.example.com":  false,
		"a." + label("b", 64) + ".c.example": false,
		label("t", 64):                       false,
		"x." + strings.Repeat(label("y", 60)+".", 4) + "example.com": false, // More than 220 bytes
	} {
		if got, why := hostOk(name, false); got != want {
			t.Errorf("hostOk(%q) = %v %q; expected %v", name, got, why, want)
		}
	}
}

// GGCH H-09: a site whose name only a wildcard subdomain of another site covers is accepted, as that wildcard is after
// such a site; the name written is served. One that a subdomain written so already serves is still refused.
func TestGGCH_H09_ASiteThatOnlyAWildcardCovers(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:addSubdomain?s=localhost&d=*", tok); code != 200 {
		t.Fatalf("addSubdomain *: %d %q", code, body)
	}
	os.WriteFile(dir+"localhost/#/@/index.html", []byte("wildcard"), 0644)
	if code, body, _ := post(base, "/admin:inside:addSite?s=app.localhost", tok); code != 200 {
		t.Fatalf("addSite app.localhost with the subdomain * of localhost: %d %q", code, body)
	}
	os.WriteFile(dir+"app.localhost/@/index.html", []byte("app"), 0644)
	if _, body, err := rawGet(base, "app.localhost", "/"); err != nil || body != "app" {
		t.Errorf("app.localhost: %q %v; expected the site written", body, err)
	}
	if _, body, err := rawGet(base, "other.localhost", "/"); err != nil || body != "wildcard" {
		t.Errorf("other.localhost: %q %v; expected the wildcard", body, err)
	}
	// The same host twice: refused (keeps what worked)
	if code, body, _ := post(base, "/admin:inside:addSubdomain?s=localhost&d=www", tok); code != 200 {
		t.Fatalf("addSubdomain www: %d %q", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:addSite?s=www.localhost", tok); code != 400 {
		t.Errorf("addSite www.localhost with the subdomain www of localhost: %d %q; expected 400", code, body)
	}
}

// Review of v2.5.3 (B-4): a site whose name only a wildcard site covers (*.com, *) is accepted too, as the name written
// wins over it when a request is served: it was refused, as "Matches site: .*.com", in one order only. A subdomain
// written so is still the same host twice.
func TestGGCH_H09_ASiteThatOnlyAWildcardSiteCovers(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	defer globalMutex.Unlock()
	constructSiteLocked("*.com", "")
	if ok, message := addSite("example.com", false); !ok {
		t.Errorf("addSite example.com with the site *.com: %q", message)
	}
	constructSiteLocked("*", "")
	if ok, message := addSite("intranet", false); !ok {
		t.Errorf("addSite intranet with the site *: %q", message)
	}
	constructSiteLocked("example.net", "app")
	if ok, message := addSite("app.example.net", false); ok {
		t.Errorf("addSite app.example.net with the subdomain app of example.net: %v %q", ok, message)
	}
}

// Review of v2.5.3 (B-5): the name of a domain whose root isn't there, with its subdomains served, is no site's host
// for an alias: it answers 404, and an alias of it, kept until then, was dropped ("its host is a site's"), and lost
// from turbo.config at the next save.
func TestGGCH_H14_AnAliasOfADomainWithoutItsRoot(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	defer globalMutex.Unlock()
	constructSiteLocked("example.com", "www")
	constructSiteLocked("*.org", "api")
	for host, want := range map[string]bool{"example.com": false, "www.example.com": true, "x.example.com": true, "example.org": false, "api.example.org": true, "localhost": true} {
		if got := hostServedBySite(host); got != want {
			t.Errorf("hostServedBySite(%q): %v; expected %v", host, got, want)
		}
	}
	domainAliases["example.com"] = "localhost"
	dropAliasesOfSites()
	if _, kept := domainAliases["example.com"]; !kept {
		t.Error("the alias example.com, whose domain has no root, was dropped")
	}
	constructSiteLocked("example.com", "") // The root back: the site wins
	dropAliasesOfSites()
	if _, kept := domainAliases["example.com"]; kept {
		t.Error("the alias example.com kept with the root of example.com there")
	}
}

// withoutRootAt sets localhost up with its settings (configureLocalhost), a subdomain www with a preprocessor for "cgi"
// and a script, and takes the @ of localhost away (a deploy of the root in progress).
func withoutRootAt(t *testing.T) (dir, base, tok string) {
	t.Helper()
	dir = initForTest(t)
	base = startServer(t)
	tok = login(t, base)
	configureLocalhost(t, dir)
	if err := os.MkdirAll(dir+"localhost/www/@", 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dir+"localhost/www/@/script.cgi", []byte("SOURCE OF THE WWW SCRIPT"), 0644)
	updateSettings(true)
	globalMutex.Lock()
	ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "www")
	globalMutex.Unlock()
	if !ok {
		t.Fatal(msg)
	}
	if err := os.Rename(dir+"localhost/@", dir+"localhost/@.away"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	return dir, base, tok
}

// siteState is whether localhost (or a subdomain of it) is active, and kept without its folder.
func siteState(subdomain string) (active, kept bool) {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	_, active = sitesMap["localhost"][subdomain]
	_, kept = dormantSites["localhost"][subdomain]
	return active, kept
}

// GGCH H-14: without the @ of a site (a deploy that replaces it), only the site goes: its subdomains, whose folders are
// there, are still served (every *.example.com answered 404). The site's own name answers 404, never through a wildcard
// subdomain; its @ back, it comes back with its settings.
func TestGGCH_H14_SubdomainsStayWithoutTheRootsAt(t *testing.T) {
	dir, base, tok := withoutRootAt(t)
	if active, kept := siteState(""); active || !kept {
		t.Errorf("localhost without its @: active %v, kept %v; expected kept", active, kept)
	}
	if active, kept := siteState("www"); !active || kept {
		t.Errorf("www: active %v, kept %v; expected active", active, kept)
	}
	if body := wwwScript(t, base); strings.Contains(body, "SOURCE") || body == "" {
		t.Errorf("www.localhost/script.cgi: %.60q; expected the output of its preprocessor", body)
	}
	if res, _, err := rawGet(base, "localhost", "/script.cgi"); err != nil || res.StatusCode != 404 {
		t.Errorf("localhost while its @ is missing: %v %v; expected 404", res, err)
	}
	if code, body, _ := post(base, "/admin:inside:subdomains?s=localhost", tok); code != 200 || !strings.Contains(body, `"www"`) {
		t.Errorf("subdomains of localhost: %d %.80q; expected www", code, body)
	}
	if err := os.Rename(dir+"localhost/@.away", dir+"localhost/@"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	checkLocalhostKept(t, base, "its @ back")
	if body := wwwScript(t, base); strings.Contains(body, "SOURCE") {
		t.Errorf("www.localhost/script.cgi after the deploy: %.60q", body)
	}
}

// GGCH H-14: the domain itself is served only by its root: with the root kept without its @, the wildcard subdomain
// served it with its own rewrites.
func TestGGCH_H14_TheDomainIsNoWildcardsWhileItsRootIsKept(t *testing.T) {
	dir := initForTest(t)
	if err := os.MkdirAll(dir+"localhost/#/@", 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dir+"localhost/#/@/index.html", []byte("wildcard"), 0644)
	updateSettings(true)
	addRewrite := func() {
		globalMutex.Lock()
		defer globalMutex.Unlock()
		if ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{"/": "https://elsewhere.example/"}, false, "localhost", "*"); !ok {
			t.Fatal(msg)
		}
	}
	addRewrite()
	base := startServer(t)
	if err := os.Rename(dir+"localhost/@", dir+"localhost/@.away"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	if res, _, err := rawGet(base, "localhost", "/"); err != nil || res.StatusCode != 404 || res.Header.Get("Location") != "" {
		t.Errorf("localhost without its @: %v %v; expected 404, not the wildcard's", res, err)
	}
	if res, _, err := rawGet(base, "a.localhost", "/"); err != nil || res.StatusCode != 302 {
		t.Errorf("a.localhost: %v %v; expected the wildcard's redirection", res, err)
	}
	globalMutex.RLock()
	matched, _, _, _ := detectWildcards("", "localhost")
	serving := servingSite("localhost")
	globalMutex.RUnlock()
	if matched || serving != "" {
		t.Errorf("the domain without its root: matched %v, served by %q", matched, serving)
	}
}

// GGCH H-14: the folder of a domain gone, its root and its subdomains are kept, each, and the domain is no longer
// active.
func TestGGCH_H14_TheWholeFolderGoes(t *testing.T) {
	dir, _, _ := withoutRootAt(t)
	if err := os.Rename(dir+"localhost", t.TempDir()+"/localhost"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	for _, subdomain := range []string{"", "www"} {
		if active, kept := siteState(subdomain); active || !kept {
			t.Errorf("%q without the folder of localhost: active %v, kept %v; expected kept", subdomain, active, kept)
		}
	}
	globalMutex.RLock()
	_, domainActive := sitesMap["localhost"]
	globalMutex.RUnlock()
	if domainActive {
		t.Error("localhost is still active, without any site")
	}
}

// GGCH H-14: saved and read again, the root kept and its subdomain served stay so.
func TestGGCH_H14_SavedAndReadAgain(t *testing.T) {
	dir, base, _ := withoutRootAt(t)
	if !saveDefaultConfig() {
		t.Fatal("saving failed")
	}
	saved := savedConfig(t, dir)["localhost"]
	if _, root := saved[""]; !root {
		t.Errorf("the section of localhost wasn't saved: %v", saved)
	}
	resetSettings()
	loadConfig(t, dir, string(mustReadFile(t, dir+"turbo.config")))
	if active, kept := siteState(""); active || !kept {
		t.Errorf("localhost read again: active %v, kept %v; expected kept", active, kept)
	}
	if active, kept := siteState("www"); !active || kept {
		t.Errorf("www read again: active %v, kept %v; expected active", active, kept)
	}
	if body := wwwScript(t, base); strings.Contains(body, "SOURCE") || body == "" {
		t.Errorf("www.localhost/script.cgi read again: %.60q", body)
	}
}

// GGCH H-14: deleting the last subdomain of a domain whose root is kept deletes the domain; the root stays kept.
func TestGGCH_H14_TheLastSubdomainGoes(t *testing.T) {
	_, base, tok := withoutRootAt(t)
	if code, body, _ := post(base, "/admin:inside:delSite?s=localhost&d=www&b=Admin", tok); code != 200 {
		t.Fatalf("delSite www: %d %q", code, body)
	}
	globalMutex.RLock()
	_, domainActive := sitesMap["localhost"]
	globalMutex.RUnlock()
	if _, kept := siteState(""); domainActive || !kept {
		t.Errorf("after deleting www: localhost active %v, its root kept %v; expected only the root kept", domainActive, kept)
	}
}

// GGCH H-14: a folder of the sites directory without its own @, of no site Turbo knows, isn't looked into: a copy of a
// site's folder ("backup/example.com/@") became the host example.com.backup, its scripts served as text. With the site
// in turbo.config, its subdomains are served.
func TestGGCH_H14_AFolderOfNoKnownSiteIsNotLookedInto(t *testing.T) {
	dir := initForTest(t)
	if err := os.MkdirAll(dir+"backup/example.com/@", 0755); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	globalMutex.RLock()
	_, active := sitesMap["backup"]
	globalMutex.RUnlock()
	if active {
		t.Error("backup/example.com/@ was activated, without backup/@ nor a site backup")
	}
	if err := os.MkdirAll(dir+"known.test/api/@", 0755); err != nil {
		t.Fatal(err)
	}
	loadConfig(t, dir, `{"^":{"v":"2"},"known.test":{"api":{"-":{"index.html":"1"}}}}`)
	globalMutex.RLock()
	_, api := sitesMap["known.test"]["api"]
	_, root := sitesMap["known.test"][""]
	globalMutex.RUnlock()
	if !api || root {
		t.Errorf("known.test of turbo.config without its @: api active %v, root active %v; expected only api", api, root)
	}
}

// mustReadFile reads a file, or fails the test.
func mustReadFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
