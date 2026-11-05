package main

// v2.4.2: a site that turbo.config names only through its subdomains (it has no "" section), or with an empty or
// null entry, isn't described by the file: it gets what a site found on disk gets, index.html as its index and the
// state of its certificate, so GET / answers. It was built with nothing, and GET / gave 404. A site with a ""
// section keeps exactly what that section says, no index included.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rootWithoutSectionDir leaves, in a new sites directory, localhost (index.html "hello", and a certificate) and
// its subdomain www (index.html "www"), with nothing loaded yet: as at startup.
func rootWithoutSectionDir(t *testing.T) string {
	t.Helper()
	dir := initForTest(t)
	if err := os.MkdirAll(dir+"localhost/www/@", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"localhost/www/@/index.html", []byte("www"), 0644); err != nil {
		t.Fatal(err)
	}
	writeTestCertificate(t, dir+"localhost/", 90*24*time.Hour, "localhost")
	resetSettings() // As at startup: the site doesn't exist yet when turbo.config is read
	return dir
}

// checkRootServed checks that localhost answers GET / with its index.html, with the state of its certificate
// recorded (C) and HTTPS off (S), and that www answers with its own.
func checkRootServed(t *testing.T, when string) {
	t.Helper()
	base := startServer(t)
	if code, body, err := get(base, "/", nil); err != nil || code != 200 || body != "hello" {
		t.Errorf("%s: GET / -> %d %q %v; expected 200 hello", when, code, body, err)
	}
	globalMutex.RLock()
	certificate, https := siteSSLConfig["localhost"]["C"], siteSSLConfig["localhost"]["S"]
	globalMutex.RUnlock()
	if certificate != true || https != 0 {
		t.Errorf("%s: C = %v and S = %v; expected true (its certificate is there) and 0", when, certificate, https)
	}
	if res, body, err := rawGet(base, "www.localhost", "/"); err != nil || res.StatusCode != 200 || body != "www" {
		t.Errorf("%s: GET www.localhost/ -> %v %q %v; expected 200 www", when, res, body, err)
	}
}

func TestRP3_RootWithoutSectionGetsItsIndex(t *testing.T) {
	for _, config := range []string{
		`{"^":{"v":"2"},"localhost":{"www":{"-":{"index.html":"1"}}}}`,
		`{"^":{"v":"2"},"localhost":{}}`,
		`{"^":{"v":"2"},"localhost":null}`,
	} {
		t.Run(config, func(t *testing.T) {
			dir := rootWithoutSectionDir(t)
			loadConfig(t, dir, config)
			checkRootServed(t, "read from the file")
			// Saved, the site has its section, with the index it has now; read again, it is the same.
			saveDefaultConfig()
			raw := savedConfig(t, dir)
			root, _ := raw["localhost"][""].(map[string]interface{})
			indexes, _ := root["-"].(map[string]interface{})
			if len(indexes) != 1 || indexes["index.html"] != "1" {
				t.Errorf("saved section of localhost: %v; expected the index index.html", raw["localhost"][""])
			}
			saved, err := os.ReadFile(dir + "turbo.config")
			if err != nil {
				t.Fatal(err)
			}
			resetSettings()
			loadConfig(t, dir, string(saved))
			checkRootServed(t, "saved and read again")
		})
	}
}

// A "" section is what the site is: one without indexes in it stays without them (delIndex leaves a site so, and
// saving writes "-":{}).
func TestRP3_RootSectionKeepsItsIndexes(t *testing.T) {
	for _, config := range []string{
		`{"^":{"v":"2"},"localhost":{"":{}}}`,
		`{"^":{"v":"2"},"localhost":{"":{"-":{}}}}`,
		`{"^":{"v":"2"},"localhost":{"":{"-":{}},"www":{"-":{"index.html":"1"}}}}`,
	} {
		t.Run(config, func(t *testing.T) {
			dir := rootWithoutSectionDir(t)
			loadConfig(t, dir, config)
			base := startServer(t)
			if code, body, err := get(base, "/", nil); err != nil || code != 404 {
				t.Errorf("GET / -> %d %q %v; expected 404: the site has no index", code, body, err)
			}
			globalMutex.RLock()
			indexes := len(indexFiles["localhost"])
			globalMutex.RUnlock()
			if indexes != 0 {
				t.Errorf("localhost has %d indexes; expected none, as its section says", indexes)
			}
		})
	}
}

// A site kept without its folder that the file names only through its subdomains comes back, with its folder, as
// a site found on disk (index.html), and its subdomain with its section.
func TestRP3_KeptRootWithoutSectionComesBack(t *testing.T) {
	dir := rootWithoutSectionDir(t)
	if err := os.Rename(dir+"localhost/@", dir+"localhost/@.away"); err != nil { // A deploy in progress
		t.Fatal(err)
	}
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"www":{"-":{"index.html":"1"},".":{"X-Www":"kept"}}}}`)
	globalMutex.RLock()
	_, rootActive := sitesMap["localhost"]
	_, wwwKept := dormantSites["localhost"]["www"]
	globalMutex.RUnlock()
	if rootActive || !wwwKept {
		t.Fatalf("without its @: localhost active %v, www kept %v; expected localhost inactive and www kept", rootActive, wwwKept)
	}
	if err := os.Rename(dir+"localhost/@.away", dir+"localhost/@"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	checkRootServed(t, "its @ back")
	globalMutex.RLock()
	header := customHeaders["www.localhost"]["X-Www"]
	globalMutex.RUnlock()
	if header != "kept" {
		t.Errorf("www's header after its site came back: %q; expected kept", header)
	}
}

// What the site gets is checked against what the reload looked at before taking the global lock: also for a site
// that the scan of the sites directory didn't list (here its folder appears just after the scan), the state of its
// certificate is looked at without the lock.
func TestRP3_RootWithoutSectionNotLookedAtUnderLock(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", 90*24*time.Hour, "localhost")
	away := filepath.Join(t.TempDir(), "localhost") // Outside the sites directory
	if err := os.Rename(dir+"localhost", away); err != nil {
		t.Fatal(err)
	}
	var underLock []string
	moved := false
	previous := siteDirStat
	siteDirStat = func(name string) (os.FileInfo, error) {
		if name == dir+"localhost" && !moved { // Looked at after the scan: the folder appears
			moved = true
			if err := os.Rename(away, dir+"localhost"); err != nil {
				t.Error(err)
			}
		}
		if lookedDisk != nil { // Within withDiskLook, by the reload itself: no one else looks at the disk here
			underLock = append(underLock, name)
		}
		return previous(name)
	}
	t.Cleanup(func() { siteDirStat = previous })
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{}}`)
	siteDirStat = previous
	if !moved {
		t.Fatal("the folder of localhost wasn't looked at")
	}
	if len(underLock) != 0 {
		t.Errorf("looked at under the global lock: %s; expected nothing", strings.Join(underLock, ", "))
	}
	globalMutex.RLock()
	certificate := siteSSLConfig["localhost"]["C"]
	_, index := indexFiles["localhost"]["index.html"]
	globalMutex.RUnlock()
	if certificate != true || !index {
		t.Errorf("localhost: C = %v, index.html %v; expected its certificate and its index", certificate, index)
	}
}
