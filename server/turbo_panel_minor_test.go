package server

// Review of 6046dbe (R6): the minor points of the panel and the API. The certificate dialog's e-mail and adapter, the
// aliases of each site when saving, numbers of schema 1, what a cut left in the sites directory, and the status of a
// folder that can't be created.

import (
	"bufio"
	"bytes"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// R6 P-05b: cfgC saves the e-mail and the adapter it is sent only when both are valid. With a valid e-mail and an
// invalid adapter, the e-mail was saved and the answer was the adapter's error, so the panel couldn't know what was.
func TestR6_P05b_CertificateEmailAndAdapterTogether(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	defer globalMutex.Unlock()
	ok, msg := siteSSLSettingCheckers["C"](false, "1", "localhost", "", "new@example.test", "bad adapter")
	if ok || !strings.HasPrefix(msg, "Invalid adapter") {
		t.Errorf("cfgC with a valid e-mail and an invalid adapter: %v %q", ok, msg)
	}
	if email := siteSSLConfig["localhost"].asSection()["E"]; email != "" {
		t.Errorf("the e-mail was saved with the adapter refused: %q", email)
	}
	ok, msg = siteSSLSettingCheckers["C"](false, "1", "localhost", "", "x", "dns-route53")
	if ok || !strings.HasPrefix(msg, "Invalid e-mail") {
		t.Errorf("cfgC with an invalid e-mail and a valid adapter: %v %q", ok, msg)
	}
	if adapter := siteSSLConfig["localhost"].asSection()["A"]; adapter != "" {
		t.Errorf("the adapter was saved with the e-mail refused: %q", adapter)
	}
}

// siteAliasListBefore is createSiteAliasList as it was: every alias sorted, for each site.
func siteAliasListBefore(siteKey string) string {
	var jsonBuilder strings.Builder
	jsonBuilder.WriteString("{")
	delimiter := ""
	for _, aliasName := range sortedKeys(domainAliases) {
		if domainAliases[aliasName] == siteKey {
			jsonBuilder.WriteString(delimiter + jsonString(aliasName) + ":\"\"")
			delimiter = ","
		}
	}
	jsonBuilder.WriteString("}")
	return "\"&\":" + jsonBuilder.String()
}

// R6 P-15: the aliases of each site, when saving, are the same as before, without sorting every alias of every site
// for each of them.
func TestR6_P15_AliasesOfEachSite(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	defer globalMutex.Unlock()
	sites := []string{"localhost", "a.test", "b.test", "c.test"}
	for i := 0; i < 40; i++ {
		domainAliases["alias"+strconv.Itoa(39-i)+".example"] = sites[i%len(sites)]
	}
	for _, site := range append(sites, "none.test") {
		if got, want := createSiteAliasList(site), siteAliasListBefore(site); got != want {
			t.Errorf("aliases of %s: %s; expected %s", site, got, want)
		}
	}
}

// BenchmarkR6_P15_AliasesWhenSaving builds the alias list of 2000 sites with 2000 aliases, as a save does.
func BenchmarkR6_P15_AliasesWhenSaving(b *testing.B) {
	resetTestState(b.TempDir() + "/")
	globalMutex.Lock()
	defer globalMutex.Unlock()
	sites := make([]string, 2000)
	for i := range sites {
		sites[i] = "site" + strconv.Itoa(i) + ".test"
		domainAliases["alias"+strconv.Itoa(i)+".example"] = sites[i]
	}
	sort.Strings(sites)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, site := range sites {
			createSiteAliasList(site)
		}
	}
}

// R6 P-17a: CIL and CIS of a turbo.config of schema 1 are migrated (from units of 10 ms) also when they are JSON
// numbers. Only text was: 500 was read as 500 ms, below the minimum, and CIL went back to its default.
func TestR6_P17a_SchemaOneNumbers(t *testing.T) {
	dir := initForTest(t)
	loadConfig(t, dir, `{".":{"CIL":500,"CIS":10},"localhost":{"":{}}}`)
	if cil, cis := time.Duration(serverRequestLimits.CIL.Load()), time.Duration(serverRequestLimits.CIS.Load()); cil != 5*time.Second || cis != 100*time.Millisecond {
		t.Errorf("CIL %v and CIS %v; expected 5s and 100ms", cil, cis)
	}
}

// R6 P-17b: what an upload, a deletion or a save cut by a stop of Turbo left in the sites directory is dealt with
// at start: a site without @, with the @ it had aside, gets it back; an upload's folder, a deleted site's folder
// and a save's temporary file, older than an hour, are deleted; the rest is only warned about. Nothing was done: a
// site cut halfway through an upload stayed without its @, so without a site, until it was put back by hand.
func TestR6_P17b_WhatACutLeft(t *testing.T) {
	dir := initForTest(t)
	other := t.TempDir() + "/"
	old := time.Now().Add(-2 * time.Hour)
	mk := func(path string, aged bool) {
		t.Helper()
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(path+"/index.html", []byte(path), 0644)
		if aged {
			os.Chtimes(path, old, old)
		}
	}
	touch := func(path string, aged bool) {
		t.Helper()
		os.WriteFile(path, []byte("{}"), 0600)
		if aged {
			os.Chtimes(path, old, old)
		}
	}
	mk(dir+"a.test/@.previous-1111", false) // Without @: put back
	mk(dir+"b.test/@", false)               // With @: only a warning
	mk(dir+"b.test/@.previous-2222", false)
	mk(dir+"c.test/@.previous-3333", false) // Two: none chosen
	mk(dir+"c.test/@.previous-4444", false)
	mk(dir+"d.test/@", false)
	mk(dir+"d.test/@.upload-5555", true) // An upload's folder: deleted when old
	mk(dir+"d.test/@.upload-6666", false)
	mk(dir+"e.test/@", false)
	mk(dir+"e.test/sub/@.previous-7777", false) // A subdomain: put back
	mk(dir+".turbo-deleted-abc", true)
	mk(dir+".turbo-deleted-def", false)
	mk(dir+"e.test/.turbo-deleted-ghi", true)
	touch(dir+"turbo.config.111.tmp", true)
	touch(dir+"turbo.config.222.tmp", false)
	touch(other+"turbo.config.333.tmp", true)
	logs := captureLog(t)
	cleanInterruptedWork(dir, other)
	there := func(path string) bool { _, err := os.Stat(path); return err == nil }
	for path, wanted := range map[string]bool{
		"a.test/@/index.html": true, "a.test/@.previous-1111": false,
		"b.test/@": true, "b.test/@.previous-2222": true,
		"c.test/@": false, "c.test/@.previous-3333": true, "c.test/@.previous-4444": true,
		"d.test/@.upload-5555": false, "d.test/@.upload-6666": true,
		"e.test/sub/@/index.html": true,
		".turbo-deleted-abc":      false, ".turbo-deleted-def": true, "e.test/.turbo-deleted-ghi": false,
		"turbo.config.111.tmp": false, "turbo.config.222.tmp": true,
	} {
		if there(dir+path) != wanted {
			t.Errorf("%s: there %v; expected %v", path, !wanted, wanted)
		}
	}
	if there(other + "turbo.config.333.tmp") {
		t.Error("the old temporary file of the start directory is still there")
	}
	for _, said := range []string{"a.test", "b.test", "c.test", "e.test/sub"} {
		if !strings.Contains(logs.String(), said) {
			t.Errorf("the log doesn't name %s:\n%s", said, logs.String())
		}
	}
}

// R6 P-17b: Turbo deals with it when it starts, before it serves: a site cut halfway through an upload is served.
func TestR6_P17b_AtStart(t *testing.T) {
	dir := t.TempDir() + "/"
	if err := os.MkdirAll(dir+"localhost/@.previous-abcd", 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dir+"localhost/@.previous-abcd/index.html", []byte("back"), 0644)
	p := startTurbo(t, dir)
	if err, ended := p.exited(); ended {
		t.Fatalf("Turbo ended: %v\n%s", err, p.out.String())
	}
	req, _ := http.NewRequest("GET", p.base+"/", nil)
	req.Host = "localhost"
	res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body := new(strings.Builder)
	bufio.NewReader(res.Body).WriteTo(body)
	if res.StatusCode != 200 || body.String() != "back" {
		t.Errorf("the site whose @ was aside: %d %q\n%s", res.StatusCode, body.String(), p.out.String())
	}
}

// R6 P-18a: a site whose folder can't take the upload is a failure of the server: 500, logged. It answered 400, as
// if the request were wrong.
func TestR6_P18a_FolderThatCantBeWrittenIs500(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if err := os.RemoveAll(dir + "localhost"); err != nil { // Still active until the next reload
		t.Fatal(err)
	}
	logs := captureLog(t)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("b", "Admin")
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="f"; filename="index.html"`)
	p, _ := w.CreatePart(h)
	p.Write([]byte("x"))
	w.Close()
	if code, body := hardUploadBody(t, base, tok, w.FormDataContentType(), buf.Bytes()); code != 500 || body != "Directory inaccessible" {
		t.Errorf("an upload to a folder that isn't there: %d %q; expected 500", code, body)
	}
	if !strings.Contains(logs.String(), "hardUpload") {
		t.Errorf("not logged:\n%s", logs.String())
	}
}
