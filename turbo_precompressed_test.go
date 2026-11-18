package main

// Review of 6046dbe (R6), O-11: precompressed files. A site with the setting "Z" on answers the request of a file
// with the file.br or file.gz that is next to it, when the request accepts it. Off, as every site is until someone
// turns it on, nothing changes.

import (
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"turbo/customNetHttp"
)

// R6 O-11: what a request accepts, by its Accept-Encoding.
func TestR6_O11_AcceptedEncodings(t *testing.T) {
	for _, c := range []struct {
		header        []string
		first, second string
	}{
		{nil, "", ""}, {[]string{""}, "", ""}, {[]string{"identity"}, "", ""}, {[]string{"deflate, zstd"}, "", ""},
		{[]string{"gzip"}, "gzip", ""}, {[]string{"br"}, "br", ""}, {[]string{"gzip, br"}, "br", "gzip"}, {[]string{"br, gzip"}, "br", "gzip"},
		{[]string{"gzip, deflate, br;q=0.5"}, "gzip", "br"}, {[]string{"gzip;q=0.5, br;q=0.6"}, "br", "gzip"},
		{[]string{"br;q=0, gzip"}, "gzip", ""}, {[]string{"gzip;q=0"}, "", ""}, {[]string{"gzip;q=0.000, br;q=0.001"}, "br", ""},
		{[]string{"*"}, "br", "gzip"}, {[]string{"*;q=0"}, "", ""}, {[]string{"gzip;q=0, *"}, "br", ""}, {[]string{"*;q=0.2, gzip"}, "gzip", "br"},
		{[]string{"GZIP ; Q=0.8 , BR"}, "br", "gzip"}, {[]string{" gzip\t;\tq = 0.8"}, "gzip", ""},
		{[]string{"gzip", "br;q=0.9"}, "gzip", "br"}, {[]string{"gzip, gzip;q=0"}, "", ""}, {[]string{"br;q=1., gzip;q=0.999"}, "br", "gzip"},
		// What isn't written as it should be isn't accepted: the file is served as it is
		{[]string{"gzip;q=1.5"}, "", ""}, {[]string{"gzip;q=0.0001"}, "", ""}, {[]string{"gzip;level=9"}, "", ""}, {[]string{"gzip;q="}, "", ""},
		{[]string{"gzip;q=.5"}, "", ""}, {[]string{"gzip;q=0,5"}, "", ""}, {[]string{"gzip;q=-1"}, "", ""}, {[]string{"x-gzip, brotli"}, "", ""},
	} {
		if first, second := acceptedEncodings(c.header); first != c.first || second != c.second {
			t.Errorf("acceptedEncodings(%q) = %q, %q; expected %q, %q", c.header, first, second, c.first, c.second)
		}
	}
}

// R6 O-11: for any header, the encodings are those two or none, without repeating one; a header is read the same
// in other capitals, as one line or as several, and with another encoding after it.
func FuzzAcceptEncoding(f *testing.F) {
	for _, header := range []string{"gzip, br", "br;q=0, gzip", "*;q=0.2, gzip", "gzip;q=1.5", "GZIP ; Q=0.8 , BR", "", ",,;q=;", "gzip;q=0.5;q=1", "br\x00, gzip"} {
		f.Add(header)
	}
	f.Fuzz(func(t *testing.T, header string) {
		first, second := acceptedEncodings([]string{header})
		valid := map[string]bool{"": true, "br": true, "gzip": true}
		if !valid[first] || !valid[second] || first == "" && second != "" || first != "" && first == second {
			t.Fatalf("acceptedEncodings(%q) = %q, %q", header, first, second)
		}
		lower := strings.ToLower(header)
		if first != "" && !strings.Contains(lower, "*") && (!strings.Contains(lower, first) || second != "" && !strings.Contains(lower, second)) {
			t.Fatalf("acceptedEncodings(%q) = %q, %q, which it doesn't name", header, first, second)
		}
		for name, other := range map[string][]string{
			"in lines": strings.Split(header, ","), "with another after it": {header + ", identity"}, "with another before it": {"compress;q=0.3," + header},
		} {
			if otherFirst, otherSecond := acceptedEncodings(other); otherFirst != first || otherSecond != second {
				t.Fatalf("acceptedEncodings(%q) = %q, %q; %s, %q, %q", header, first, second, name, otherFirst, otherSecond)
			}
		}
		if upper := strings.ToUpper(header); strings.ToLower(upper) == lower { // Not where the capitals of a letter outside ASCII change it
			if otherFirst, otherSecond := acceptedEncodings([]string{upper}); otherFirst != first || otherSecond != second {
				t.Fatalf("acceptedEncodings(%q) = %q, %q; in capitals, %q, %q", header, first, second, otherFirst, otherSecond)
			}
		}
	})
}

// precompressedSite leaves z.test with files and variants of every kind, and returns its handler and how to turn
// its setting on and off.
func precompressedSite(t *testing.T) (dir string, get func(method, uri string, headers ...string) *responseRecorder, set func(value string)) {
	t.Helper()
	dir = initForTest(t)
	for name, content := range map[string]string{
		"a.css": "body { margin: 0 }", "a.css.br": "BR-OF-A", "a.css.gz": "GZ-OF-A",
		"only.js": "let only = 1", "only.js.gz": "GZ-OF-ONLY",
		"plain.txt": "plain",
		"noext":     "<html><body>page</body></html>", "noext.br": "BR-OF-NOEXT",
		"dir/index.html": "<p>index</p>", "dir/index.html.br": "BR-OF-INDEX",
		"empty.css": "p {}", "empty.css.br": "",
		"folder.css": "q {}", "folder.css.br/x": "inside",
		"script.cgi": "the source of a script", "script.cgi.br": "BR-OF-THE-SOURCE",
	} {
		path := dir + "z.test/@/" + name
		if err := os.MkdirAll(path[:strings.LastIndexByte(path, '/')], 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	updateSettings(true)
	set = func(value string) {
		t.Helper()
		if applied, answer := lockedCheck(func() (bool, string) { return siteSSLSettingCheckers["Z"](false, value, "z.test", "") }); !applied {
			t.Fatalf("cfgZ %s: %s", value, answer)
		}
	}
	handler := serverHandlerFn(false)
	get = func(method, uri string, headers ...string) *responseRecorder {
		request := benchRequest("z.test", uri, "203.0.113.9:40000")
		request.Method, request.Body = method, customNetHttp.NoBody // As the server gives a request without a body
		for i := 0; i+1 < len(headers); i += 2 {
			request.Header.Set(headers[i], headers[i+1])
		}
		recorder := &responseRecorder{}
		handler(recorder, request)
		return recorder
	}
	return dir, get, set
}

// R6 O-11: with the setting off, a request that accepts br gets the file as it is, as it always did; and the setting
// is turned on and off by its validator, for a site that exists.
func TestR6_O11_OffNothingChanges(t *testing.T) {
	_, get, set := precompressedSite(t)
	plain := get("GET", "/a.css")
	accepting := get("GET", "/a.css", "Accept-Encoding", "br, gzip")
	if accepting.code != 200 || accepting.body.String() != "body { margin: 0 }" || !reflect.DeepEqual(accepting.header, plain.header) {
		t.Errorf("off, a request that accepts br: %d %q %v; without Accept-Encoding, %v", accepting.code, accepting.body.String(), accepting.header, plain.header)
	}
	if accepting.header.Get("Vary") != "" || accepting.header.Get("Content-Encoding") != "" {
		t.Errorf("off: Vary %q, Content-Encoding %q", accepting.header.Get("Vary"), accepting.header.Get("Content-Encoding"))
	}
	set("1")
	if on := get("GET", "/a.css", "Accept-Encoding", "br, gzip"); on.body.String() != "BR-OF-A" {
		t.Errorf("on: %q", on.body.String())
	}
	set("0")
	if off := get("GET", "/a.css", "Accept-Encoding", "br, gzip"); off.body.String() != "body { margin: 0 }" || off.header.Get("Vary") != "" {
		t.Errorf("off again: %q, Vary %q", off.body.String(), off.header.Get("Vary"))
	}
	for _, c := range []struct{ value, domain, subdomain, expected string }{
		{"2", "z.test", "", "Invalid value"}, {"", "z.test", "", "Invalid value"},
		{"1", "missing.test", "", "Site not found"}, {"1", "z.test", "missing", "Subdomain not found"},
	} {
		if applied, answer := lockedCheck(func() (bool, string) { return siteSSLSettingCheckers["Z"](false, c.value, c.domain, c.subdomain) }); applied || answer != c.expected {
			t.Errorf("cfgZ %q for %q/%q: %v %q; expected %q", c.value, c.subdomain, c.domain, applied, answer, c.expected)
		}
	}
}

// R6 O-11: with the setting on, who gets a variant and who gets the file.
func TestR6_O11_VariantsAndWhoGetsThem(t *testing.T) {
	dir, get, set := precompressedSite(t)
	set("1")
	type expectation struct {
		code               int
		body, encoding     string
		contentType, about string
	}
	check := func(recorder *responseRecorder, expected expectation) {
		t.Helper()
		if recorder.code != expected.code || recorder.body.String() != expected.body || recorder.header.Get("Content-Encoding") != expected.encoding {
			t.Errorf("%s: %d %q, Content-Encoding %q; expected %d %q, %q", expected.about, recorder.code, recorder.body.String(), recorder.header.Get("Content-Encoding"), expected.code, expected.body, expected.encoding)
		}
		if expected.contentType != "" && recorder.header.Get("Content-Type") != expected.contentType {
			t.Errorf("%s: Content-Type %q; expected %q", expected.about, recorder.header.Get("Content-Type"), expected.contentType)
		}
		if expected.code < 300 && recorder.header.Get("Vary") != "Accept-Encoding" {
			t.Errorf("%s: Vary %q; expected Accept-Encoding, on every file of the site", expected.about, recorder.header.Get("Vary"))
		}
	}

	brotli := get("GET", "/a.css", "Accept-Encoding", "gzip, deflate, br")
	check(brotli, expectation{200, "BR-OF-A", "br", "text/css; charset=utf-8", "a request that accepts br and gzip"})
	if brotli.header.Get("Content-Length") != "7" || brotli.header.Get("Accept-Ranges") != "" || !strings.HasSuffix(brotli.header.Get("Etag"), `-br"`) {
		t.Errorf("the variant: Content-Length %q, Accept-Ranges %q, ETag %q; expected its 7 bytes, no ranges and an ETag of its own", brotli.header.Get("Content-Length"), brotli.header.Get("Accept-Ranges"), brotli.header.Get("Etag"))
	}
	gzip := get("GET", "/a.css", "Accept-Encoding", "gzip")
	check(gzip, expectation{200, "GZ-OF-A", "gzip", "text/css; charset=utf-8", "a request that accepts gzip"})
	if gzip.header.Get("Etag") == brotli.header.Get("Etag") || gzip.header.Get("Etag") == "" {
		t.Errorf("the ETag of the gzip variant, %q, and of the br one, %q: each has its own", gzip.header.Get("Etag"), brotli.header.Get("Etag"))
	}
	check(get("GET", "/a.css", "Accept-Encoding", "br;q=0, gzip"), expectation{200, "GZ-OF-A", "gzip", "", "br refused with q=0"})
	check(get("GET", "/a.css", "Accept-Encoding", "gzip;q=0.9, br;q=0.1"), expectation{200, "GZ-OF-A", "gzip", "", "gzip preferred"})
	check(get("GET", "/a.css", "Accept-Encoding", "br;q=0, gzip;q=0"), expectation{200, "body { margin: 0 }", "", "text/css; charset=utf-8", "both refused"})
	check(get("GET", "/a.css"), expectation{200, "body { margin: 0 }", "", "", "without Accept-Encoding"})
	check(get("GET", "/a.css", "Accept-Encoding", "identity"), expectation{200, "body { margin: 0 }", "", "", "identity only"})
	check(get("GET", "/only.js", "Accept-Encoding", "br, gzip"), expectation{200, "GZ-OF-ONLY", "gzip", "", "a file with only its .gz"})
	check(get("GET", "/only.js", "Accept-Encoding", "br"), expectation{200, "let only = 1", "", "", "a file without the variant accepted"})
	check(get("GET", "/plain.txt", "Accept-Encoding", "br, gzip"), expectation{200, "plain", "", "", "a file without variants"})
	check(get("GET", "/noext", "Accept-Encoding", "br"), expectation{200, "BR-OF-NOEXT", "br", "text/html; charset=utf-8", "a file without extension: the type of what it has"})
	check(get("GET", "/dir/", "Accept-Encoding", "br"), expectation{200, "BR-OF-INDEX", "br", "text/html; charset=utf-8", "the index of a folder"})
	check(get("GET", "/empty.css", "Accept-Encoding", "br"), expectation{200, "p {}", "", "", "an empty variant"})
	check(get("GET", "/folder.css", "Accept-Encoding", "br"), expectation{200, "q {}", "", "", "a variant that is a folder"})

	head := get("HEAD", "/a.css", "Accept-Encoding", "br")
	check(head, expectation{200, "", "br", "text/css; charset=utf-8", "HEAD"})
	if head.header.Get("Content-Length") != "7" {
		t.Errorf("HEAD: Content-Length %q; expected that of the variant", head.header.Get("Content-Length"))
	}
	ranged := get("GET", "/a.css", "Accept-Encoding", "br", "Range", "bytes=0-3")
	check(ranged, expectation{206, "body", "", "", "a range: of the file as it is"})
	check(get("POST", "/a.css", "Accept-Encoding", "br"), expectation{get("POST", "/a.css").code, get("POST", "/a.css").body.String(), "", "", "another method"})

	unchanged := get("GET", "/a.css", "Accept-Encoding", "br", "If-None-Match", brotli.header.Get("Etag"))
	if unchanged.code != 304 || unchanged.body.Len() != 0 || unchanged.header.Get("Content-Length") != "" {
		t.Errorf("If-None-Match with the ETag of the variant: %d %q, Content-Length %q; expected 304", unchanged.code, unchanged.body.String(), unchanged.header.Get("Content-Length"))
	}
	check(get("GET", "/a.css", "Accept-Encoding", "br", "If-None-Match", gzip.header.Get("Etag")), expectation{200, "BR-OF-A", "br", "", "If-None-Match with the ETag of the other variant"})
	// A range is of the file as it is, which isn't the response that the ETag of the variant names: the whole file
	check(get("GET", "/a.css", "Accept-Encoding", "br", "If-Range", brotli.header.Get("Etag"), "Range", "bytes=0-3"), expectation{200, "body { margin: 0 }", "", "", "a range with If-Range and the ETag of the variant"})

	// A URL that ends in /index.html keeps its own treatment, whatever it is
	set("0")
	before := get("GET", "/dir/index.html", "Accept-Encoding", "br")
	set("1")
	if after := get("GET", "/dir/index.html", "Accept-Encoding", "br"); after.code != before.code || after.body.String() != before.body.String() || after.header.Get("Content-Encoding") != "" {
		t.Errorf("/dir/index.html: %d %q, Content-Encoding %q; with the setting off, %d %q", after.code, after.body.String(), after.header.Get("Content-Encoding"), before.code, before.body.String())
	}

	// The target of a rewrite, and the MIME type that the site gives
	withGlobalLock(func() {
		for kind, entry := range map[string][2]string{"=": {"/old", "/a.css"}, "$": {"css", "text/x-site"}} {
			if ok, msg := subdomainContentCheckers[kind](true, map[string]interface{}{entry[0]: entry[1]}, false, "z.test", ""); !ok {
				t.Fatalf("%s: %s", kind, msg)
			}
		}
	})
	check(get("GET", "/old", "Accept-Encoding", "br"), expectation{200, "BR-OF-A", "br", "text/x-site", "the target of a rewrite, with the MIME type of the site"})

	// A header of the site that says how the response is encoded, or which one it is: the file as it is
	for _, name := range []string{"Content-Encoding", "ETag"} {
		value := map[string]string{"Content-Encoding": "identity", "ETag": `"of-the-site"`}[name]
		withGlobalLock(func() { customHeaders["z.test"][name] = value })
		if with := get("GET", "/a.css", "Accept-Encoding", "br"); with.body.String() != "body { margin: 0 }" || with.header.Get(name) != value {
			t.Errorf("with the header %s of the site: %q, %s %q; expected the file as it is, with that header", name, with.body.String(), name, with.header.Get(name))
		}
		withGlobalLock(func() { delete(customHeaders["z.test"], name) })
	}
	withGlobalLock(func() { customHeaders["z.test"]["Vary"] = "Origin" })
	if varied := get("GET", "/a.css", "Accept-Encoding", "br"); !reflect.DeepEqual(varied.header.Values("Vary"), []string{"Origin", "Accept-Encoding"}) {
		t.Errorf("with a Vary of the site: %q; expected the site's and Accept-Encoding", varied.header.Values("Vary"))
	}
	withGlobalLock(func() { customHeaders["z.test"]["Vary"] = "accept-encoding, Origin" })
	if varied := get("GET", "/a.css", "Accept-Encoding", "br"); !reflect.DeepEqual(varied.header.Values("Vary"), []string{"accept-encoding, Origin"}) {
		t.Errorf("with a Vary of the site that already has it: %q", varied.header.Values("Vary"))
	}
	withGlobalLock(func() { delete(customHeaders["z.test"], "Vary") })

	// A script is run, never answered with a file next to it; and a site that runs .br or .gz serves no variant
	withGlobalLock(func() {
		if ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "z.test", ""); !ok {
			t.Fatal(msg)
		}
	})
	if script := get("GET", "/script.cgi", "Accept-Encoding", "br"); strings.Contains(script.body.String(), "BR-OF-THE-SOURCE") || strings.Contains(script.body.String(), "the source of a script") || script.header.Get("Content-Encoding") != "" {
		t.Errorf("a script with a .br next to it: %d %q, Content-Encoding %q; expected the output of its preprocessor", script.code, script.body.String(), script.header.Get("Content-Encoding"))
	}
	withGlobalLock(func() { preprocessors["z.test"]["gz"] = toolPath("cgiecho") })
	check(get("GET", "/a.css", "Accept-Encoding", "br"), expectation{200, "body { margin: 0 }", "", "", "a site that runs .gz with a preprocessor"})
	withGlobalLock(func() { delete(preprocessors["z.test"], "gz") })

	// A variant that leads outside the site isn't opened
	outside := t.TempDir() + "/secret.br"
	os.WriteFile(outside, []byte("OUTSIDE"), 0644)
	if os.Symlink(outside, dir+"z.test/@/plain.txt.br") == nil {
		if linked := get("GET", "/plain.txt", "Accept-Encoding", "br"); linked.body.String() != "plain" {
			t.Errorf("a variant that is a link to a file outside the site: %q", linked.body.String())
		}
	}
}

// R6 O-11: the setting is saved in turbo.config and read from it, stays with a site whose folder goes and comes
// back, is of each subdomain, and the panel gets it and changes it with cfgZ.
func TestR6_O11_TheSettingSavedAndFromThePanel(t *testing.T) {
	dir, get, _ := precompressedSite(t)
	os.MkdirAll(dir+"z.test/sub/@", 0755)
	os.WriteFile(dir+"z.test/sub/@/a.css", []byte("sub"), 0644)
	os.WriteFile(dir+"z.test/sub/@/a.css.br", []byte("BR-OF-SUB"), 0644)
	updateSettings(true)
	base := startServer(t)
	token := login(t, base)
	if code, body, err := post(base, "/admin:inside:cfgZ?a=1&s=z.test&d=", token); err != nil || code != 200 || body != "Precompressed files enabled" {
		t.Fatalf("cfgZ a=1: %d %q %v", code, body, err)
	}
	if code, body, _ := post(base, "/admin:inside:subdomainData?s=z.test&d=", token); code != 200 || !strings.Contains(body, `"Z":"1"`) {
		t.Errorf("the settings of the site for the panel: %d %s; expected Z at 1", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:subdomainData?s=z.test&d=sub", token); code != 200 || !strings.Contains(body, `"Z":"0"`) {
		t.Errorf("the settings of its subdomain: %d %s; expected Z at 0, its own", code, body)
	}
	if on := get("GET", "/a.css", "Accept-Encoding", "br"); on.body.String() != "BR-OF-A" {
		t.Errorf("after cfgZ a=1: %q", on.body.String())
	}

	if !saveDefaultConfig() {
		t.Fatal("saving failed")
	}
	site, _ := savedConfig(t, dir)["z.test"][""].(map[string]interface{})
	if settings, _ := site["!"].(map[string]interface{}); settings["Z"] != "1" {
		t.Errorf("turbo.config saved: the settings of z.test are %v; expected Z at 1", site["!"])
	}
	saved, _ := os.ReadFile(dir + configFileName)
	loadConfig(t, dir, strings.Replace(string(saved), `"Z":"1"`, `"Z":"0"`, 1))
	if off := get("GET", "/a.css", "Accept-Encoding", "br"); off.body.String() != "body { margin: 0 }" {
		t.Errorf("after loading a turbo.config with Z at 0: %q", off.body.String())
	}
	loadConfig(t, dir, string(saved))
	if on := get("GET", "/a.css", "Accept-Encoding", "br"); on.body.String() != "BR-OF-A" {
		t.Errorf("after loading the turbo.config saved, with Z at 1: %q", on.body.String())
	}

	// The folder of the site goes, a save happens meanwhile, and it comes back
	if err := os.Rename(dir+"z.test/@", dir+"z.test/@.away"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	if !saveDefaultConfig() {
		t.Fatal("saving failed")
	}
	site, _ = savedConfig(t, dir)["z.test"][""].(map[string]interface{})
	if settings, _ := site["!"].(map[string]interface{}); settings["Z"] != "1" {
		t.Errorf("turbo.config saved while z.test has no @: its settings are %v; expected Z at 1", site["!"])
	}
	if err := os.Rename(dir+"z.test/@.away", dir+"z.test/@"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	if back := get("GET", "/a.css", "Accept-Encoding", "br"); back.body.String() != "BR-OF-A" {
		t.Errorf("after the folder came back: %q; expected the setting kept", back.body.String())
	}

	// Through the network, as a client that asks for gzip itself gets it: the bytes of the variant, with their length
	request, _ := http.NewRequest("GET", base+"/a.css", nil)
	request.Host = "z.test"
	request.Header.Set("Accept-Encoding", "gzip")
	response, err := (&http.Client{Timeout: clientTimeout(), Transport: &http.Transport{DisableCompression: true}}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if string(body) != "GZ-OF-A" || response.Header.Get("Content-Encoding") != "gzip" || response.ContentLength != 7 || response.Header.Get("Vary") != "Accept-Encoding" {
		t.Errorf("through the network: %q, Content-Encoding %q, length %d, Vary %q", body, response.Header.Get("Content-Encoding"), response.ContentLength, response.Header.Get("Vary"))
	}
	if code, body, err := post(base, "/admin:inside:cfgZ?a=0&s=z.test&d=", token); err != nil || code != 200 || body != "Precompressed files disabled" {
		t.Errorf("cfgZ a=0: %d %q %v", code, body, err)
	}
	if code, body, _ := post(base, "/admin:inside:cfgZ?a=3&s=z.test&d=", token); code != 400 || body != "Invalid value" {
		t.Errorf("cfgZ a=3: %d %q", code, body)
	}
}
