package server

// The tests of the findings about reading turbo.config of the review of v2.5 (_revision/INFORME_REVISION_4cb626c.md,
// block 2): each failed before its fix.

import (
	"os"
	"strings"
	"testing"
)

// v25ReviewCGI makes localhost/@/x.cgi, whose text is a script's source, and returns the folder of the sites.
func v25ReviewCGI(t *testing.T) string {
	t.Helper()
	dir := initForTest(t)
	if err := os.WriteFile(dir+"localhost/@/x.cgi", []byte("<?php secret(); ?>"), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// V2.5 review E-1 (decision D2): a key of turbo.config that isn't the name of a site or of a subdomain makes the file
// invalid, as a site that isn't a JSON object: skipped, the folder of the site came from the disk with the defaults,
// its scripts served as text. A reload keeps the configuration in use.
func TestV25R_E1_AKeyThatIsNoSiteNameMakesTheFileInvalid(t *testing.T) {
	dir := v25ReviewCGI(t)
	base := startServer(t)
	echo := toolPath("cgiecho")
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"?":{"cgi":"`+echo+`"}}}}`)
	if code, body, _ := get(base, "/x.cgi", nil); code != 200 || strings.Contains(body, "<?php") {
		t.Fatalf("with a valid turbo.config: %d, source served %v", code, strings.Contains(body, "<?php"))
	}
	for _, config := range []string{
		`{"^":{"v":"2"},"Localhost":{"":{"?":{"cgi":"` + echo + `"}}}}`,
		`{"^":{"v":"2"},"localhost.":{"":{"?":{"cgi":"` + echo + `"}}}}`,
		`{"^":{"v":"2"},"localhost ":{"":{"?":{"cgi":"` + echo + `"}}}}`,
		`{"^":{"v":"2"},"localhost":{"":{"?":{"cgi":"` + echo + `"}},"Www":{}}}`,
		`{"^":{"v":"2"},"localhost":{"":{"?":{"cgi":"` + echo + `"}},"www.":{}}}`,
	} {
		if err := os.WriteFile(dir+"turbo.config", []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := parseSiteConfig(dir + "turbo.config")
		if siteErr := (configSiteError{}); err == nil || !asConfigSiteError(err, &siteErr) || siteErr.name == "" {
			t.Errorf("%s: %v; expected a site that isn't a name", config, err)
			continue
		}
		if message := configErrorMessage(err, true); !strings.Contains(message, "isn't the name of a site") {
			t.Errorf("%s: the message %q", config, message)
		}
		loadConfig(t, dir, config)
		if code, body, _ := get(base, "/x.cgi", nil); code != 200 || strings.Contains(body, "<?php") {
			t.Errorf("after reading %s: %d, source served %v; expected the configuration in use kept", config, code, strings.Contains(body, "<?php"))
		}
	}
	// Names of sites as Turbo writes them are still valid: wildcards, a subdomain *, an IP address
	for _, config := range []string{
		`{"^":{"v":"2"},"*.example.test":{"":{},"*":{},"a.b":{}}}`,
		`{"^":{"v":"2"},"*":{"":{}},"192.0.2.10":{"":{}},"xn--bcher-kva.example":{"":{}}}`,
	} {
		os.WriteFile(dir+"turbo.config", []byte(config), 0600)
		if _, err := parseSiteConfig(dir + "turbo.config"); err != nil {
			t.Errorf("%s: %v", config, err)
		}
	}
}

// asConfigSiteError is errors.As for a configSiteError.
func asConfigSiteError(err error, target *configSiteError) bool {
	for err != nil {
		if siteErr, is := err.(configSiteError); is {
			*target = siteErr
			return true
		}
		unwrapper, can := err.(interface{ Unwrap() error })
		if !can {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

// V2.5 review E-2 (decision D3): a preprocessor of turbo.config whose key can't be used ("cgi ", "*.cgi", "a.cgi")
// makes the extension it was meant for answer 500, unless an entry of that extension can be used: kept under its own
// key, it matched no file, and the files of that extension were served as text. The extension closed isn't written
// when the configuration is saved.
func TestV25R_E2_AnEntryThatCantBeUsedClosesItsExtension(t *testing.T) {
	dir := v25ReviewCGI(t)
	base := startServer(t)
	echo := toolPath("cgiecho")
	for _, c := range []struct {
		entries string
		code    int
	}{
		{`"cgi ":"` + echo + `"`, 500},
		{`" CGI":"` + echo + `"`, 500},
		{`"*.cgi":"` + echo + `"`, 500},
		{`"a.cgi":"` + echo + `"`, 500},
		{`"cgi":42`, 500},
		// Second pass, M-3: what isn't a letter or a digit at the ends of the key, a control character among it
		{`"cgi.":"` + echo + `"`, 500},
		{`"cgi,":"` + echo + `"`, 500},
		{`".cgi;":"` + echo + `"`, 500},
		{`"cgi\u200b":"` + echo + `"`, 500},
		{`"cgi\t":"` + echo + `"`, 500},
		{`"cgi ":"` + echo + `","cgi":"` + echo + `"`, 200}, // One that can be used wins
		{`"a.cgi":"` + echo + `","CGI":"` + echo + `"`, 200},
	} {
		loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"?":{`+c.entries+`}}}}`)
		code, body, _ := get(base, "/x.cgi", nil)
		if code != c.code || strings.Contains(body, "<?php") {
			t.Errorf("preprocessors {%s}: %d, source served %v; expected %d", c.entries, code, strings.Contains(body, "<?php"), c.code)
		}
	}
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"?":{"cgi ":"`+echo+`"}}}}`)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:setC?a=&b=Admin", tok); code != 200 {
		t.Fatalf("setC: %d %q", code, body)
	}
	saved := savedConfig(t, dir)["localhost"][""].(map[string]interface{})["?"].(map[string]interface{})
	if _, written := saved["cgi"]; written || saved["cgi "] != echo {
		t.Errorf("the preprocessors saved: %v; expected the entry as written, and nothing more", saved)
	}
}

// V2.5 review, second pass, M-2: the extension that an entry of turbo.config that can't be used closed opens again
// once that entry is deleted from the panel: its mark stayed, and the files answered 500 for an entry that was neither
// in the panel nor in the file, until Turbo started again. The extension closed is no entry to delete by itself.
func TestV25R_M2_AnExtensionClosedOpensWhenItsEntryIsDeleted(t *testing.T) {
	dir := v25ReviewCGI(t)
	base := startServer(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"?":{"cgi ":"`+toolPath("cgiecho")+`"}}}}`)
	if code, _, _ := get(base, "/x.cgi", nil); code != 500 {
		t.Fatalf("with the entry that can't be used: %d; expected 500", code)
	}
	remove := func(key string) (bool, string) {
		return lockedCheck(func() (bool, string) {
			return subdomainContentDeleters["?"](true, map[string]interface{}{key: false}, "localhost", "")
		})
	}
	if ok, message := remove("cgi"); ok || message != "Preprocessor not found" {
		t.Errorf("deleting the extension that the entry closes: %v %q; expected it not found", ok, message)
	}
	if code, _, _ := get(base, "/x.cgi", nil); code != 500 {
		t.Errorf("after that: %d; expected 500 still", code)
	}
	if ok, message := remove("cgi "); !ok {
		t.Fatalf("deleting the entry: %q", message)
	}
	globalMutex.RLock()
	left := len(preprocessors["localhost"])
	globalMutex.RUnlock()
	if code, _, _ := get(base, "/x.cgi", nil); code != 200 || left != 0 {
		t.Errorf("with the entry deleted: %d, and %d preprocessors left; expected the file as any other, and none", code, left)
	}
}

// V2.5 review, second pass, M-4: the log says what an entry that can't be used does when its key is the empty
// extension (the files without an extension answer 500: it said that it matched no file); and "." alone, which isn't
// that extension, is kept as written: kept as "", it closed those files, and was saved as a preprocessor of all of them.
func TestV25R_M4_TheEmptyExtensionAndADotAlone(t *testing.T) {
	dir := v25ReviewCGI(t)
	os.WriteFile(dir+"localhost/@/noext", []byte("<?php source"), 0644)
	base := startServer(t)
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"?":{"":"/no/such/program"}}}}`)
	if code, _, _ := get(base, "/noext", nil); code != 500 || !strings.Contains(logs.String(), "the files of its extension answer 500") || strings.Contains(logs.String(), "it matches no file") {
		t.Errorf("the empty extension with a program that isn't there: %d; expected 500, and the log to say so:\n%s", code, logs.String())
	}
	logs.Reset()
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"?":{".":"`+toolPath("cgiecho")+`"}}}}`)
	if code, body, _ := get(base, "/noext", nil); code != 200 || !strings.Contains(body, "<?php source") || !strings.Contains(logs.String(), "it matches no file") {
		t.Errorf("a dot alone as a key: %d %.40q; expected the file as any other, and a warning:\n%s", code, body, logs.String())
	}
	saved := createSubdomainData("localhost", "")
	if !strings.Contains(saved, `"?":{".":`) {
		t.Errorf("saved: %s; expected the key as written", saved)
	}
}

// V2.5 review, second pass, M-10: the message of a key that isn't a site's name says that a wildcard is written "*",
// where its folder has "#": it said only "named as its folder".
func TestV25R_M10_TheMessageOfAKeyNamesTheWildcard(t *testing.T) {
	dir := initForTest(t)
	if err := os.WriteFile(dir+"turbo.config", []byte(`{"^":{"v":"2"},"#.example.com":{"":{}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := parseSiteConfig(dir + "turbo.config")
	if err == nil || !strings.Contains(configErrorMessage(err, true), `with "*" where the folder has "#"`) {
		t.Errorf("a key written as the folder of a wildcard: %v", err)
	}
}

// V2.5 review E-3 (decision D4): every entry of turbo.config that is dropped because it can't be used says so in the
// log: a rewrite that kept a folder private, or a header that kept the pages safe, went without a word.
func TestV25R_E3_EveryEntryDroppedIsLogged(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{`+
		`"=":{"private/":"/403.html","/a/":"/x//y","/b/":"/x/../y","/c/":7},`+
		`".":{"X-Long":"`+strings.Repeat("a", 600)+`","Bad Name":"1","X-Number":1},`+
		`"$":{"bad ext":"text/html","css":"x"},`+
		`"-":{"`+strings.Repeat("i", 60)+`":"1"},`+
		`"&":{"bad_alias":false,"*.wild.test":false}}}}`)
	for _, entry := range []string{"private/", "/a/", "/b/", "/c/", "X-Long", "Bad Name", "X-Number", "bad ext", "css", strings.Repeat("i", 60), "bad_alias", "*.wild.test"} {
		if !strings.Contains(logs.String(), "turbo.config entry discarded") || !strings.Contains(logs.String(), "entry="+logQuoted(entry)) {
			t.Errorf("the entry %q was dropped without a line in the log", entry)
		}
	}
}

// logQuoted is how the text handler of slog writes a value: quoted when it needs it.
func logQuoted(value string) string {
	if strings.ContainsAny(value, " =\"") {
		return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	}
	return value
}

// V2.5 review E-8: an alias that is an IP address is refused: only the site * serves an IP address, and with it the
// alias is a site's host. It was assigned without the site *, and never reached.
func TestV25R_E8_NoIPAlias(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:addAlias?s=localhost&d=&a=192.0.2.10", tok); code != 400 || !strings.Contains(body, "site *") {
		t.Errorf("an IP alias: %d %q; expected 400", code, body)
	}
	globalMutex.RLock()
	_, assigned := domainAliases["192.0.2.10"]
	globalMutex.RUnlock()
	if assigned {
		t.Error("the IP alias was assigned")
	}
}

// V2.5 review E-12: a preprocessor of the files without extension doesn't run the file of an ACME challenge, which is
// given as it is: Certbot couldn't validate the site.
func TestV25R_E12_AnACMEChallengeIsNeverRun(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/@/.well-known/acme-challenge", 0755)
	os.WriteFile(dir+"localhost/@/.well-known/acme-challenge/token-123", []byte("the-token-content"), 0644)
	os.WriteFile(dir+"localhost/@/noext", []byte("x"), 0644)
	globalMutex.Lock()
	ok, message := subdomainContentCheckers["?"](true, map[string]interface{}{"": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("a preprocessor of the files without extension: %q", message)
	}
	base := startServer(t)
	if code, body, _ := get(base, "/.well-known/acme-challenge/token-123", nil); code != 200 || body != "the-token-content" {
		t.Errorf("the ACME challenge: %d %.80q; expected its file as it is", code, body)
	}
	if code, body, _ := get(base, "/noext", nil); code != 200 || !strings.Contains(body, "SCRIPT_FILENAME") {
		t.Errorf("a file without extension: %d %.80q; expected it run", code, body)
	}
}
