package main

// T23 (N20, N31): no site uses a folder reserved by Turbo, two sites don't
// share a key (the site "c.a.b" and the subdomain "c" of "a.b"), and an
// alias doesn't hide the host of a site.

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestN31_ReservedSiteNames(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, name := range []string{"turbo.dev", "turbo.panel", "turbo.certificates", "turbo.config"} {
		if code, body, _ := post(base, "/admin:inside:addSite?"+url.Values{"s": {name}}.Encode(), tok); code != 400 || !strings.Contains(body, "reserved") {
			t.Errorf("addSite %s: %d %q; expected 400", name, code, body)
		}
	}
	logs := captureLog(t)
	os.MkdirAll(dir+"turbo.dev/@", 0755)
	os.MkdirAll(dir+"turbo.dev/admin/@", 0755)
	updateSettings(true)
	first := strings.Count(logs.String(), "not activated")
	updateSettings(true)
	globalMutex.RLock()
	_, active := sitesMap["turbo.dev"]
	globalMutex.RUnlock()
	if active {
		t.Error("the turbo.dev folder (or its admin subdomain) was activated as a site")
	}
	if again := strings.Count(logs.String(), "not activated"); first != 2 || again != first {
		t.Errorf("warnings about the reserved folders: %d and, after another reload, %d; expected 2 (turbo.dev and its admin) and no more:\n%s", first, again, logs.String())
	}
	loadConfig(t, dir, `{"^":{"v":"2"},"turbo.dev":{"":{"-":{"index.html":"1"}}}}`)
	globalMutex.RLock()
	_, active = sitesMap["turbo.dev"]
	globalMutex.RUnlock()
	if active {
		t.Error("turbo.dev of turbo.config was activated as a site")
	}
}

// N20: the site "c.a.b" and the subdomain "c" of "a.b" would have the same
// key: the first one in order is activated, with a warning, and cfgC doesn't
// panic.
func TestN20_SiteKeyConflict(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"a.b/@", 0755)
	os.MkdirAll(dir+"a.b/c/@", 0755)
	os.MkdirAll(dir+"c.a.b/@", 0755)
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"a.b":{"":{},"c":{".":{"X-Sub":"1"}}},"c.a.b":{"":{".":{"X-Root":"1"}}}}`)
	globalMutex.RLock()
	_, root := sitesMap["c.a.b"]
	_, sub := sitesMap["a.b"]["c"]
	header := customHeaders["c.a.b"]["X-Sub"]
	globalMutex.RUnlock()
	if root || !sub || header != "1" {
		t.Errorf("key conflict: site c.a.b=%v, subdomain c of a.b=%v, header of the subdomain=%q", root, sub, header)
	}
	if !strings.Contains(logs.String(), "c.a.b") {
		t.Errorf("no warning about the conflict:\n%s", logs.String())
	}
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:addSite?s=c.a.b", tok); code != 400 {
		t.Errorf("addSite c.a.b with the subdomain c of a.b: %d %q", code, body)
	}
	if code, _, err := post(base, "/admin:inside:cfgC?s=c.a.b&d=&a=1&z=a%40b.test", tok); err != nil || code == 500 {
		t.Errorf("cfgC of the site in conflict: %d %v", code, err)
	}
}

// An alias can't be the host of a site; when loading, the site wins.
func TestN31_AliasOfSiteHost(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"a.test/@", 0755)
	os.MkdirAll(dir+"b.test/@", 0755)
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"a.test":{"":{"&":{"b.test":true,"other.test":true}}},"b.test":{"":{}}}`)
	globalMutex.RLock()
	_, shadowed := domainAliases["b.test"]
	other := domainAliases["other.test"]
	globalMutex.RUnlock()
	if shadowed || other != "a.test" {
		t.Errorf("alias b.test=%v (expected discarded), other.test=%q", shadowed, other)
	}
	if !strings.Contains(logs.String(), "b.test") {
		t.Error("no warning about the discarded alias")
	}
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:addAlias?s=a.test&d=&a=b.test", tok); code != 400 {
		t.Errorf("addAlias with the host of a site: %d %q", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:addSite?s=other.test", tok); code != 400 {
		t.Errorf("addSite with the name of an alias: %d %q", code, body)
	}
}
