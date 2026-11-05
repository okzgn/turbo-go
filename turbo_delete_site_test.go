package main

// T26 (N23): deleting a root domain also removes the state of its
// subdomains and the aliases that point to them.

import (
	"testing"
)

func TestN23_DeleteRootRemovesSubdomains(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, step := range []string{
		"/admin:inside:addSite?s=root.test",
		"/admin:inside:addSubdomain?s=root.test&d=sub",
		"/admin:inside:addAlias?s=root.test&d=sub&a=alias-sub.test",
		"/admin:inside:addAlias?s=root.test&d=&a=alias-root.test",
		"/admin:inside:addPreprocessor?s=root.test&d=sub&a=php&c=Admin&b=" + toolPath("cgiecho"),
		"/admin:inside:addHeader?s=root.test&d=sub&a=X-Sub&b=1&c=Admin",
	} {
		if code, body, err := post(base, step, tok); err != nil || code != 200 {
			t.Fatalf("%s: %d %q %v", step, code, body, err)
		}
	}
	if code, body, err := post(base, "/admin:inside:delSite?s=root.test&d=&b=Admin", tok); err != nil || code != 200 {
		t.Fatalf("delSite: %d %q %v", code, body, err)
	}
	globalMutex.RLock()
	for name, present := range map[string]bool{
		"preprocessors": preprocessors["sub.root.test"] != nil,
		"headers":       customHeaders["sub.root.test"] != nil,
		"indexes":       indexFiles["sub.root.test"] != nil,
		"MIME":          mimeTypes["sub.root.test"] != nil,
		"SSL":           siteSSLConfig["sub.root.test"] != nil,
		"sub alias":     domainAliases["alias-sub.test"] != "",
		"root alias":    domainAliases["alias-root.test"] != "",
	} {
		if present {
			t.Errorf("left after deleting the root: %s", name)
		}
	}
	globalMutex.RUnlock()

	// Created again, the subdomain doesn't get back the old alias.
	for _, step := range []string{"/admin:inside:addSite?s=root.test", "/admin:inside:addSubdomain?s=root.test&d=sub"} {
		if code, body, err := post(base, step, tok); err != nil || code != 200 {
			t.Fatalf("%s: %d %q %v", step, code, body, err)
		}
	}
	if res, _, err := rawGet(base, "alias-sub.test", "/"); err == nil && res.StatusCode != 404 {
		t.Errorf("the old alias serves the subdomain again: %d", res.StatusCode)
	}
	if code, body, _ := post(base, "/admin:inside:addAlias?s=root.test&d=sub&a=alias-sub.test", tok); code != 200 {
		t.Errorf("addAlias of the old alias: %d %q", code, body)
	}
}
