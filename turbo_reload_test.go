package main

// T13 (N11, N43; D19 (a)): the turbo.config reload replaces what came from the
// file (what is no longer there stops applying) in a single section under the
// lock, and in a fixed order: the result doesn't depend on the order of the
// maps.

import (
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// N11: removing a header, an alias, a preprocessor, a denied IP or a
// replacement from the file makes them stop applying; the fixed ones stay.
func TestN11_ReloadRemovesWhatTheFileDropped(t *testing.T) {
	dir := initForTest(t)
	until := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},".":{"X-A":"yes"},"?":{"cgi":"`+toolPath("cgiecho")+`"},"&":{"alias.test":true}}},"@":{"203.0.113.5":"`+until+`"},"_":{"!":"zz"},"#":{"404":"Not here"}}`)
	globalMutex.RLock()
	before := customHeaders["localhost"]["X-A"] == "yes" && domainAliases["alias.test"] == "localhost" && preprocessors["localhost"]["cgi"] != "" && charReplacements["!"] == "zz"
	globalMutex.RUnlock()
	if !before {
		t.Fatal("the starting configuration wasn't fully loaded")
	}
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"}}}}`)
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	if _, kept := customHeaders["localhost"]["X-A"]; kept {
		t.Error("the header removed from the file is still there")
	}
	if _, kept := domainAliases["alias.test"]; kept {
		t.Error("the alias removed from the file is still there")
	}
	if _, kept := preprocessors["localhost"]["cgi"]; kept {
		t.Error("the preprocessor removed from the file is still there")
	}
	if _, kept := deniedIPList()["203.0.113.5"]; kept {
		t.Error("the denied IP removed from the file is still there")
	}
	if _, kept := charReplacements["!"]; kept {
		t.Error("the replacement removed from the file is still there")
	}
	if _, kept := (*httpResponses.Load())[404]; kept {
		t.Error("the response removed from the file is still there")
	}
	if charReplacements[";"] != "-.-" || (*httpResponses.Load())[0] == "" {
		t.Error("the fixed replacements or responses were removed")
	}
}

// N11: changing an alias's target or the order of the indexes applies.
func TestN11_ReloadAppliesChanges(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"a.test/@", 0755)
	os.MkdirAll(dir+"b.test/@", 0755)
	loadConfig(t, dir, `{"^":{"v":"2"},"a.test":{"":{"&":{"alias.test":true}}},"localhost":{"":{"-":{"index.html":"1","index.php":"2"}}}}`)
	loadConfig(t, dir, `{"^":{"v":"2"},"b.test":{"":{"&":{"alias.test":true}}},"localhost":{"":{"-":{"index.php":"1","index.html":"2"}}}}`)
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	if got := domainAliases["alias.test"]; got != "b.test" {
		t.Errorf("alias.test points to %q; expected b.test", got)
	}
	if indexFiles["localhost"]["index.php"] >= indexFiles["localhost"]["index.html"] {
		t.Errorf("index order %v; expected index.php first", indexFiles["localhost"])
	}
}

// N11, N43: the result doesn't depend on the order of the maps: R and W at
// 1 → R; "PHP" and "php" → the first in order; two indexes with the same
// position → by name; an alias in two sites → the first.
func TestN11_DeterministicOrder(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"a.test/@", 0755)
	os.MkdirAll(dir+"b.test/@", 0755)
	logs := captureLog(t)
	cfg := `{"^":{"v":"2"},"localhost":{"":{"!":{"R":"1","W":"1"},"?":{"PHP":"/usr/bin/first","php":"/usr/bin/second"},"-":{"b.html":"1","a.html":"1"}}},` +
		`"a.test":{"":{"&":{"common.test":true}}},"b.test":{"":{"&":{"common.test":true}}}}`
	for i := 0; i < 50; i++ {
		loadConfig(t, dir, cfg)
		globalMutex.RLock()
		r, w := siteSSLConfig["localhost"]["R"], siteSSLConfig["localhost"]["W"]
		php := preprocessors["localhost"]["php"]
		order := indexFiles["localhost"]["a.html"] < indexFiles["localhost"]["b.html"]
		alias := domainAliases["common.test"]
		globalMutex.RUnlock()
		if r != true || w == true {
			t.Fatalf("load %d: R=%v W=%v; expected R", i, r, w)
		}
		if php != "/usr/bin/first" {
			t.Fatalf("load %d: php = %q; expected the one of \"PHP\", first in order", i, php)
		}
		if !order {
			t.Fatalf("load %d: indexes with the same position %v; expected by name", i, indexFiles["localhost"])
		}
		if alias != "a.test" {
			t.Fatalf("load %d: common.test → %q; expected a.test, the first", i, alias)
		}
	}
	for _, want := range []string{"php", "common.test"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("no warning for the repeated entry %s", want)
		}
	}
}

// During reloads, requests never see the site half loaded. (With the reload
// that only added, the site couldn't disappear: this test protects the reload
// that replaces.)
func TestN11_ReloadIsAtomicForRequests(t *testing.T) {
	dir := initForTest(t)
	// All the requests come from 127.0.0.1: without raising the per-IP limit,
	// the bursts after each reload get 429.
	cfg := `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},".":{"X-A":"yes"}}},".":{"CIS":"50000","CII":"50000"}}`
	loadConfig(t, dir, cfg)
	base := startServer(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var requests, wrong atomic.Int64
	client := &http.Client{Timeout: clientTimeout()}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, _ := http.NewRequest("GET", base+"/", nil)
				req.Host = "localhost"
				res, err := client.Do(req)
				if err != nil {
					continue
				}
				res.Body.Close()
				if requests.Add(1); res.StatusCode != 200 || res.Header.Get("X-A") != "yes" {
					if wrong.Add(1) == 1 {
						t.Logf("first wrong response: %d %v", res.StatusCode, res.Header)
					}
				}
			}
		}()
	}
	for requests.Load() < 1000 {
		configFileModTime = 0
		updateSettings(false)
	}
	close(stop)
	wg.Wait()
	if wrong.Load() != 0 {
		t.Errorf("%d of %d requests saw the site half loaded", wrong.Load(), requests.Load())
	}
}

// BenchmarkReload measures a reload of turbo.config with 500 sites.
func BenchmarkReload(b *testing.B) {
	dir := initForTest(b)
	var config strings.Builder
	config.WriteString(`{"^":{"v":"2"}`)
	for i := 0; i < 500; i++ {
		site := "site-" + strconv.Itoa(i) + ".test"
		os.MkdirAll(dir+site+"/@", 0755)
		config.WriteString(`,"` + site + `":{"":{"=":{"/old/":"/new/"},".":{"X-Site":"` + site + `"},"-":{"index.html":"1"},"!":{"S":"0"}}}`)
	}
	config.WriteString(`,".":{"CIS":"1000","CII":"100"}}`)
	if err := os.WriteFile(dir+"turbo.config", []byte(config.String()), 0600); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		configFileModTime = 0
		if err := updateSettings(true); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzConfigReload: whatever turbo.config becomes while Turbo runs, the reload never panics; a file that
// parseSiteConfig refuses keeps the configuration in use (credentials, PA and sites) and one it accepts is
// applied; the credentials change only to what the file says; and the same file read twice gives the same
// configuration. A file with "M" is left out: it moves the sites directory, which is setM's business.
func FuzzConfigReload(f *testing.F) {
	example, err := os.ReadFile("testdata/config/v2-example.json")
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		strings.Replace(string(example), `"M":"{TURBO_CURRENT_DIR}",`, "", 1),
		`{"^":{"v":"2"},".":{"U":"other","PA":"panel.test"}}`,
		`{"^":{"v":"2"},".":{"PA":"*;x"}}`,
		`{".":{"P":"password","CIL":"100"},"localhost":{"":{"?":{"php":"/does/not/exist"}}}}`,
		`{"^":{"v":"x"}}`,
		`null`,
		`{"a.test":{"":{"&":{"localhost":true}}},"localhost":{"":{"=":{"/a":"/b"},".":{"X-A":"1"}}},"_":{"!":"zz"}}`,
		`{"^":{"v":2},"localhost":{"":{"!":{"S":1,"R":"1","W":"1"},"-":{"a.html":"2","b.html":"2"}}},"@":{"203.0.113.9":"4102444800"}}`,
	} {
		f.Add([]byte(seed))
	}
	dir := initForTest(f)
	hash, err := hashPassword("fuzz-password")
	if err != nil {
		f.Fatal(err)
	}
	reload := func(t testing.TB, content []byte) error {
		if err := os.WriteFile(dir+"turbo.config", content, 0600); err != nil {
			t.Fatal(err)
		}
		withGlobalLock(func() { configFileModTime = 0 })
		return updateSettings(false)
	}
	state := func() (user, hash, access, sites string) {
		withReadLock(func() {
			var names []string
			for name := range sitesMap {
				names = append(names, name)
			}
			sort.Strings(names)
			user, hash, access, sites = panelUser.Get(), panelPasswordHash.Get(), panelAccess.Load().setting, strings.Join(names, ",")
		})
		return
	}
	saved := func(t *testing.T) map[string]map[string]interface{} {
		var config string
		withReadLock(func() { config = createDefaultConfig(false, false, true) })
		var parsed map[string]map[string]interface{}
		if err := json.Unmarshal([]byte(config), &parsed); err != nil {
			t.Fatalf("the configuration in use wouldn't be saved as valid JSON: %v\n%s", err, config)
		}
		return parsed
	}
	start := `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"}}},".":{"U":"fz","PH":"` + hash + `","PA":"panel.test"}}`
	if err := reload(f, []byte(start)); err != nil {
		f.Fatal(err)
	}
	if user, _, access, _ := state(); user != "fz" || access != "panel.test" {
		f.Fatalf("starting configuration: user %q, PA %q", user, access)
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 64<<10 {
			return
		}
		var raw map[string]map[string]interface{}
		if parseConfig(content, &raw) == nil {
			if _, moves := raw["."]["M"]; moves {
				return
			}
		}
		userBefore, hashBefore, accessBefore, sitesBefore := state()
		err := reload(t, content)
		_, parseErr := parseSiteConfig(dir + "turbo.config")
		if (err == nil) != (parseErr == nil) {
			t.Fatalf("turbo.config %q: the reload gives %v and parseSiteConfig %v", content, err, parseErr)
		}
		user, hash, access, sites := state()
		if err != nil {
			if user != userBefore || hash != hashBefore || access != accessBefore || sites != sitesBefore {
				t.Errorf("invalid turbo.config %q (%v) changed the configuration in use: user %q -> %q, PA %q -> %q, sites %q -> %q, hash changed %v",
					content, err, userBefore, user, accessBefore, access, sitesBefore, sites, hash != hashBefore)
			}
			return
		}
		if u, ok := raw["."]["U"].(string); ok && user != u {
			t.Errorf("turbo.config %q: user %q; the file says %q", content, user, u)
		} else if !ok && user != userBefore {
			t.Errorf("turbo.config %q without U: the user went from %q to %q", content, userBefore, user)
		}
		if h, ok := raw["."]["PH"].(string); ok && hash != h {
			t.Errorf("turbo.config %q: the hash is not the one of PH", content)
		} else if _, plain := raw["."]["P"].(string); !ok && !plain && hash != hashBefore {
			t.Errorf("turbo.config %q without PH or P: the password changed", content)
		}
		first := saved(t)
		if err := reload(t, content); err != nil {
			t.Fatalf("turbo.config %q: accepted once and rejected the second time: %v", content, err)
		}
		second := saved(t)
		if _, plain := raw["."]["P"].(string); plain { // A plain password is hashed with a new salt each time
			delete(first["."], "PH")
			delete(second["."], "PH")
		}
		if !reflect.DeepEqual(first, second) {
			t.Errorf("turbo.config %q applied twice gives different configurations:\n%v\n%v", content, first, second)
		}
	})
}
