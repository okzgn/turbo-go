package main

// Size limits, rate limiter and denied IPs (#7, #8, #9, #25, #36, #37,
// #42).

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// #25: MUB and MHB changed from the validator must reach the server.
func TestP25_LimitsValueCopy(t *testing.T) {
	initForTest(t)
	for _, setting := range [][2]string{{"MUB", "40"}, {"MHB", "600"}, {"MBB", "10"}} {
		if ok, msg := defaultSettingValidators["."][setting[0]](setting[1], "Admin"); !ok {
			t.Fatalf("%s=%s: %s", setting[0], setting[1], msg)
		}
	}
	if customNetHttp.TurboMaxURILength.Load() != 40 || customNetHttp.TurboMaxHeaderBytes.Load() != 600 || customNetHttp.TurboMaxBodySize.Load() != 10 {
		t.Fatalf("the fork didn't get the limits: MUB=%d MHB=%d MBB=%d", customNetHttp.TurboMaxURILength.Load(), customNetHttp.TurboMaxHeaderBytes.Load(), customNetHttp.TurboMaxBodySize.Load())
	}
	base := startServer(t)
	if code, _, err := get(base, "/"+strings.Repeat("a", 100), nil); code != 414 {
		t.Errorf("101-byte URI with MUB=40: code=%d err=%v; expected 414", code, err)
	}
	if code, _, err := get(base, "/index.html", map[string]string{"X-Test": strings.Repeat("a", 3000)}); code != 431 {
		t.Errorf("3000-byte header with MHB=600: code=%d err=%v; expected 431", code, err)
	}
}

// #9: CIL and CIS in actual milliseconds.
func TestP09_CILUnits(t *testing.T) {
	initForTest(t)
	defaultSettingValidators["."]["CIL"]("1000", "Admin")
	defaultSettingValidators["."]["CIS"]("100", "Admin")
	if d := time.Duration(serverRequestLimits.CIL.Load()); d != time.Second {
		t.Errorf("CIL=1000 -> %v; expected 1s", d)
	}
	if d := time.Duration(serverRequestLimits.CIS.Load()); d != 100*time.Millisecond {
		t.Errorf("CIS=100 -> %v; expected 100ms", d)
	}
}

// #8, #36: with the default values (CII=100), the rejection comes near request
// 100 and is a 429.
func TestP08_RateLimitCount(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	for i := 1; i <= 300; i++ {
		code, _, err := get(base, "/", nil) // /index.html redirects to ./ (#39): it would count two requests
		if err != nil || code == 429 {
			t.Logf("first rejection at request %d (code=%d err=%v)", i, code, err)
			if err != nil || code != 429 {
				t.Fatalf("rejection without 429: code=%d err=%v", code, err)
			}
			if i < 90 || i > 110 {
				t.Fatalf("rejection at request %d; expected near 100", i)
			}
			// Same connection (the transport reuses it): a new one would be closed.
			res, _, err := rawGet(base, "localhost", "/")
			if err != nil || res.StatusCode != 429 || res.Header.Get("Retry-After") == "" {
				t.Fatalf("blocked request: err=%v res=%v; expected 429 with Retry-After", err, res)
			}
			t.Logf("Retry-After: %s", res.Header.Get("Retry-After"))
			return
		}
	}
	t.Fatal("no rejection in 300 requests")
}

// #37: the first denial must be recorded in turbo.denials.
func TestP08b_RateLimitDetail(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.denials", nil, 0644)
	updateSettings(false) // The periodic reload opens the log
	base := startServer(t)
	fails := 0
	for i := 1; i <= 200; i++ {
		code, _, err := get(base, "/", nil)
		if err != nil || code != 200 {
			t.Logf("request %d: code=%d err=%v", i, code, err)
			fails++
			if fails > 6 {
				break
			}
		}
	}
	if fails == 0 {
		t.Fatal("the limiter rejected no request")
	}
	serverSetLogState(denialsLogName, nil) // Flushes and closes the log
	b, _ := os.ReadFile(dir + "turbo.denials")
	t.Logf("denials:\n%s", b)
	if !strings.Contains(string(b), "127.0.0.1") {
		t.Fatal("turbo.denials doesn't hold the denial")
	}
}

// #42: an IP denied by hand is blocked from the first call and unblocked when
// it is deleted.
func TestW_ManualDeniedIP(t *testing.T) {
	initForTest(t)
	ip := "203.0.113.7"
	globalMutex.Lock()
	ok, msg := adminAddHandlers["@"](ip, "9999999999")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("add: %q", msg)
	}
	if !perIPNotAvailable(ip, true) {
		t.Fatal("the denied IP isn't blocked on the first call")
	}
	globalMutex.Lock()
	ok, msg = adminDeleteHandlers["@"](ip)
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("delete: %q", msg)
	}
	if perIPNotAvailable(ip, true) {
		t.Fatal("the IP is still blocked after deleting it")
	}
}

// #7: ipReferences must not grow without limit: the periodic cleanup forgets
// the IPs idle for longer than CIL.
func TestP07_IPRefMemory(t *testing.T) {
	initForTest(t)
	if ok, msg := defaultSettingValidators["."]["CIL"]("1000", "Admin"); !ok {
		t.Fatal(msg)
	}
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	n := 1_000_000
	for i := 0; i < n; i++ {
		perIPNotAvailable(fmt.Sprintf("2001:db8::%x:%x", i>>16, i&0xffff), true)
	}
	time.Sleep(1100 * time.Millisecond)
	cleanIPReferences()
	runtime.GC()
	runtime.ReadMemStats(&m1)
	count := 0
	ipReferences.Range(func(_, _ any) bool { count++; return true })
	t.Logf("%d distinct IPs -> %d entries kept after the cleanup, %+.1f MiB of heap after GC", n, count, (float64(m1.HeapAlloc)-float64(m0.HeapAlloc))/(1<<20))
	if count > n/100 {
		t.Fatalf("%d entries kept; expected near zero", count)
	}
}

// #42, §5.2: the "@" entries of an earlier turbo.config are loaded as manual
// denials (the expired ones are discarded), and saving writes only those, not
// the temporary marks of the global limiter.
func TestC_DeniedIPsFromConfig(t *testing.T) {
	dir := initForTest(t)
	cfg := `{"localhost":{"":{}},"@":{"203.0.113.8":"9999999999","203.0.113.9":"1000"}}`
	os.WriteFile(dir+"turbo.config", []byte(cfg), 0600)
	configFileStamp = configStamp{}
	updateSettings(false)
	if !perIPNotAvailable("203.0.113.8", true) {
		t.Error("the active IP of turbo.config isn't blocked")
	}
	if perIPNotAvailable("203.0.113.9", true) {
		t.Error("the expired IP of turbo.config is blocked")
	}
	if !saveDefaultConfig() {
		t.Fatal("couldn't save")
	}
	b, _ := os.ReadFile(dir + "turbo.config")
	s := string(b)
	if !strings.Contains(s, "203.0.113.8") || strings.Contains(s, "203.0.113.9") {
		t.Errorf("saved \"@\": %s", s)
	}
}

// An IP of fewer than 3 characters ("::" is a valid IPv6) must not panic when
// it is added, neither from the panel nor when loading turbo.config (there it
// would bring down the startup).
func TestW_DeniedIPShortAddress(t *testing.T) {
	dir := initForTest(t)
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic when denying \"::\": %v", r)
			}
		}()
		globalMutex.Lock()
		defer globalMutex.Unlock()
		if ok, msg := adminAddHandlers["@"]("::", "9999999999"); ok {
			t.Errorf("\"::\" accepted: %q", msg)
		}
		if ok, msg := adminAddHandlers["@"]("::1", "9999999999"); ok {
			t.Errorf("\"::1\" (localhost) accepted: %q", msg)
		}
	}()
	os.WriteFile(dir+"turbo.config", []byte(`{"localhost":{"":{}},"@":{"::":"9999999999"}}`), 0600)
	configFileStamp = configStamp{}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic when loading turbo.config with \"::\" in \"@\": %v", r)
		}
	}()
	updateSettings(false)
}
