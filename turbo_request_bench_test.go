package main

// Review of 6046dbe (R6), block 6: what a request costs before it reaches the disk, each part measured on its own.
// BenchmarkServeStatic goes through the network and a site without settings: it can't tell these apart.

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// benchSites leaves localhost and three more sites, with their files: bench.test, with what a site in production has
// (12 MIME types, 4 headers, a preprocessor, 3 indexes and 50 rewrites that the requests measured don't match), an
// alias of it, and wild.bench with a wildcard subdomain. It returns the sites directory.
func benchSites(b *testing.B) string {
	b.Helper()
	dir := initForTest(b)
	serverRequestLimits.CII.Store(1 << 40) // Not the limiter of requests per client
	for _, file := range []string{"bench.test/@/index.html", "bench.test/@/css/site.css", "wild.bench/#/@/index.html"} {
		if err := os.MkdirAll(dir+file[:len(file)-len(lastPathSegment(file))], 0755); err != nil {
			b.Fatal(err)
		}
		os.WriteFile(dir+file, []byte("body { margin: 0 }"), 0644)
	}
	globalMutex.Lock()
	defer globalMutex.Unlock()
	constructSiteWithoutIndex("bench.test", "")
	constructSiteWithoutIndex("wild.bench", "")
	constructSiteWithoutIndex("wild.bench", "*")
	set := func(kind string, entries map[string]interface{}, domain, subdomain string) {
		for key, value := range entries {
			if ok, msg := subdomainContentCheckers[kind](true, map[string]interface{}{key: value}, true, domain, subdomain); !ok {
				b.Fatalf("%s %q: %s", kind, key, msg)
			}
		}
	}
	mimes, rewrites := map[string]interface{}{}, map[string]interface{}{}
	for i, extension := range []string{"css", "js", "mjs", "json", "svg", "png", "jpg", "webp", "woff2", "txt", "xml", "map"} {
		mimes[extension] = "application/x-bench-" + strconv.Itoa(i)
	}
	for i := 0; i < 50; i++ {
		rewrites["/section"+strconv.Itoa(i)+"/"] = "/pages/" + strconv.Itoa(i) + "/{REWRITE_COMPLEMENT}"
	}
	set("$", mimes, "bench.test", "")
	set("=", rewrites, "bench.test", "")
	set(".", map[string]interface{}{"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "max-age=600"}, "bench.test", "")
	set("?", map[string]interface{}{"cgi": toolPath("cgiecho")}, "bench.test", "")
	set("-", map[string]interface{}{"index.html": "1", "index.htm": "2", "default.html": "3"}, "bench.test", "")
	set("-", map[string]interface{}{"index.html": "1"}, "wild.bench", "*")
	domainAliases["alias.bench"] = "bench.test"
	return dir
}

func lastPathSegment(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

// benchRequest is a GET of uri for host from remote, as the server gives it to the handler.
func benchRequest(host, uri, remote string) *customNetHttp.Request {
	target, _ := url.ParseRequestURI(uri)
	return &customNetHttp.Request{
		Method: "GET", Host: host, RequestURI: uri, URL: target, Header: customNetHttp.Header{},
		RemoteAddr: remote, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}
}

var benchResolveCases = []struct{ name, host, uri string }{
	{"default", "localhost", "/"}, {"realistic", "bench.test", "/css/site.css"}, {"wildcard", "a.wild.bench", "/"},
	{"alias", "alias.bench", "/css/site.css"}, {"miss", "unknown.bench", "/"},
}

// BenchmarkResolveRequest measures what the handler does with the global read lock held: finding the site of the
// request and what it serves, without the disk.
func BenchmarkResolveRequest(b *testing.B) {
	benchSites(b)
	for _, c := range benchResolveCases {
		resolve := func() {
			recorder := &responseRecorder{}
			request := benchRequest(c.host, c.uri, "203.0.113.9:40000")
			held := newHeldResponse(recorder)
			acme := &acmeLookup{}
			withReadLock(func() { resolveRequest(false, held, request, acme) })
			held.sendTo(recorder)
		}
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				resolve()
			}
		})
		b.Run(c.name+"-parallel", func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					resolve()
				}
			})
		})
	}
}

// BenchmarkHandlerStatic measures the whole handler for a file, without the network: the limits of its client, the
// resolution and the file served to a recorder.
func BenchmarkHandlerStatic(b *testing.B) {
	benchSites(b)
	handler := serverHandlerFn(false)
	var clients atomic.Int64
	for _, c := range benchResolveCases[:2] {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				recorder := &responseRecorder{}
				handler(recorder, benchRequest(c.host, c.uri, "198.51.100.1:40000"))
				if recorder.code != 200 {
					b.Fatalf("%s%s: %d", c.host, c.uri, recorder.code)
				}
			}
		})
		b.Run(c.name+"-parallel", func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				remote := "198.51.100." + strconv.FormatInt(clients.Add(1)%250+2, 10) + ":40000" // One client each: not their limiter
				for pb.Next() {
					recorder := &responseRecorder{}
					handler(recorder, benchRequest(c.host, c.uri, remote))
				}
			})
		})
	}
}

// BenchmarkRateLimited measures the limits of a client that is within them: its address read, and its count.
func BenchmarkRateLimited(b *testing.B) {
	benchSites(b)
	for name, remote := range map[string]string{"ipv4": "203.0.113.7:40000", "ipv6": "[2001:db8:1:2:3:4:5:6]:40000"} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if status, _ := rateLimited(clientOf(remote)); status != 0 {
					b.Fatalf("limited: %d", status)
				}
			}
		})
	}
}

// BenchmarkRewriteLookup measures looking for the rewrite of a path among those of its site, where names are told
// apart by case and where they aren't: a path that has none, short and deep, and one written in other capitals than
// its rewrite (which only has it where names fold).
func BenchmarkRewriteLookup(b *testing.B) {
	initForTest(b)
	previous, previousDir := foldRewrites, sitesDirFolds.Load()
	b.Cleanup(func() {
		withGlobalLock(func() { foldRewrites = previous })
		sitesDirFolds.Store(previousDir)
	})
	paths := []struct{ name, path string }{{"miss-depth=1", "/a"}, {"miss-depth=6", "/a/b/c/d/e/f"}, {"othercase", "/SECTION0/b/c"}, {"exact", "/Section0/"}}
	for _, fold := range []bool{false, true} {
		for _, count := range []int{0, 10, 100, 1000} {
			for _, c := range paths {
				b.Run("fold="+strconv.FormatBool(fold)+"/rewrites="+strconv.Itoa(count)+"/"+c.name, func(b *testing.B) {
					sitesDirFolds.Store(fold) // On Windows the sites directory folds: that alone folds the rewrites
					withGlobalLock(func() {
						foldRewrites = fold
						constructSiteWithoutIndex("rewrites.bench", "")
						for i := 0; i < count; i++ {
							sitesMap["rewrites.bench"][""]["/Section"+strconv.Itoa(i)+"/"] = "N/target"
						}
					})
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						withReadLock(func() { rewrite(c.path, "rewrites.bench", "") })
					}
				})
			}
		}
	}
}

// BenchmarkVisitsLogLine measures the line that each request writes in turbo.visits.
func BenchmarkVisitsLogLine(b *testing.B) {
	dir := initForTest(b)
	os.WriteFile(dir+visitsLogName, nil, 0600)
	updateSettings(false) // Opens the log
	request := benchRequest("localhost", "/css/site.css?v=1", "203.0.113.9:40000")
	b.Run("sequential", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			serverWriteLogs(visitsLogName, request, 1700000000, "Visit")
		}
	})
	b.Run("parallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				serverWriteLogs(visitsLogName, request, 1700000000, "Visit")
			}
		})
	})
}

// benchGet reads GET /hello.txt of localhost at base until pb says.
func benchGet(b *testing.B, base string, next func() bool) {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 1}}
	defer client.CloseIdleConnections()
	for next() {
		request, _ := http.NewRequest("GET", base+"/hello.txt", nil)
		request.Host = "localhost"
		response, err := client.Do(request)
		if err != nil {
			b.Error(err)
			return
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
}

// BenchmarkServeStaticLogged is BenchmarkServeStatic with turbo.visits there, or not, and with one connection or with
// many, each from a client of its own: what the visits log costs a server in use.
func BenchmarkServeStaticLogged(b *testing.B) {
	for _, visits := range []bool{false, true} {
		name := "novisits"
		if visits {
			name = "visits"
		}
		b.Run(name, func(b *testing.B) {
			dir := initForTest(b)
			serverRequestLimits.CII.Store(1 << 40)
			os.WriteFile(dir+"localhost/@/hello.txt", []byte("hello"), 0644)
			if visits {
				os.WriteFile(dir+visitsLogName, nil, 0600)
				updateSettings(false)
			}
			var connections atomic.Int64
			base, _ := startServerAs(b, func() net.IP { return net.IPv4(198, 51, 100, byte(connections.Add(1)%250+2)) })
			b.Run("sequential", func(b *testing.B) {
				left := b.N
				benchGet(b, base, func() bool { left--; return left >= 0 })
			})
			b.Run("parallel", func(b *testing.B) {
				b.SetParallelism(4)
				b.RunParallel(func(pb *testing.PB) { benchGet(b, base, pb.Next) })
			})
		})
	}
}
