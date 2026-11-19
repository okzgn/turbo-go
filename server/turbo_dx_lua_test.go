package server

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// The mode dx with the real worker of Lua, dx-lua (dx/dx-lua, in Rust): TURBO_DX_LUA names the program,
// or it is found in the PATH; without it these tests are skipped, as the one of php-cgi is. The continuous integration
// builds it.
func dxLuaProgram(t testing.TB) string {
	t.Helper()
	source := os.Getenv("TURBO_DX_LUA")
	if source == "" {
		found, err := exec.LookPath("dx-lua")
		if err != nil {
			t.Skip("dx-lua is not built: TURBO_DX_LUA names it, or it is in the PATH")
		}
		source = found
	}
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("TURBO_DX_LUA: %v", err)
	}
	target := toolPath("dx-lua") // Next to the test tools: a short path, as a preprocessor needs
	if existing, err := os.ReadFile(target); err != nil || !bytes.Equal(existing, data) {
		if err := os.WriteFile(target, data, 0755); err != nil {
			t.Fatal(err)
		}
	}
	return target
}

var dxLuaScripts = map[string]string{
	"hello.lua": `return "<h1>Hello, " .. turbox.html_escape(REQUEST.params.name or "world") .. "</h1>"`,
	"echo.lua": `
		local files = {}
		for _, f in ipairs(REQUEST.files) do files[#files + 1] = f.field .. ":" .. f.filename .. ":" .. f.data end
		return { status = 200, headers = { ["Content-Type"] = "text/plain", ["X-Echo"] = "yes", ["Set-Cookie"] = { "a=1", "b=2" } },
			body = table.concat({ METHOD, REQUEST.path, REQUEST.vars.SCRIPT_NAME, REQUEST.host, REQUEST.headers["x-test"] or "-",
				REQUEST.cookies.c or "-", tostring(REQUEST.cookies.turbo_session), REQUEST.form.name or "-", table.concat(files, ","),
				#BODY, tostring(REQUEST.vars.DX_GRANTS), tostring(REQUEST.vars.HTTP_DX_GRANTS) }, "|") }`,
	"missing.lua": `return 404`,
	"secret.lua":  `error("a secret of the script")`,
	"sandbox.lua": `return tostring(io) .. tostring(os) .. tostring(require) .. tostring(load) .. tostring(debug) .. tostring(ffi)`,
	"loop.lua":    `while true do end`,
	"memory.lua":  `local s = "x" for i = 1, 40 do s = s .. s end return #s`,
	"n.lua":       `return REQUEST.params.n`,
	"deep.lua": `
		local depth = 0
		local function f() depth = depth + 1 return (string.gsub("x", "x", f)) end
		local ok, message = pcall(f)
		return tostring(ok) .. "|" .. depth .. "|" .. tostring(message)`,
	// As a tail call, string.gsub takes the frame of f: some 13 000 levels, the deepest (review of v2.5.1, RS-1)
	"deeptail.lua": `
		local depth = 0
		local function f() depth = depth + 1 return string.gsub("x", "x", f) end
		local ok, message = pcall(f)
		return tostring(ok) .. "|" .. depth .. "|" .. tostring(message)`,
	"number.lua": `return { headers = { ["X-Ratio"] = 1.5 }, body = 2.5 }`,
}

func setupDXLua(t *testing.T) (string, string) {
	t.Helper()
	program := dxLuaProgram(t)
	dir := initForTest(t)
	for name, code := range dxLuaScripts {
		if err := os.WriteFile(dir+"localhost/@/"+name, []byte(code), 0644); err != nil {
			t.Fatal(err)
		}
	}
	globalMutex.Lock()
	ok, message := subdomainContentCheckers["?"](true, map[string]interface{}{"lua": "dx>" + program}, false, "localhost", "")
	if ok {
		ok, message = subdomainContentCheckers["="](true, map[string]interface{}{"/pretty/": "/echo.lua"}, false, "localhost", "")
	}
	globalMutex.Unlock()
	if !ok {
		t.Fatal(message)
	}
	t.Cleanup(func() { stopPreprocessorModes(time.Second) })
	return dir, startServer(t)
}

func TestDXLuaServesScripts(t *testing.T) {
	_, base := setupDXLua(t)
	if code, body := dxRequest(t, "GET", base, "/hello.lua?name=%3Cb%3E", nil, nil); code != 200 || body != "<h1>Hello, &lt;b&gt;</h1>" {
		t.Errorf("hello.lua: %d %q", code, body)
	}
	if code, body := dxRequest(t, "GET", base, "/sandbox.lua", nil, nil); code != 200 || body != "nilnilnilnilnilnil" {
		t.Errorf("the sandbox: %d %q", code, body)
	}
	if code, body := dxRequest(t, "GET", base, "/missing.lua", nil, nil); code != 404 || !strings.Contains(body, "404") {
		t.Errorf("return 404: %d %q; expected the site's template", code, body)
	}
	if code, body := dxRequest(t, "GET", base, "/secret.lua", nil, nil); code != 500 || strings.Contains(body, "secret") {
		t.Errorf("an error of a script: %d %q; expected 500 without its text", code, body)
	}
	if code, _ := dxRequest(t, "GET", base, "/memory.lua", nil, nil); code != 500 {
		t.Errorf("a script out of memory: %d; expected 500", code)
	}
	if code, body := dxRequest(t, "GET", base, "/hello.lua", nil, nil); code != 200 || !strings.Contains(body, "world") {
		t.Errorf("after the errors: %d %q", code, body)
	}
}

// What a script gets of the request, through Turbo: the path asked for and the script's, a header, the cookies but the
// panel's session, a form with a file in memory; and nothing granted, whatever the client sends.
func TestDXLuaGetsTheRequest(t *testing.T) {
	_, base := setupDXLua(t)
	var form bytes.Buffer
	writer := multipart.NewWriter(&form)
	writer.WriteField("name", "ana")
	file, _ := writer.CreateFormFile("doc", "a;b.txt")
	file.Write([]byte("12345"))
	writer.Close()
	headers := map[string]string{"Content-Type": writer.FormDataContentType(), "X-Test": "yes", "Cookie": "c=3; turbo_session=secret", "DX-Grants": "fs"}
	code, body := dxRequest(t, "POST", base, "/pretty/x", form.Bytes(), headers)
	expected := "POST|/pretty/x|/echo.lua|localhost|yes|3|nil|ana|doc:a;b.txt:12345|0|nil|fs"
	if code != 200 || body != expected {
		t.Errorf("echo.lua:\n got %d %q\nwant 200 %q", code, body, expected)
	}
}

// The headers of a script, a list among them, reach the client.
func TestDXLuaHeaders(t *testing.T) {
	_, base := setupDXLua(t)
	response, body, err := rawGet(base, "localhost", "/echo.lua")
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("echo.lua: %v %q", err, body)
	}
	if response.Header.Get("X-Echo") != "yes" || len(response.Header.Values("Set-Cookie")) != 2 {
		t.Errorf("the headers of the script: %v", response.Header)
	}
}

// A script that doesn't end: the worker stops it before WT is over (DX_TIMEOUT_MS leaves it a margin) and answers
// 500, before Turbo would give up (504) and kill it; and the next request is answered.
func TestDXLuaTime(t *testing.T) {
	_, base := setupDXLua(t)
	if ok, message := setting("WT", "1s"); !ok {
		t.Fatal(message)
	}
	start := time.Now()
	if code, _ := dxRequest(t, "GET", base, "/loop.lua", nil, nil); code != 500 || time.Since(start) > 5*time.Second {
		t.Errorf("a script that doesn't end: %d after %v; expected 500 after about 0.9 s", code, time.Since(start))
	}
	if code, body := dxRequest(t, "GET", base, "/hello.lua", nil, nil); code != 200 || !strings.Contains(body, "world") {
		t.Errorf("after it: %d %q", code, body)
	}
}

// V2.5.0 review DX-1: a script that recurses through a function of the library (string.gsub with a function) gets
// LuaJIT's "stack overflow", an error that pcall catches, and its worker goes on: the stack of C ran out first, the
// worker ended, and so did the one of the retry. Also as a tail call, the deepest (review of v2.5.1, RS-1: with a
// stack of 96 or 112 MiB the worker ended there on Linux). And DX-4: a number with decimals is a body and a header's
// value.
func TestDXLuaDeepRecursionKeepsTheWorker(t *testing.T) {
	_, base := setupDXLua(t)
	logs := captureLog(t)
	for _, script := range []string{"/deep.lua", "/deeptail.lua"} {
		for attempt := 0; attempt < 2; attempt++ {
			code, body := dxRequest(t, "GET", base, script, nil, nil)
			if code != 200 || !strings.HasPrefix(body, "false|") || !strings.Contains(body, "stack overflow") {
				t.Fatalf("request %d of %s, which recurses through string.gsub: %d %q; expected the error caught by pcall", attempt+1, script, code, body)
			}
		}
	}
	if code, body := dxRequest(t, "GET", base, "/number.lua", nil, nil); code != 200 || body != "2.5" {
		t.Errorf("a number as the body: %d %q", code, body)
	}
	if code, body := dxRequest(t, "GET", base, "/hello.lua", nil, nil); code != 200 || !strings.Contains(body, "world") {
		t.Errorf("after them: %d %q", code, body)
	}
	if text := logs.String(); strings.Contains(text, "the worker ended") || strings.Contains(text, "overflowed its stack") {
		t.Errorf("a worker ended: %s", text)
	}
}

// Many requests at once: each gets its own answer. (What is tested is the workers, not the limiter: its limit is
// removed, as in TestR_RealisticRace.)
func TestDXLuaManyAtOnce(t *testing.T) {
	_, base := setupDXLua(t)
	serverRequestLimits.CII.Store(1 << 40)
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var wrong []string
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 10 {
				n := fmt.Sprint(i*100 + j)
				code, body := dxRequest(t, "GET", base, "/n.lua?n="+n, nil, nil)
				if code != 200 || body != n {
					mutex.Lock()
					wrong = append(wrong, fmt.Sprintf("%s: %d %q", n, code, body))
					mutex.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if len(wrong) > 0 {
		t.Errorf("%d wrong answers, as %s", len(wrong), wrong[0])
	}
}

// What a request to a script costs in each mode, through the server and its loopback: a CGI started for each request
// (cgiecho), and a worker kept running (dxecho, which answers as cgiecho does, and dx-lua, where it is).
func BenchmarkPreprocessorModes(b *testing.B) {
	modes := []struct{ name, extension, value, code string }{
		{"cgi-cgiecho", "e", toolPath("cgiecho"), "the script"},
		{"dx-dxecho", "e", "dx>" + toolPath("dxecho"), "the script"},
		{"dx-lua", "lua", "", `return "ok"`},
	}
	for _, mode := range modes {
		b.Run(mode.name, func(b *testing.B) {
			if mode.value == "" {
				mode.value = "dx>" + dxLuaProgram(b)
			}
			dir := initForTest(b)
			b.Cleanup(func() { stopPreprocessorModes(time.Second) })
			serverRequestLimits.CII.Store(1 << 40)
			os.WriteFile(dir+"localhost/@/x."+mode.extension, []byte(mode.code), 0644)
			globalMutex.Lock()
			ok, message := subdomainContentCheckers["?"](true, map[string]interface{}{mode.extension: mode.value}, false, "localhost", "")
			globalMutex.Unlock()
			if !ok {
				b.Fatal(message)
			}
			base := startServer(b)
			client := &http.Client{Timeout: 10 * time.Second}
			defer client.CloseIdleConnections()
			get := func() {
				request, _ := http.NewRequest("GET", base+"/x."+mode.extension+"?a=1", nil)
				request.Host = "localhost"
				response, err := client.Do(request)
				if err != nil {
					b.Fatal(err)
				}
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode != 200 {
					b.Fatalf("status %d", response.StatusCode)
				}
			}
			get() // The first starts the worker
			b.ResetTimer()
			for range b.N {
				get()
			}
		})
	}
}
