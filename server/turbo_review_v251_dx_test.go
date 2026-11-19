package server

// The tests of the findings about the worker of Lua (dx-lua 0.3.2) of the review of v2.5.1, with the real worker
// (TURBO_DX_LUA, as the tests of turbo_dx_lua_test.go): each failed with dx-lua 0.3.1.

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// V2.5.1 review RS-3: a Content-Length that a script returns doesn't reach the client: the length is the body's. One
// that wasn't it cut the answer (none of the body, or some of it) and closed the connection.
func TestR251_RS3_TheContentLengthOfAScriptIsDropped(t *testing.T) {
	dir, base := setupDXLua(t)
	script := `return { headers = { ["Content-Length"] = REQUEST.params.cl, ["X-Test"] = "yes" }, body = "hello world" }`
	if err := os.WriteFile(dir+"localhost/@/length.lua", []byte(script), 0644); err != nil {
		t.Fatal(err)
	}
	for _, length := range []string{"5", "50", "11"} {
		conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		// A second request on the same connection: it is answered, after the whole body of the first
		_, _ = io.WriteString(conn, "GET /length.lua?cl="+length+" HTTP/1.1\r\nHost: localhost\r\n\r\nGET /hello.lua HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
		reader := bufio.NewReader(conn)
		first, err := http.ReadResponse(reader, nil)
		if err != nil {
			conn.Close()
			t.Fatalf("Content-Length %s from the script: %v", length, err)
		}
		body, err := io.ReadAll(first.Body)
		if err != nil || string(body) != "hello world" || first.Header.Get("X-Test") != "yes" || first.ContentLength != -1 && first.ContentLength != 11 {
			t.Errorf("Content-Length %s from the script: %q, %v, length %d; expected the whole body, with its own length", length, body, err, first.ContentLength)
		}
		second, err := http.ReadResponse(reader, nil)
		if err == nil {
			body, err = io.ReadAll(second.Body)
		}
		if err != nil || !strings.Contains(string(body), "Hello, world") {
			t.Errorf("Content-Length %s from the script: the next request on the connection: %v %q", length, err, body)
		}
		conn.Close()
	}
}

// V2.5.1 review RS-2: table.insert with a position out of 1 to #t + 1 is an error at once (500), and the worker
// goes on: a position of 2^31 that a request gave held it some 18 s in a loop of C, past its time.
func TestR251_RS2_TableInsertFarAwayIsAnError(t *testing.T) {
	dir, base := setupDXLua(t)
	script := `local list = {} local position = tonumber(REQUEST.params.p) if position < 1 then position = 1 end
		table.insert(list, position, "x") return tostring(#list)`
	if err := os.WriteFile(dir+"localhost/@/insert.lua", []byte(script), 0644); err != nil {
		t.Fatal(err)
	}
	for position, expected := range map[string]int{"2147483648": 500, "4294967296": 500, "1": 200} {
		start := time.Now()
		code, body := dxRequest(t, "GET", base, "/insert.lua?p="+position, nil, nil)
		if code != expected || time.Since(start) > 3*time.Second {
			t.Errorf("table.insert at %s: %d %q in %v; expected %d at once", position, code, body, time.Since(start), expected)
		}
	}
	if code, body := dxRequest(t, "GET", base, "/hello.lua", nil, nil); code != 200 || !strings.Contains(body, "world") {
		t.Errorf("after them: %d %q", code, body)
	}
}
