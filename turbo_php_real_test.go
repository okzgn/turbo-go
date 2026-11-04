package main

// V2 (N37, N64, I11, N12): Turbo with the real php-cgi, where it is installed (on
// Windows and where there is no php-cgi, the test is skipped). The environment
// PHP sees, REDIRECT_STATUS with cgi.force_redirect, forms and uploads, chunked
// bodies, PHP's headers and codes, sessions, timings, processes it leaves
// behind, fatal errors, big output and HEAD.

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// phpScripts are the scripts of the test, in the @ of localhost.
var phpScripts = map[string]string{
	"info.php": `<?php
foreach (["PHP_SELF", "SCRIPT_NAME", "PATH_INFO", "REQUEST_URI", "QUERY_STRING", "REDIRECT_STATUS", "CONTENT_LENGTH"] as $k) {
	echo $k, "=", $_SERVER[$k] ?? "(no)", "\n";
}
echo "GET=", json_encode($_GET), "\n";`,
	"post.php":  `<?php echo "a=", $_POST["a"] ?? "(no)", ";b=", $_POST["b"] ?? "(no)";`,
	"up.php":    `<?php echo move_uploaded_file($_FILES["f"]["tmp_name"], __DIR__ . "/uploaded.txt") ? "moved" : "not moved";`,
	"input.php": `<?php echo strlen(file_get_contents("php://input")), ";", $_SERVER["CONTENT_LENGTH"] ?? "(no)";`,
	"hdr.php":   `<?php header("X-Php: yes"); http_response_code(404); echo "not here";`,
	"loc.php":   `<?php header("Location: /other"); echo "outside";`,
	"sess.php": `<?php
ini_set("session.save_path", dirname(__DIR__) . "/sessions");
session_start();
$_SESSION["n"] = ($_SESSION["n"] ?? 0) + 1;
echo $_SESSION["n"];`,
	"slow.php":  `<?php sleep(6); echo "late";`,
	"bg.php":    `<?php pclose(popen("sleep 4 &", "w")); echo "leaves a process";`,
	"fatal.php": `<?php this_function_does_not_exist(); echo "never";`,
	"big.php":   `<?php echo str_repeat("x", 5 * 1024 * 1024);`,
}

func TestV02_PHPReal(t *testing.T) {
	php, err := exec.LookPath("php-cgi")
	if err != nil {
		t.Skip("php-cgi is not installed")
	}
	dir := initForTest(t)
	for name, code := range phpScripts {
		if err := os.WriteFile(dir+"localhost/@/"+name, []byte(code), 0644); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(dir+"localhost/sessions", 0700)
	globalMutex.Lock()
	if ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"php": php}, false, "localhost", ""); !ok {
		globalMutex.Unlock()
		t.Fatal(msg)
	}
	if ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{"/r/": "/info.php?c={REWRITE_COMPLEMENT}"}, false, "localhost", ""); !ok {
		globalMutex.Unlock()
		t.Fatal(msg)
	}
	globalMutex.Unlock()
	if ok, msg := setting("WT", "2s"); !ok {
		t.Fatal(msg)
	}
	base := startServer(t)
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, path, contentType string, body io.Reader, cookie string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, base+path, body)
		req.Host = "localhost"
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res, string(b)
	}
	lines := func(body string) map[string]string {
		values := map[string]string{}
		for _, line := range strings.Split(body, "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				values[k] = v
			}
		}
		return values
	}

	t.Run("environment", func(t *testing.T) {
		_, body := do("GET", "/info.php?x=1", "", nil, "")
		v := lines(body)
		want := map[string]string{"PHP_SELF": "/info.php", "SCRIPT_NAME": "/info.php", "PATH_INFO": "(no)", "REQUEST_URI": "/info.php?x=1", "QUERY_STRING": "x=1", "REDIRECT_STATUS": "CGI"}
		for k, w := range want {
			if v[k] != w && !(k == "PATH_INFO" && v[k] == "") {
				t.Errorf("%s = %q; expected %q\n%s", k, v[k], w, body)
			}
		}
	})
	t.Run("rewrite with REWRITE_COMPLEMENT", func(t *testing.T) {
		// In the query, {REWRITE_COMPLEMENT} is the rest of the path plus the query, as one value; the client's
		// query goes first.
		_, body := do("GET", "/r/x/y?a=1", "", nil, "")
		v := lines(body)
		if v["QUERY_STRING"] != "a=1&c=x%2Fy%3Fa%3D1" || v["PHP_SELF"] != "/info.php" || v["REQUEST_URI"] != "/r/x/y?a=1" || v["GET"] != `{"a":"1","c":"x\/y?a=1"}` {
			t.Errorf("after the rewrite: %q", body)
		}
	})
	t.Run("POST urlencoded", func(t *testing.T) {
		if _, body := do("POST", "/post.php", "application/x-www-form-urlencoded", strings.NewReader("a=one&b=two+three"), ""); body != "a=one;b=two three" {
			t.Errorf("POST: %q", body)
		}
	})
	t.Run("multipart upload", func(t *testing.T) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		part, _ := w.CreateFormFile("f", "a.txt")
		part.Write([]byte("uploaded content"))
		w.Close()
		if _, body := do("POST", "/up.php", w.FormDataContentType(), &buf, ""); body != "moved" {
			t.Fatalf("upload: %q", body)
		}
		if data, _ := os.ReadFile(dir + "localhost/@/uploaded.txt"); string(data) != "uploaded content" {
			t.Errorf("uploaded.txt = %q", data)
		}
	})
	t.Run("chunked body", func(t *testing.T) {
		body := io.MultiReader(strings.NewReader(strings.Repeat("c", 3000))) // Unknown length: sent chunked
		if _, got := do("POST", "/input.php", "application/octet-stream", body, ""); got != "3000;3000" {
			t.Errorf("php://input of a chunked body: %q; expected 3000;3000", got)
		}
	})
	t.Run("PHP headers and code", func(t *testing.T) {
		res, body := do("GET", "/hdr.php", "", nil, "")
		if res.StatusCode != 404 || res.Header.Get("X-Php") != "yes" || body != "not here" {
			t.Errorf("header() and http_response_code(404): %d %q %q", res.StatusCode, res.Header.Get("X-Php"), body)
		}
		res, _ = do("GET", "/loc.php", "", nil, "")
		if res.StatusCode != 302 || res.Header.Get("Location") != "/other" {
			t.Errorf("Location: %d %q", res.StatusCode, res.Header.Get("Location"))
		}
	})
	t.Run("sessions", func(t *testing.T) {
		res, first := do("GET", "/sess.php", "", nil, "")
		var cookie string
		for _, c := range res.Cookies() {
			if c.Name == "PHPSESSID" {
				cookie = c.Name + "=" + c.Value
			}
		}
		if _, second := do("GET", "/sess.php", "", nil, cookie); first != "1" || second != "2" || cookie == "" {
			t.Errorf("PHP session: %q, %q (cookie %q)", first, second, cookie)
		}
	})
	t.Run("longer than WT", func(t *testing.T) {
		start := time.Now()
		res, _ := do("GET", "/slow.php", "", nil, "")
		if res.StatusCode != 504 || time.Since(start) > 5*time.Second {
			t.Errorf("6 s script with WT = 2 s: %d in %v; expected 504 in a little over 2 s", res.StatusCode, time.Since(start))
		}
	})
	t.Run("process left behind with the output open", func(t *testing.T) {
		start := time.Now()
		_, body := do("GET", "/bg.php", "", nil, "")
		if elapsed := time.Since(start); body != "leaves a process" || elapsed > 2500*time.Millisecond {
			t.Errorf("PHP that leaves a sleep 4 with its output: %q in %v; expected the response in a little over 1 s", body, elapsed)
		}
	})
	t.Run("fatal error", func(t *testing.T) {
		res, body := do("GET", "/fatal.php", "", nil, "")
		if res.StatusCode != 500 || strings.Contains(body, "never") || strings.Contains(body, dir) {
			t.Errorf("PHP fatal error: %d %q; expected 500 without details", res.StatusCode, body)
		}
	})
	t.Run("big output", func(t *testing.T) {
		if _, body := do("GET", "/big.php", "", nil, ""); len(body) != 5*1024*1024 {
			t.Errorf("5 MiB output: %d bytes arrived", len(body))
		}
	})
	t.Run("HEAD", func(t *testing.T) {
		if res, body := do("HEAD", "/info.php", "", nil, ""); res.StatusCode != 200 || body != "" {
			t.Errorf("HEAD: %d %q", res.StatusCode, body)
		}
	})
}
