package main

// P14 (N91, N102, N103, N105, N106): the body of a CGI request is read whole before the CGI takes a slot and
// starts, and reaches it through a pipe; the connection's write deadline counts from when the CGI starts; the
// framing headers of its answer are the server's; and on every system it gets the variables of the temporary
// folder.

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// N91: a CGI slot is taken once the body has been read: a client that sends its body slowly, or not at all,
// doesn't hold one. Before, with the slots taken that way (CGP of them), every other CGI request got 503.
func TestN91_SlowBodyHoldsNoCGISlot(t *testing.T) {
	_, base := cgiLoadSetup(t)
	if ok, msg := defaultSettingValidators["."]["CGP"]("1", "Admin"); !ok {
		t.Fatal(msg)
	}
	addr := strings.TrimPrefix(base, "http://")
	for _, head := range []string{
		"POST /x.cgi HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nabc",
		"POST /x.cgi HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
	} {
		slow, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(slow, head)
		time.Sleep(300 * time.Millisecond) // The slow request is in the CGI code by now
		req, _ := http.NewRequest("GET", base+"/x.cgi", nil)
		req.Host = "localhost"
		res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 200 {
			t.Errorf("with %q half sent: another CGI request got %d; expected 200", strings.SplitN(head, "\r\n", 4)[2], res.StatusCode)
		}
		slow.Close()
	}
}

// N102: the connection's write deadline for a CGI (WT + 2 s) counts from when the CGI starts, not from before
// the body is read: a body that takes longer than that still gets its answer.
func TestN102_WriteDeadlineFromCGIStart(t *testing.T) {
	_, base := cgiLoadSetup(t)
	globalMutex.Lock()
	setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.WT = time.Second })
	globalMutex.Unlock()
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "POST /x.cgi HTTP/1.1\r\nHost: localhost\r\nContent-Length: 6\r\nConnection: close\r\n\r\nabc")
	time.Sleep(3500 * time.Millisecond) // Past WT + 2 s, within RT (5 s)
	io.WriteString(conn, "def")
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	answer, _ := io.ReadAll(conn)
	if !bytes.HasPrefix(answer, []byte("HTTP/1.1 200")) || !bytes.Contains(answer, []byte("BODY_BYTES=6")) {
		t.Errorf("body finished after WT + 2 s: %q; expected the CGI's response", answer)
	}
}

// N103: a Content-Length of a CGI that isn't only digits ("+4", "-0") is dropped, as Go takes it as a number but
// would send it as written, which a client or a proxy may read otherwise.
func TestN103_CGIContentLengthOnlyDigits(t *testing.T) {
	dir, base := cgiLoadSetup(t)
	for _, value := range []string{"+4", "-0", "+0"} {
		os.WriteFile(dir+"localhost/@/r.cgi", []byte("Content-Type: text/plain\r\nContent-Length: "+value+"\r\n\r\nabcd"), 0644)
		conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(conn, "GET /r.cgi?raw=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		head := ""
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			head += line
			if err != nil || line == "\r\n" {
				break
			}
		}
		conn.Close()
		if strings.Contains(head, "Content-Length: "+value+"\r\n") {
			t.Errorf("the CGI's Content-Length %q was sent as is:\n%s", value, head)
		}
	}
}

// N105: a body kept in a temporary file reaches the CGI through a pipe, not as the file: what the CGI starts
// can't inherit it, and the file is removed when the request ends. Before, on Windows, a child of the CGI that
// kept its input open left the file behind.
func TestN105_CGIBodyFileNotInherited(t *testing.T) {
	tmp := t.TempDir()
	for _, name := range []string{"TMP", "TEMP", "TMPDIR"} {
		t.Setenv(name, tmp)
	}
	_, base := cgiLoadSetup(t)
	maxBodySize.Store(5 << 20)
	t.Cleanup(func() { maxBodySize.Store(1048576) })
	mark := filepath.ToSlash(filepath.Join(t.TempDir(), "child"))
	body := bytes.Repeat([]byte("x"), 2<<20) // Beyond what is kept in memory
	req, _ := http.NewRequest("POST", base+"/x.cgi?childstdin=1500&childmark="+url.QueryEscape(mark), io.NopCloser(bytes.NewReader(body)))
	req.Host = "localhost"
	res, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !bytes.Contains(answer, []byte("BODY_BYTES=2097152")) {
		t.Fatalf("2 MiB POST: %d %q", res.StatusCode, answer)
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(mark); err == nil {
			break
		}
	}
	time.Sleep(300 * time.Millisecond) // The child has ended
	entries, _ := os.ReadDir(tmp)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "turbo-cgi-") {
			t.Errorf("the body's temporary file is still there after the request: %s", entry.Name())
		}
	}
}

// N106: a CGI gets the variables of the temporary folder (TEMP and TMP on Windows, TMPDIR elsewhere), which PHP
// uses for uploads and sessions. Before, on Windows, it got none and fell back to the Windows folder.
func TestN106_CGIGetsTempFolder(t *testing.T) {
	names := []string{"TMPDIR"}
	if runtime.GOOS == "windows" {
		names = []string{"TEMP", "TMP"}
	}
	for _, name := range names {
		t.Setenv(name, t.TempDir())
	}
	_, base := cgiLoadSetup(t)
	code, body, err := get(base, "/x.cgi", nil)
	if err != nil || code != 200 {
		t.Fatalf("GET /x.cgi: %d %v", code, err)
	}
	got := "," + cgiEnv(body)["ENV_NAMES"] + ","
	for _, name := range names {
		if !strings.Contains(got, ","+name+",") {
			t.Errorf("the CGI didn't get %s (it got %s)", name, got)
		}
	}
}
