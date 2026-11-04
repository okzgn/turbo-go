// Echo CGI: it returns the relevant environment variables and the bytes read from the body.
// With sleep=<ms> in the query it waits before responding and, if it also carries
// mark=<path>, creates that file when the wait ends. With header=<line>
// (repeatable) it writes that header line before Content-Type, and with
// bigheader=<bytes>, a header line of that size. With after=<ms> it keeps
// running that long after writing, with its output open. With raw=1 it
// only writes, as is, the content of the requested script (SCRIPT_FILENAME):
// any CGI response, headers included. With big=<bytes> it responds with
// that many bytes, in chunks (a large streaming output; the manual stability
// test uses it, not the test suite). With child=<ms> it leaves a child
// that inherits its output, waits that long and creates the file childmark=<path>;
// with childstdin=<ms>, one that inherits its input (not its output). With
// procstatus=1 it writes the Cap* lines of /proc/self/status (Linux). With
// env=<NAME,NAME…> it also writes those variables.
package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	if ms, err := strconv.Atoi(os.Getenv("CGIECHO_CHILD")); err == nil { // The child of child=: it keeps stdout open
		time.Sleep(time.Duration(ms) * time.Millisecond)
		if mark := os.Getenv("CGIECHO_CHILDMARK"); mark != "" {
			os.WriteFile(mark, nil, 0644)
		}
		return
	}
	q, _ := url.ParseQuery(os.Getenv("QUERY_STRING"))
	if q.Get("raw") != "" { // The script's file is the whole response
		if script, err := os.Open(os.Getenv("SCRIPT_FILENAME")); err == nil {
			io.Copy(os.Stdout, script)
			script.Close()
		}
		return
	}
	if size, err := strconv.Atoi(q.Get("big")); err == nil { // A large answer, written as it goes
		io.Copy(io.Discard, os.Stdin)
		fmt.Print("Content-Type: application/octet-stream\r\n\r\n")
		chunk := []byte(strings.Repeat("x", 32<<10))
		for left := size; left > 0; left -= len(chunk) {
			if _, err := os.Stdout.Write(chunk[:min(left, len(chunk))]); err != nil {
				return // The client went away
			}
		}
		if ms, err := strconv.Atoi(q.Get("after")); err == nil { // And it keeps running, its output open
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
		return
	}
	if ms := q.Get("child"); ms != "" { // Leaves a child that inherits stdout, sleeps ms and then writes childmark
		child := exec.Command(os.Args[0])
		child.Env = append(os.Environ(), "CGIECHO_CHILD="+ms, "CGIECHO_CHILDMARK="+q.Get("childmark"))
		child.Stdout = os.Stdout
		child.Start()
	}
	if ms := q.Get("childstdin"); ms != "" { // Leaves a child that inherits stdin (not stdout), sleeps ms and then writes childmark
		child := exec.Command(os.Args[0])
		child.Env = append(os.Environ(), "CGIECHO_CHILD="+ms, "CGIECHO_CHILDMARK="+q.Get("childmark"))
		child.Stdin = os.Stdin
		child.Start()
	}
	if ms, err := strconv.Atoi(q.Get("sleep")); err == nil {
		time.Sleep(time.Duration(ms) * time.Millisecond)
		if mark := q.Get("mark"); mark != "" {
			os.WriteFile(mark, nil, 0644)
		}
	}
	n, _ := io.Copy(io.Discard, os.Stdin)
	for _, line := range q["header"] {
		fmt.Print(line + "\r\n")
	}
	if size, err := strconv.Atoi(q.Get("bigheader")); err == nil { // One header line of that many bytes
		fmt.Print("X-Big: " + strings.Repeat("a", max(size-len("X-Big: "), 0)) + "\r\n")
	}
	fmt.Print("Content-Type: text/plain\r\n\r\n")
	if q.Get("procstatus") != "" { // The capabilities the CGI got (Linux)
		status, _ := os.ReadFile("/proc/self/status")
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Cap") {
				fmt.Println(line)
			}
		}
	}
	keys := []string{"QUERY_STRING", "REDIRECT_STATUS", "SCRIPT_FILENAME", "SCRIPT_NAME", "DOCUMENT_ROOT", "REQUEST_URI", "CONTENT_LENGTH", "HTTP_HOST", "PATH_INFO", "HTTP_COOKIE"}
	for _, k := range keys {
		fmt.Printf("%s=%s\n", k, os.Getenv(k))
	}
	for _, k := range strings.Split(q.Get("env"), ",") {
		if k != "" {
			fmt.Printf("%s=%s\n", k, os.Getenv(k))
		}
	}
	env := os.Environ()
	sort.Strings(env)
	var names []string
	for _, e := range env {
		names = append(names, strings.SplitN(e, "=", 2)[0])
	}
	fmt.Printf("ENV_NAMES=%s\n", strings.Join(names, ","))
	fmt.Printf("BODY_BYTES=%d\n", n)
	if ms, err := strconv.Atoi(q.Get("after")); err == nil {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}
