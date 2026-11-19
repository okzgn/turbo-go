//go:build !windows

package server

import (
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

// V2.5 review E-13: a FIFO in the public folder of a site is never opened: opening it waited for a writer, and held a
// thread of the server, for as long as the client waited, for each request. It is answered 404, as a name that isn't a
// file nor a folder; so is one of its precompressed variants.
func TestV25R_E13_AFIFOIsNeverOpened(t *testing.T) {
	dir := initForTest(t)
	if err := syscall.Mkfifo(dir+"localhost/@/pipe.html", 0644); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	os.WriteFile(dir+"localhost/@/page.html", []byte("the page"), 0644)
	if err := syscall.Mkfifo(dir+"localhost/@/page.html.gz", 0644); err != nil {
		t.Fatal(err)
	}
	globalMutex.Lock()
	subdomainContentCheckers["!"](true, map[string]interface{}{"Z": "1"}, false, "localhost", "")
	globalMutex.Unlock()
	base := startServer(t)
	start := time.Now()
	if code, _, err := get(base, "/pipe.html", nil); err != nil || code != 404 || time.Since(start) > 2*time.Second {
		t.Errorf("a FIFO: %d (%v) after %v; expected 404 at once", code, err, time.Since(start))
	}
	request, _ := http.NewRequest("GET", base+"/page.html", nil)
	request.Host = "localhost"
	request.Header.Set("Accept-Encoding", "gzip")
	start = time.Now()
	response, err := (&http.Transport{DisableCompression: true}).RoundTrip(request)
	if err != nil || response.StatusCode != 200 || response.Header.Get("Content-Encoding") != "" || time.Since(start) > 2*time.Second {
		t.Errorf("a file whose .gz variant is a FIFO: %v %v after %v; expected the file itself at once", response, err, time.Since(start))
	}
	if response != nil {
		response.Body.Close()
	}
}
