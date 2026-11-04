//go:build unix

package customNetHttp

// The end of a CGI's processes (turbo:P12, see 0.turbo.cgi.go) when the
// client leaves after the CGI has ended: what it left in its group is killed
// all the same.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestN81_GroupKilledWhenClientLeavesAfterCGIEnds starts CGIs that leave a
// process in their group, without their output, and end at once. The client
// leaves (the context of watch expires) when the CGI has already ended and exec
// is no longer going to kill it (in P12, if Wait returned first): the first
// select of watch has the context ready, and even so the process it left must
// die before writing its mark.
func TestN81_GroupKilledWhenClientLeavesAfterCGIEnds(t *testing.T) {
	switch os.Getenv("TURBO_N81_HELPER") {
	case "cgi": // Leaves the child in its group, without its output, records it and ends
		child := exec.Command(os.Args[0], "-test.run=^TestN81_GroupKilledWhenClientLeavesAfterCGIEnds$")
		child.Env = append(os.Environ(), "TURBO_N81_HELPER=child")
		if child.Start() == nil {
			os.WriteFile(os.Getenv("TURBO_N81_READY"), nil, 0o644)
		}
		os.Exit(0)
	case "child":
		time.Sleep(2 * time.Second)
		os.WriteFile(os.Getenv("TURBO_N81_MARK"), nil, 0o644)
		os.Exit(0)
	}
	const total = 40
	dir := t.TempDir()
	marks, ready := filepath.Join(dir, "marks"), filepath.Join(dir, "ready")
	os.MkdirAll(marks, 0o755)
	os.MkdirAll(ready, 0o755)
	type cgi struct {
		cmd    *exec.Cmd
		output *turboCGIOutput
		group  *turboCGIGroup
	}
	var cgis []cgi
	for i := 0; i < total; i++ {
		// As P12 does, with CommandContext, but with a context that doesn't expire: exec kills nothing, the CGI ends by itself.
		cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestN81_GroupKilledWhenClientLeavesAfterCGIEnds$")
		cmd.Env = append(os.Environ(), "TURBO_N81_HELPER=cgi", "TURBO_N81_MARK="+filepath.Join(marks, fmt.Sprint(i)), "TURBO_N81_READY="+filepath.Join(ready, fmt.Sprint(i)))
		output, writeEnd, err := turboCGIOutputPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout = writeEnd
		group := turboCGIPrepare(cmd)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		writeEnd.Close()
		group.started(cmd)
		cgis = append(cgis, cgi{cmd, output, group})
	}
	for start := time.Now(); time.Since(start) < 10*time.Second; time.Sleep(20 * time.Millisecond) { // Every CGI left its child
		if entries, _ := os.ReadDir(ready); len(entries) == total {
			break
		}
	}
	time.Sleep(100 * time.Millisecond) // And has ended
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	var wg sync.WaitGroup
	for _, c := range cgis {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-c.output.watch(gone, c.cmd, c.group)
			c.output.stop()
		}()
	}
	wg.Wait()
	time.Sleep(2500 * time.Millisecond)
	if left, _ := os.ReadDir(marks); len(left) > 0 {
		t.Errorf("%d of %d CGIs that had already ended when the client went away left a process that kept running", len(left), total)
	}
}
