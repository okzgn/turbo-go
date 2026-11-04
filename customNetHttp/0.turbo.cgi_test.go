package customNetHttp

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// N106 (a): the group of a CGI can be killed until whoever reads its output
// stops reading (stop), also if the CGI has already ended and its output was
// closed: it is what P12 does when the response can't be used. On Windows, the
// Job Object was closed as soon as the output ended, and killing it afterwards
// no longer reached what the CGI left running.
func TestN106_GroupKilledAfterOutputEnds(t *testing.T) {
	switch os.Getenv("TURBO_N106_HELPER") {
	case "cgi": // Leaves a child without its output, records it and ends
		child := exec.Command(os.Args[0], "-test.run=^TestN106_GroupKilledAfterOutputEnds$")
		child.Env = append(os.Environ(), "TURBO_N106_HELPER=child")
		if child.Start() == nil {
			os.WriteFile(os.Getenv("TURBO_N106_READY"), nil, 0o644)
		}
		os.Exit(0)
	case "child":
		time.Sleep(2 * time.Second)
		os.WriteFile(os.Getenv("TURBO_N106_MARK"), nil, 0o644)
		os.Exit(0)
	}
	dir := t.TempDir()
	mark, ready := filepath.Join(dir, "mark"), filepath.Join(dir, "ready")
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestN106_GroupKilledAfterOutputEnds$")
	cmd.Env = append(os.Environ(), "TURBO_N106_HELPER=cgi", "TURBO_N106_MARK="+mark, "TURBO_N106_READY="+ready)
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
	finished := output.watch(context.Background(), cmd, group)
	io.Copy(io.Discard, output) // Until the output closes: the CGI has ended
	for start := time.Now(); time.Since(start) < 10*time.Second; time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
	}
	time.Sleep(200 * time.Millisecond) // watch has already seen the end of the CGI and of its output
	group.kill()                       // The response couldn't be used
	output.stop()
	<-finished
	time.Sleep(2500 * time.Millisecond)
	if _, err := os.Stat(mark); err == nil {
		t.Error("the child the CGI left kept running: killing the group after its output ended didn't reach it")
	}
}
