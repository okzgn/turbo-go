//go:build linux

package customNetHttp

// S14 (review of 57cbb3c): the leader of a CGI's process group was reaped as
// soon as it ended, and its PID, which is the group's ID, could be given to
// another process while the group could still be killed (the client went
// away, or the CGI's time ran out, with what it left running): the kill
// reached that process's group. On Linux the leader stays a zombie, keeping
// its PID, until the group is released, and the group is never killed after
// that.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// processState is the state of pid in /proc ("Z" for a zombie), or "" if it
// is gone.
func processState(pid int) string {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func TestS14_LeaderKeptUntilGroupCannotBeKilled(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "/bin/sh", "-c", "exit 0")
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
	pid := cmd.Process.Pid
	done := output.watch(context.Background(), cmd, group)
	deadline := time.Now().Add(5 * time.Second)
	for processState(pid) != "Z" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if state := processState(pid); state != "Z" {
		t.Fatalf("the leader, ended, while its group may still be killed: state %q; expected a zombie, which keeps its PID", state)
	}
	time.Sleep(200 * time.Millisecond)
	if state := processState(pid); state != "Z" {
		t.Errorf("the leader was reaped before the group was released: state %q", state)
	}
	output.stop()
	<-done
	for processState(pid) != "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if state := processState(pid); state != "" {
		t.Errorf("the group released: the leader is still there (state %q); expected it reaped", state)
	}
	if err := group.signal(pid); !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("killing a released group: %v; expected nothing sent", err)
	}
}
