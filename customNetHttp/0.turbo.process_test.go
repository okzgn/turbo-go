package customNetHttp

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// A process that Turbo keeps (TurboStartProcess) ends with what it started: killed while it runs, or released once
// it has ended by itself, the child it left running never gets to write its mark.
func TestTurboProcessEndsWithWhatItStarted(t *testing.T) {
	switch os.Getenv("TURBO_PROCESS_HELPER") {
	case "keeps", "leaves": // Starts a child, records it, and then runs on (keeps) or ends (leaves)
		child := exec.Command(os.Args[0], "-test.run=^TestTurboProcessEndsWithWhatItStarted$")
		child.Env = append(os.Environ(), "TURBO_PROCESS_HELPER=child")
		if child.Start() == nil {
			os.WriteFile(os.Getenv("TURBO_PROCESS_READY"), nil, 0o644)
		}
		if os.Getenv("TURBO_PROCESS_HELPER") == "keeps" {
			time.Sleep(30 * time.Second)
		}
		os.Exit(0)
	case "child":
		time.Sleep(2 * time.Second)
		os.WriteFile(os.Getenv("TURBO_PROCESS_MARK"), nil, 0o644)
		os.Exit(0)
	}
	for _, helper := range []string{"keeps", "leaves"} {
		t.Run(helper, func(t *testing.T) {
			dir := t.TempDir()
			mark, ready := filepath.Join(dir, "mark"), filepath.Join(dir, "ready")
			cmd := exec.Command(os.Args[0], "-test.run=^TestTurboProcessEndsWithWhatItStarted$")
			cmd.Env = append(os.Environ(), "TURBO_PROCESS_HELPER="+helper, "TURBO_PROCESS_MARK="+mark, "TURBO_PROCESS_READY="+ready)
			process, err := TurboStartProcess(cmd)
			if err != nil {
				t.Fatal(err)
			}
			for start := time.Now(); time.Since(start) < 10*time.Second; time.Sleep(20 * time.Millisecond) {
				if _, err := os.Stat(ready); err == nil {
					break
				}
			}
			if helper == "keeps" {
				process.Kill()
			}
			select {
			case <-process.Exited():
			case <-time.After(10 * time.Second):
				t.Fatal("the process didn't end")
			}
			process.Release()
			time.Sleep(2500 * time.Millisecond)
			if _, err := os.Stat(mark); err == nil {
				t.Error("the child it left kept running")
			}
			process.Kill() // Already released: nothing to reach, and no other process's group
		})
	}
}
