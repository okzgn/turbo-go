package main

// V7 (production review of 775a809): turbo.config is known by a stamp (kind, date and size), whose zero value means
// "read it": a file dated at the Unix epoch was taken for one already read, and never applied at start.

import (
	"os"
	"testing"
	"time"
)

func TestRP2_V7_EpochDatedConfigRead(t *testing.T) {
	// 0, 1 and 2 ns were the markers of "never read", "missing" and "can't be looked at".
	for _, nanoseconds := range []int64{0, 1, 2} {
		dir := initForTest(t)
		date := time.Unix(0, nanoseconds)
		write := func(user string) {
			t.Helper()
			if err := os.WriteFile(dir+"turbo.config", []byte(`{"^":{"v":"2"},".":{"U":"`+user+`"}}`), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(dir+"turbo.config", date, date); err != nil {
				t.Fatal(err)
			}
		}
		write("epoch")
		resetTestState(dir) // As a start
		if err := updateSettings(false); err != nil {
			t.Fatalf("%d ns: start: %v", nanoseconds, err)
		}
		if user := panelUser.Get(); user != "epoch" {
			t.Fatalf("%d ns: a turbo.config dated at the Unix epoch isn't read at start: user %q", nanoseconds, user)
		}
		// Rewritten with the same date and another size: read again.
		write("epoch-rewritten")
		if err := updateSettings(true); err != nil {
			t.Fatalf("%d ns: reload: %v", nanoseconds, err)
		}
		if user := panelUser.Get(); user != "epoch-rewritten" {
			t.Errorf("%d ns: a turbo.config rewritten with the same date isn't read again: user %q", nanoseconds, user)
		}
	}
}

// The stamp of a missing file, of an unreadable path and of a file differ, and only the zero value always reads.
func TestRP2_V7_StampKinds(t *testing.T) {
	dir := t.TempDir() + "/"
	missing := configStampOf(dir + "turbo.config")
	if missing.kind != stampMissing {
		t.Fatalf("missing: %+v", missing)
	}
	if err := os.WriteFile(dir+"turbo.config", []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	file := configStampOf(dir + "turbo.config")
	if file.kind != stampFile || file.size != 2 {
		t.Fatalf("file: %+v", file)
	}
	if file.changedSince(file) || missing.changedSince(missing) {
		t.Error("an unchanged stamp counts as changed")
	}
	if !file.changedSince(missing) || !missing.changedSince(file) {
		t.Error("a file that appears or disappears doesn't count as changed")
	}
	if !file.changedSince(configStamp{}) || !missing.changedSince(configStamp{}) {
		t.Error("after the zero stamp, the file isn't read")
	}
}
