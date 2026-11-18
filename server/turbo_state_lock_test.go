package server

// Review of 6046dbe (R6), O-2: the global lock counts its write locks, so that what is derived from the shared state
// knows when to be derived again without anyone telling it.

import (
	"sync"
	"testing"
)

// R6 O-2: the generation of the lock is odd while it is write-locked, however it was locked, and another even one
// after each write lock, also one released by a defer after a panic; read locks and a TryLock that fails leave it.
func TestR6_O2_StateLockCountsWriteLocks(t *testing.T) {
	var lock stateLock
	expect := func(step string, generation uint64) {
		t.Helper()
		if got := lock.generation.Load(); got != generation {
			t.Fatalf("%s: generation %d; expected %d", step, got, generation)
		}
	}
	expect("at the start", 0)
	lock.Lock()
	expect("write-locked", 1)
	lock.Unlock()
	expect("after a write lock", 2)
	lock.RLock()
	lock.RLock()
	expect("read-locked", 2)
	if lock.TryLock() {
		t.Fatal("TryLock got the lock while it was read-locked")
	}
	expect("after a TryLock that failed", 2)
	lock.RUnlock()
	lock.RUnlock()
	if !lock.TryLock() {
		t.Fatal("TryLock didn't get a free lock")
	}
	expect("write-locked with TryLock", 3)
	lock.Unlock()
	expect("after it", 4)
	func() {
		defer func() { recover() }()
		lock.Lock()
		defer lock.Unlock()
		panic("while write-locked")
	}()
	expect("after a panic while write-locked", 6)
	var locker sync.Locker = &lock // As anything that takes a lock gets it
	locker.Lock()
	expect("write-locked as a sync.Locker", 7)
	locker.Unlock()
	expect("after it", 8)
}

// R6 O-2: everything that changes the shared state of Turbo goes through that count.
func TestR6_O2_GlobalLockCountsItsWriters(t *testing.T) {
	initForTest(t)
	for name, write := range map[string]func(){
		"withGlobalLock": func() { withGlobalLock(func() {}) },
		"lockedCheck":    func() { lockedCheck(func() (bool, string) { return true, "" }) },
		"a reload":       func() { updateSettings(false) },
		"a site added":   func() { addSiteFromPanel("counted.test", "") },
		"cleanOldValues": func() { cleanOldValues(&signedInTokens) },
	} {
		before := globalMutex.generation.Load()
		write()
		if after := globalMutex.generation.Load(); after == before || after&1 == 1 || before&1 == 1 {
			t.Errorf("%s: generation %d, then %d; expected another even one", name, before, after)
		}
	}
	before := globalMutex.generation.Load()
	withReadLock(func() {})
	if after := globalMutex.generation.Load(); after != before {
		t.Errorf("a read lock: generation %d, then %d", before, after)
	}
}
