package main

// T14 (N13, N26, N35, N36, I12): the per-IP limiter allows exactly CII
// requests per CIS window, doesn't grow without a cap and doesn't depend on
// the wall clock.

import (
	"strconv"
	"testing"
	"time"
)

// limits sets CIS (ms) and CII directly, as they are after loading the configuration.
func limits(cisMillis, cii int64) {
	serverRequestLimits.CIS.Store(cisMillis * int64(time.Millisecond))
	serverRequestLimits.CII.Store(cii)
}

// N35: exactly CII requests in the first window get through; the next one doesn't.
func TestN35_ExactlyCIIPerWindow(t *testing.T) {
	initForTest(t)
	limits(1000, 100)
	for i := 1; i <= 100; i++ {
		if perIPNotAvailable("198.51.100.40", true) {
			t.Fatalf("request %d of 100 blocked", i)
		}
	}
	if !perIPNotAvailable("198.51.100.40", true) {
		t.Error("request 101 of the first window was not blocked")
	}
}

// N35: with CII=1, the first request from an IP gets through and the second one
// in the same window is blocked.
func TestN35_CIIOne(t *testing.T) {
	initForTest(t)
	limits(50, 1)
	if perIPNotAvailable("198.51.100.41", true) {
		t.Fatal("the first request with CII=1 was blocked")
	}
	if !perIPNotAvailable("198.51.100.41", true) {
		t.Error("the second request in the same window with CII=1 was not blocked")
	}
}

// N13: with the cap on entries reached, new IPs share one entry, limited as a
// single client; the memory doesn't grow, and a known IP keeps its own count.
func TestN13_IPReferencesCapped(t *testing.T) {
	initForTest(t)
	limits(1000, 100)
	previous := ipReferenceLimit
	ipReferenceLimit = 100
	t.Cleanup(func() { ipReferenceLimit = previous })
	if perIPNotAvailable("198.51.100.50", true) {
		t.Fatal("the known IP was blocked on its first request")
	}
	blocked := 0
	for i := 0; i < 1000; i++ {
		if perIPNotAvailable("2001:db8:50::"+strconv.FormatInt(int64(i), 16), true) {
			blocked++
		}
	}
	count := 0
	ipReferences.Range(func(_, _ any) bool { count++; return true })
	if count > 101 {
		t.Errorf("%d entries with a cap of 100", count)
	}
	if blocked == 0 {
		t.Error("the new IPs above the cap don't share the limit")
	}
	if perIPNotAvailable("198.51.100.50", true) {
		t.Error("the known IP was blocked because of the overflow")
	}
}

// N36: if the clock goes back, nobody is left blocked.
func TestN36_ClockBackwards(t *testing.T) {
	initForTest(t)
	limits(1000, 10)
	clock := int64(100 * time.Second)
	previous := monotonicNow
	monotonicNow = func() int64 { return clock }
	t.Cleanup(func() { monotonicNow = previous })
	for i := 0; i < 10; i++ {
		if perIPNotAvailable("198.51.100.51", true) {
			t.Fatalf("request %d blocked", i+1)
		}
	}
	clock -= int64(5 * time.Second)
	for i := 0; i < 5; i++ {
		if perIPNotAvailable("198.51.100.51", true) {
			t.Fatalf("request %d blocked after the clock went back", i+1)
		}
	}
}

// BenchmarkPerIPLimiter measures a request from an IP already known and one from a new IP.
func BenchmarkPerIPLimiter(b *testing.B) {
	initForTest(b)
	limits(50000, 50000)
	b.Run("known", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				perIPNotAvailable("198.51.100.52", true)
			}
		})
	})
	b.Run("new", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			perIPNotAvailable("2001:db8:52::"+strconv.Itoa(i), true)
		}
	})
}

// N13, N26 (D21 (a)): IPv6 addresses count by their /64, in the per-IP limiter
// and in the login one; IPv4 addresses (also when written as ::ffff:a.b.c.d),
// by address.
func TestN13_IPv6LimitedBy64(t *testing.T) {
	initForTest(t)
	limits(50000, 100)
	blocked := 0
	for i := 1; i <= 1000; i++ {
		if perIPNotAvailable("2001:db8:1:2::"+strconv.FormatInt(int64(i), 16), true) {
			blocked++
		}
	}
	if blocked != 900 {
		t.Errorf("1 000 addresses of the same /64: %d blocked; expected 900 (they count as one, with CII=100)", blocked)
	}
	if perIPNotAvailable("2001:db8:1:3::1", true) {
		t.Error("another /64 blocked")
	}
	for i := 1; i <= 100; i++ {
		perIPNotAvailable("192.0.2.7", true)
	}
	if !perIPNotAvailable("::ffff:192.0.2.7", true) {
		t.Error("::ffff:192.0.2.7 doesn't count as 192.0.2.7")
	}
	if perIPNotAvailable("192.0.2.8", true) {
		t.Error("another IPv4 blocked")
	}
}

func TestN26_LoginFailuresIPv6By64(t *testing.T) {
	initForTest(t)
	for i := 1; i <= 5; i++ {
		ip := "2001:db8:5:6::" + strconv.Itoa(i)
		attempt, retry := startLoginAttempt(ip)
		if retry > 0 {
			t.Fatalf("attempt %d blocked", i)
		}
		finishLoginAttempt(attempt, true)
	}
	if _, retry := startLoginAttempt("2001:db8:5:6::99"); retry == 0 {
		t.Error("after 5 failures from the same /64, another of its addresses is not blocked")
	}
	if _, retry := startLoginAttempt("2001:db8:5:7::1"); retry != 0 {
		t.Error("another /64 blocked")
	}
}
