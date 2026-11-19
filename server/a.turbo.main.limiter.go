/*
Turbo - A cross-platform, high-performance HTTP web server with a real-time, visual management interface. Manage unlimited domains and multi-level wildcard subdomains, SSL certificates, URI rewrites, request preprocessing, fine-grained request rate and size limiting, as well as custom aliases, headers, MIMEs, and indexes.
Copyright (C) 2026 OKZGN

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please visit one of the following:
- https://okzgn.com/#contact
- https://okzgn.github.io/#contact
*/

package server

// The limits of the requests: those of each client (its IP, or the /64 of an IPv6 one), with the entries that count
// them and the networks that share one when there are too many, and the one of the whole server.

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"turbo/customNetHttp"
)

// connHandler closes new connections from an IP that is already blocked. Requests are counted, and
// answered with 429, in the handler (rateLimited).
func connHandler(conn net.Conn, connState customNetHttp.ConnState) {
	if connState != customNetHttp.StateNew {
		return
	}

	if blocked, _ := ipBlocked(clientOf(conn.RemoteAddr().String())); blocked {
		_ = conn.Close() // Refused: whatever happens to the connection doesn't matter
	}
}

// ipBlocked reports whether the client is denied or blocked by the limiter, and the seconds left, without
// counting a request.
func ipBlocked(client clientAddress) (bool, int64) {
	nowUnix := time.Now().Unix() // Denials are dates, saved in turbo.config
	if until := deniedUntil(client); until > nowUnix {
		return true, until - nowUnix
	}
	ipRef, found := ipReferences.Load(client.key)
	if !found {
		return false, 0
	}
	ipData := ipRef.(*IPReference)
	ipData.mutex.Lock()
	defer ipData.mutex.Unlock()
	if left := ipData.blockedUntil - monotonicNow(); left > 0 {
		return true, (left + int64(time.Second) - 1) / int64(time.Second)
	}
	return false, 0
}

// rateLimited counts a request of the client in the per-IP and global limiters. When the request must be
// rejected, it returns the status (429 for the IP, 503 for the whole server) and the seconds to send in
// Retry-After; otherwise status is 0.
func rateLimited(client clientAddress) (status int, retryAfter int64) {
	if rejected, retryAfter := perIPRejected(client, true); rejected {
		return 429, retryAfter
	}
	if globalRateExceeded() {
		return 503, 1
	}
	return 0, 0
}

// The limiters measure time with the monotonic clock, from the start of the process: moving the wall clock back
// (NTP, a restored virtual machine) neither blocks the clients nor stretches the windows. Denied IPs, saved as
// dates, keep the wall clock.
var (
	processStart = time.Now()
	monotonicNow = func() int64 { return int64(time.Since(processStart)) } // Nanoseconds; a variable so that tests can move it
)

// monotonicSecond is the second of the monotonic clock, aligned with the seconds of the wall clock at start.
func monotonicSecond() int64 {
	return (monotonicNow() + int64(processStart.Nanosecond())) / int64(time.Second)
}

// globalRateExceeded counts a request for the whole server and reports whether it goes over CGL in the current
// second. It doesn't blame any IP and takes no lock: a request that starts a new second resets the count.
// The windows are fixed seconds, so a burst across two of them can reach twice CGL; sharing the server among
// clients is what CII and CIS do.
func globalRateExceeded() bool {
	return globalRateExceededAt(monotonicSecond())
}

// globalRateExceededAt is globalRateExceeded for a request that read the time now. The second and its count
// change together, and only forwards: a request that read the previous second counts in the current one.
func globalRateExceededAt(now int64) bool {
	limit := globalRequestLimit.Load()
	if limit == 0 {
		return false
	}
	for {
		window := globalRequestWindow.Load()
		second, count := int64(window>>32), int64(window&0xffffffff)
		next := uint64(now)<<32 | 1 // #nosec G115 -- seconds since the process started: positive, and below 2^32 for 136 years
		if now <= second {
			if count > limit { // Already over: nothing to count, and the count can't overflow
				return true
			}
			next = window + 1
		}
		if globalRequestWindow.CompareAndSwap(window, next) {
			return int64(next&0xffffffff) > limit
		}
	}
}

// requestLimits are the per-IP limits of the panel: CIL (how long an IP's count lasts) and CIS (the window of
// CII requests) in nanoseconds, and CII in requests. The panel changes them while requests read them, so they are
// atomic; they start with the defaults of turbo.config.
type requestLimits struct{ CIL, CIS, CII atomic.Int64 }

func init() {
	serverRequestLimits.CIL.Store(10 * int64(time.Second))
	serverRequestLimits.CIS.Store(int64(time.Second))
	serverRequestLimits.CII.Store(100)
}

// The limiter keeps an entry per client (limiterKey) for about CIL after its last window, some 200 bytes each.
// ipReferenceLimit bounds them: beyond it, a new client shares the entry of its network, an IPv4 /24 or an IPv6 /48,
// while there are fewer than an eighth of ipReferenceLimit of those; then that of a wider one, a /16 or a /32, up to
// a sixty-fourth; and only then the one entry of every other client (overflowIPKey). Every new client went to that
// last one at once, and a flood of new addresses kept it blocked for every new visitor; now a flood fills the
// entries of its own networks first. The clients already known keep theirs. ipReferenceCounts are the entries of
// each level (limiterLevels). ipReferenceLimit is a variable so that tests can lower it.
var (
	ipReferenceLimit  int64 = 200000
	ipReferenceCounts [limiterLevels]atomic.Int64
)

// limiterLevels are the levels of the limiter's entries: a client's own (0), its network's (1 and 2, wider) and the
// one of every other client (3).
const limiterLevels = 4

const overflowIPKey = "" // No IP has this key

// limiterLevelCap is how many entries level 0, 1 or 2 may have: ipReferenceLimit, an eighth and a sixty-fourth.
func limiterLevelCap(level int) int64 {
	return max(1, ipReferenceLimit>>(3*level))
}

// limiterNetworkKey is the key of the network of a client's key (limiterKey) at level 1 (an IPv4 /24 or an IPv6 /48)
// or 2 (a /16 or a /32): a prefix, which no client's key is. overflowIPKey for the last level, or a key that isn't an
// address.
func limiterNetworkKey(client string, level int) string {
	if level >= limiterLevels-1 {
		return overflowIPKey
	}
	address, err := netip.ParseAddr(client)
	if prefix, prefixErr := netip.ParsePrefix(client); prefixErr == nil { // An IPv6 client: its /64
		address, err = prefix.Addr(), nil
	}
	if err != nil {
		return overflowIPKey
	}
	bits := [...]int{0, 24, 16}[level]
	if address.Is6() {
		bits = [...]int{0, 48, 32}[level]
	}
	network, _ := address.Prefix(bits)
	return network.String()
}

// limiterKey is the key of an IP in the per-IP limiter and the failed-login limit: an IPv4 address on its own
// (also written as ::ffff:a.b.c.d), and an IPv6 address by its /64, the block a client usually gets, so that a
// client can't get a new quota from each address of it.
func limiterKey(ip string) string {
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	address = address.Unmap().WithZone("")
	if address.Is4() {
		return address.String()
	}
	prefix, _ := address.Prefix(64)
	return prefix.String()
}

// limiterReference returns the limiter entry of key, a client's (limiterKey): its own, made if its level has room, or
// else the entry of its network or the shared one (ipReferenceLimit).
func limiterReference(key string) *IPReference {
	if ipRef, found := ipReferences.Load(key); found { // Most requests: no entry to allocate
		return ipRef.(*IPReference)
	}
	client, level := key, 0
	for level < limiterLevels-1 && ipReferenceCounts[level].Load() >= limiterLevelCap(level) {
		level++
		if key = limiterNetworkKey(client, level); key == overflowIPKey {
			level = limiterLevels - 1
		}
		if ipRef, found := ipReferences.Load(key); found {
			return ipRef.(*IPReference)
		}
	}
	ipRef, loaded := ipReferences.LoadOrStore(key, &IPReference{windowStart: monotonicNow(), level: level})
	if !loaded {
		ipReferenceCounts[level].Add(1)
	}
	return ipRef.(*IPReference)
}

// cleanIPReferences forgets the IPs whose counting window ended more than CIL ago and that aren't blocked:
// their next request would start from zero anyway.
func cleanIPReferences() {
	now := monotonicNow()
	intervalLimit := serverRequestLimits.CIL.Load()
	ipReferences.Range(func(ip, ipRef any) bool {
		ipData := ipRef.(*IPReference)
		ipData.mutex.Lock()
		idle := now-ipData.windowStart > intervalLimit && ipData.blockedUntil <= now
		ipData.mutex.Unlock()
		if idle && ipReferences.CompareAndDelete(ip, ipRef) {
			ipReferenceCounts[ipData.level].Add(-1)
		}
		return true
	})
}

// perIPNotAvailable counts a request of the client (if incrementCounter) and reports whether it must be rejected:
// its IP is denied, it is blocked, or it goes over CII requests per CIS window, counted from the start of its
// count (which restarts after CIL): with t elapsed, CII × (⌊t/CIS⌋ + 1) requests are allowed, the current one
// included. Going over blocks the client for 5 seconds.
func perIPNotAvailable(client clientAddress, incrementCounter bool) bool {
	rejected, _ := perIPRejected(client, incrementCounter)
	return rejected
}

// perIPRejected is perIPNotAvailable with the seconds left of the block that rejects the request (of the entry
// counted, shared or not); the line of turbo.denials is written once the entry is unlocked.
func perIPRejected(client clientAddress, incrementCounter bool) (bool, int64) {
	nowUnix := time.Now().Unix()
	if until := deniedUntil(client); until > nowUnix { // Without the global lock, like the rest of the limiter
		return true, until - nowUnix
	}

	ipData := limiterReference(client.key)
	ipData.mutex.Lock()
	rejected, left, newBlock := ipData.countLocked(incrementCounter)
	ipData.mutex.Unlock()
	if newBlock {
		serverWriteLogs(denialsLogName, nil, 0, client.ip+" conn denial")
	}
	return rejected, (left + int64(time.Second) - 1) / int64(time.Second)
}

// countLocked counts a request in the entry. Callers hold its mutex.
func (ipData *IPReference) countLocked(incrementCounter bool) (rejected bool, left int64, newBlock bool) {
	now := monotonicNow()
	if ipData.blockedUntil > now {
		return true, ipData.blockedUntil - now, false
	}
	if incrementCounter {
		ipData.requestCount++
	}

	intervalLimit := serverRequestLimits.CIL.Load()
	windowLimit := serverRequestLimits.CIS.Load()
	maxRequests := serverRequestLimits.CII.Load()

	timeDiff := now - ipData.windowStart
	if timeDiff > intervalLimit || timeDiff < 0 { // A new count (a test clock may go back)
		ipData.windowStart, timeDiff = now, 0
		ipData.requestCount = 0
		if incrementCounter {
			ipData.requestCount = 1
		}
	}
	if windowLimit == 0 || maxRequests == 0 {
		return false, 0, false
	}
	if ipData.requestCount > maxRequests*(timeDiff/windowLimit+1) {
		ipData.blockedUntil = now + 5*int64(time.Second)
		return true, 5 * int64(time.Second), true
	}
	return false, 0, false
}

// IPReference is the limiter entry of an IP. Times are of the monotonic clock (monotonicNow).
type IPReference struct {
	mutex        sync.Mutex
	blockedUntil int64 // Blocked until then
	windowStart  int64 // Start of the current count
	requestCount int64 // Requests counted since windowStart
	level        int   // Its level (limiterLevels), fixed when it is made
}
