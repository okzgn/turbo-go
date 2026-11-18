package main

// Review of 6046dbe (R6), O-5: the address of a client is read once per request for its IP and for its key in the
// limiter. Before, it was written as text and read again: three times per request.

import (
	"testing"
)

var clientAddresses = []string{
	"203.0.113.7:40000", "[::ffff:203.0.113.7]:40000", "[2001:DB8:1:2:3:4:5:6]:443", "[fe80::1%eth0]:80", "[::1]:80", "::1", "[::1]",
	"203.0.113.7", "2001:db8::1", "::ffff:1.2.3.4", "localhost:80", "1.2.3.4:99999", "[::FFFF:1.2.3.4]:99999", "[2001:DB8::1]:99999",
	"", "garbage", ":80", "[", "1.2.3.4:", "0.0.0.0:0", "[::]:0",
}

// R6 O-5: clientOf gives what ipAddr and limiterKey gave one after the other, for the addresses of a connection and
// for what isn't one.
func TestR6_O5_ClientOf(t *testing.T) {
	for address, expected := range map[string]clientAddress{
		"203.0.113.7:40000":          {"203.0.113.7", "203.0.113.7"},
		"[::ffff:203.0.113.7]:40000": {"203.0.113.7", "203.0.113.7"},
		"[2001:DB8:1:2:3:4:5:6]:443": {"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		"[fe80::1%eth0]:80":          {"fe80::1", "fe80::/64"},
		"[::1]:80":                   {"::1", "::/64"},
		"localhost:80":               {"localhost", "localhost"},
		"[::FFFF:1.2.3.4]:99999":     {"::FFFF:1.2.3.4", "1.2.3.4"}, // Not an address: its host as written, and the key of that
	} {
		if client := clientOf(address); client != expected {
			t.Errorf("clientOf(%q) = %+v; expected %+v", address, client, expected)
		}
	}
	for _, address := range clientAddresses {
		ip := ipAddr(address)
		if client, expected := clientOf(address), (clientAddress{ip, limiterKey(ip)}); client != expected {
			t.Errorf("clientOf(%q) = %+v; ipAddr and limiterKey give %+v", address, client, expected)
		}
	}
}

// R6 O-5: the limits of a request within them cost one text for an IPv4 client, its IP, and two for an IPv6 one,
// its IP and its /64.
func TestR6_O5_LimitsReadTheAddressOnce(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates on its own")
	}
	initForTest(t)
	serverRequestLimits.CII.Store(1 << 40)
	for remote, limit := range map[string]float64{"203.0.113.7:40000": 1, "[2001:db8:1:2:3:4:5:6]:40000": 2} {
		rateLimited(clientOf(remote)) // Its entry in the limiter, made
		if allocations := testing.AllocsPerRun(200, func() { rateLimited(clientOf(remote)) }); allocations > limit {
			t.Errorf("the limits of a request from %s: %.0f allocations; expected %.0f", remote, allocations, limit)
		}
	}
}

// R6 O-5: for any text, clientOf is ipAddr and limiterKey of it.
func FuzzClientAddress(f *testing.F) {
	for _, address := range clientAddresses {
		f.Add(address)
	}
	f.Fuzz(func(t *testing.T, address string) {
		ip := ipAddr(address)
		if client, expected := clientOf(address), (clientAddress{ip, limiterKey(ip)}); client != expected {
			t.Fatalf("clientOf(%q) = %+v; ipAddr and limiterKey give %+v", address, client, expected)
		}
	})
}
