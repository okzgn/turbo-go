//go:build linux

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

package main

import (
	"errors"
	"log/slog"
	"syscall"
	"unsafe"
)

// prCapAmbient and prCapAmbientClearAll are PR_CAP_AMBIENT and PR_CAP_AMBIENT_CLEAR_ALL of prctl(2).
const (
	prCapAmbient         = 47
	prCapAmbientClearAll = 4
)

// capabilityHeader and capabilityData are the structures of capget(2) and capset(2), version 3 (two data
// structures: capabilities 0-31 and 32-63).
type capabilityHeader struct {
	version uint32
	pid     int32
}

type capabilityData struct {
	effective, permitted, inheritable uint32
}

const linuxCapabilityVersion3 = 0x20080522

// clearInheritedCapabilities empties the ambient and inheritable capabilities of every thread of Turbo, so that
// the programs it runs (CGIs, Certbot) don't inherit CAP_NET_BIND_SERVICE from a systemd unit with
// AmbientCapabilities: neither at once (ambient) nor by running a program whose file marks it as inheritable.
// Turbo keeps it in its effective set, enough to open :443 later. Capabilities are per thread, hence
// AllThreadsSyscall, which a binary built with cgo can't use: then it is only logged.
func clearInheritedCapabilities() {
	_, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClearAll, 0)
	if errno == 0 {
		errno = clearInheritableCapabilities()
	}
	if errno == 0 {
		return
	}
	if errors.Is(errno, syscall.ENOTSUP) {
		slog.Warn("Can't clear the capabilities the CGIs inherit (binary built with cgo): the CGIs inherit Turbo's")
		return
	}
	slog.Warn("Can't clear the capabilities the CGIs inherit: the CGIs inherit Turbo's", "error", errno)
}

// clearInheritableCapabilities empties the inheritable set of every thread, keeping the effective and permitted
// ones.
func clearInheritableCapabilities() syscall.Errno {
	header := capabilityHeader{version: linuxCapabilityVersion3}
	var data [2]capabilityData
	// #nosec G103 -- capget and capset take these structures by address (capabilities(7))
	if _, _, errno := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return errno
	}
	if data[0].inheritable == 0 && data[1].inheritable == 0 {
		return 0
	}
	data[0].inheritable, data[1].inheritable = 0, 0
	header.pid = 0 // Each thread, itself
	// #nosec G103 -- as above
	_, _, errno := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0)
	return errno
}
