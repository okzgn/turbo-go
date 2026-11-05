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

package customNetHttp

// The leader of a CGI's process group on Linux (turbo:P12, see 0.turbo.cgi.go
// and 0.turbo.cgi_unix.go).

import (
	"os/exec"
	"syscall"
	"unsafe"
)

// turboCGIKeepsLeader: the leader of a CGI's group stays a zombie until the
// group is released (turboCGIWaitExit), and is reaped then.
const turboCGIKeepsLeader = true

// waitid's arguments, which syscall doesn't name.
const (
	turboPidType = 1          // P_PID
	turboWExited = 0x4        // WEXITED
	turboWNoWait = 0x01000000 // WNOWAIT
	turboSiginfo = 128        // sizeof(siginfo_t)
)

// turboCGIWaitExit waits for the leader of a CGI's group to end without
// reaping it (waitid with WNOWAIT). The leader's PID is the group's ID: once
// reaped, the system may give it to another process, and a kill of the group
// that came after (the client went away, or the CGI's time ran out, with the
// processes it left still running) reached that process's group instead. As a
// zombie it keeps its PID until release reaps it, when nothing kills the
// group any more.
func turboCGIWaitExit(cmd *exec.Cmd) {
	var info [turboSiginfo]byte
	for {
		// #nosec G103 -- waitid writes a siginfo_t into info, which outlives the call
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, turboPidType, uintptr(cmd.Process.Pid), uintptr(unsafe.Pointer(&info[0])), turboWExited|turboWNoWait, 0, 0)
		if errno != syscall.EINTR {
			return // Ended, or it can't be waited for this way: release's cmd.Wait says why
		}
	}
}
