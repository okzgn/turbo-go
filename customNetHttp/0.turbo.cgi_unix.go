//go:build unix

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

// The process group of a CGI on Unix (turbo:P12, see 0.turbo.cgi.go).

import (
	"os/exec"
	"sync/atomic"
	"syscall"
)

// turboCGIGroup is a CGI's own process group: the process leads it and the
// ones it leaves running inherit it.
type turboCGIGroup struct {
	pid atomic.Int64
}

// turboCGIPrepare prepares cmd to go in a process group of its own, which
// cmd.Cancel (when the context expires) kills whole.
func turboCGIPrepare(cmd *exec.Cmd) *turboCGIGroup {
	group := &turboCGIGroup{}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error { // cmd.Process already exists when exec calls it
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return group
}

// started records the process, already started, which is the one that names the group.
func (g *turboCGIGroup) started(cmd *exec.Cmd) {
	g.pid.Store(int64(cmd.Process.Pid))
}

// kill kills the whole group.
func (g *turboCGIGroup) kill() {
	if pid := int(g.pid.Load()); pid > 0 {
		syscall.Kill(-pid, syscall.SIGKILL)
	}
}

// release does nothing on Unix: the group holds nothing.
func (g *turboCGIGroup) release() {}
