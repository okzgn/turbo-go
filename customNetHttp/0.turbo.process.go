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

// A process that Turbo keeps running for its preprocessors (the worker of a mode), in a group of its own as a CGI is
// (0.turbo.cgi_unix.go, 0.turbo.cgi_windows.go): killing it ends whatever it started too, and on Windows the end of
// Turbo, however it ends, ends it (the Job Object closes with Turbo).

import "os/exec"

// TurboProcess is a process of a preprocessor that Turbo keeps running, in its own process group (a Job Object on
// Windows).
type TurboProcess struct {
	cmd    *exec.Cmd
	group  *turboCGIGroup
	exited chan struct{}
}

// TurboStartProcess starts cmd in a group of its own. cmd isn't one of exec.CommandContext: Kill ends it. Its input
// and output are best *os.File (pipes made by the caller), which exec hands over without goroutines of its own.
func TurboStartProcess(cmd *exec.Cmd) (*TurboProcess, error) {
	group := turboCGIPrepare(cmd)
	cmd.Cancel = nil // For a command of CommandContext, which this one isn't
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	group.started(cmd)
	process := &TurboProcess{cmd: cmd, group: group, exited: make(chan struct{})}
	go func() {
		group.wait(cmd) // On Linux without reaping the leader, which keeps the group's ID until Release
		group.exited()  // Elsewhere the group is killed now, while its ID can't be another's yet, and never again
		close(process.exited)
	}()
	return process, nil
}

// TurboInheritedEnvironment is what the CGI host gives a CGI of Turbo's environment besides the PATH and what
// InheritEnv names: what the system needs to run a program. A worker of a mode gets the same.
func TurboInheritedEnvironment() []string { return append([]string(nil), osDefaultInheritEnv...) }

// Pid is the process's ID.
func (p *TurboProcess) Pid() int { return p.cmd.Process.Pid }

// Exited is closed once the process has ended. What it started may still run, until Release.
func (p *TurboProcess) Exited() <-chan struct{} { return p.exited }

// Kill kills the process and whatever it started. The process may already have ended.
func (p *TurboProcess) Kill() {
	p.group.kill()
	p.cmd.Process.Kill() // Also where it has no group to kill (Windows, without its Job Object)
}

// Release, once the process has ended, kills what it left running and lets its group go (on Linux, the leader is
// reaped then; outside Linux, that was done when it ended): nothing of it goes on. It waits for the end of the
// process.
func (p *TurboProcess) Release() {
	<-p.exited
	p.group.kill()
	p.group.release(p.cmd)
}
