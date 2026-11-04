//go:build windows

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

// The Job Object of a CGI on Windows (turbo:P12, see 0.turbo.cgi.go), with
// kernel32 directly: without new dependencies.

import (
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

var (
	turboKernel32                 = syscall.NewLazyDLL("kernel32.dll")
	turboCreateJobObject          = turboKernel32.NewProc("CreateJobObjectW")
	turboSetInformationJobObject  = turboKernel32.NewProc("SetInformationJobObject")
	turboAssignProcessToJobObject = turboKernel32.NewProc("AssignProcessToJobObject")
	turboTerminateJobObject       = turboKernel32.NewProc("TerminateJobObject")
)

const (
	turboJobObjectExtendedLimitInformation = 9      // JOBOBJECTINFOCLASS
	turboJobObjectLimitKillOnJobClose      = 0x2000 // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	turboProcessSetQuotaAndTerminate       = 0x0101 // PROCESS_SET_QUOTA | PROCESS_TERMINATE
)

// turboJobLimits is JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
type turboJobLimits struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
	IoCounters              [6]uint64
	ProcessMemoryLimit      uintptr
	JobMemoryLimit          uintptr
	PeakProcessMemoryUsed   uintptr
	PeakJobMemoryUsed       uintptr
}

// turboCGIGroup is the Job Object of a CGI: the process joins it after Start,
// and the ones it leaves running inherit it. While it is open, closing it
// kills them all (KILL_ON_JOB_CLOSE), also if Turbo exits.
type turboCGIGroup struct {
	mutex sync.Mutex
	job   syscall.Handle
}

// turboCGIPrepare prepares cmd to go in a Job Object of its own, which
// cmd.Cancel (when the context expires) kills whole.
func turboCGIPrepare(cmd *exec.Cmd) *turboCGIGroup {
	group := &turboCGIGroup{}
	cmd.Cancel = func() error {
		group.kill()
		return cmd.Process.Kill()
	}
	return group
}

// started creates the Job Object and puts the process, already started, in it.
// If something fails, the CGI goes on without a Job Object, as before.
func (g *turboCGIGroup) started(cmd *exec.Cmd) {
	job, _, _ := turboCreateJobObject.Call(0, 0)
	if job == 0 {
		return
	}
	limits := turboJobLimits{LimitFlags: turboJobObjectLimitKillOnJobClose}
	if ok, _, _ := turboSetInformationJobObject.Call(job, turboJobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits)); ok == 0 {
		syscall.CloseHandle(syscall.Handle(job))
		return
	}
	process, err := syscall.OpenProcess(turboProcessSetQuotaAndTerminate, false, uint32(cmd.Process.Pid))
	if err != nil {
		syscall.CloseHandle(syscall.Handle(job))
		return
	}
	defer syscall.CloseHandle(process)
	if ok, _, _ := turboAssignProcessToJobObject.Call(job, uintptr(process)); ok == 0 {
		syscall.CloseHandle(syscall.Handle(job))
		return
	}
	g.mutex.Lock()
	g.job = syscall.Handle(job)
	g.mutex.Unlock()
}

// kill kills all the processes of the Job Object.
func (g *turboCGIGroup) kill() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if g.job != 0 {
		turboTerminateJobObject.Call(uintptr(g.job), 1)
	}
}

// release closes the Job Object without killing anyone: the processes left by
// a CGI that ended normally go on.
func (g *turboCGIGroup) release() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if g.job == 0 {
		return
	}
	limits := turboJobLimits{}
	turboSetInformationJobObject.Call(uintptr(g.job), turboJobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	syscall.CloseHandle(g.job)
	g.job = 0
}
