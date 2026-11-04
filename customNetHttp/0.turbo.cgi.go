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

// The output of a CGI and the end of its processes (turbo:P12). A process
// the CGI leaves running inherits its output: without this, the request would
// wait for that process to close it. What depends on the system (the process
// group or the Job Object) is in 0.turbo.cgi_unix.go and
// 0.turbo.cgi_windows.go.

import (
	"context"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// turboCGIOutputGrace is how long the output of a CGI that has already ended
// is still read: reading stops after that long without new data.
var turboCGIOutputGrace = time.Second

// turboCGIClockStart is the origin of the turboCGINow clock.
var turboCGIClockStart = time.Now()

// turboCGINow is the current instant on the monotonic clock, in nanoseconds
// since turboCGIClockStart: a change of the system time neither shortens nor
// lengthens the turboCGIOutputGrace wait.
func turboCGINow() int64 { return int64(time.Since(turboCGIClockStart)) }

// turboCGIOutput is the output of a CGI. It is read from the pipe in a
// goroutine of its own, so that reading can stop when the CGI has ended even
// if the pipe is still open.
type turboCGIOutput struct {
	file     *os.File // Read end of the pipe
	chunks   chan []byte
	pending  []byte
	stopped  chan struct{}
	ended    chan struct{} // Closed when the reading goroutine ends
	stopOnce sync.Once
	reading  atomic.Bool  // The goroutine waits for data in Read
	lastData atomic.Int64 // When it started waiting in Read (turboCGINow): after receiving data, or after handing it over
}

// turboCGIOutputPipe creates the pipe of a CGI's output: it returns what reads
// it and the end that goes to the process, which the caller closes after Start.
func turboCGIOutputPipe() (*turboCGIOutput, *os.File, error) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	o := &turboCGIOutput{file: readEnd, chunks: make(chan []byte, 16), stopped: make(chan struct{}), ended: make(chan struct{})}
	o.lastData.Store(turboCGINow())
	go func() {
		defer close(o.ended)
		defer close(o.chunks)
		for {
			buffer := make([]byte, 32<<10)
			o.lastData.Store(turboCGINow()) // Also after waiting for the previous data to be taken (a slow client)
			o.reading.Store(true)
			n, err := readEnd.Read(buffer)
			o.reading.Store(false)
			if n > 0 {
				o.lastData.Store(turboCGINow())
				select {
				case o.chunks <- buffer[:n]:
				case <-o.stopped:
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return o, writeEnd, nil
}

// Read returns what the CGI wrote; after stop, only what was already received.
func (o *turboCGIOutput) Read(p []byte) (int, error) {
	if len(o.pending) == 0 {
		select {
		case chunk, open := <-o.chunks:
			if !open {
				return 0, io.EOF
			}
			o.pending = chunk
		case <-o.stopped:
			select {
			case chunk, open := <-o.chunks:
				if !open {
					return 0, io.EOF
				}
				o.pending = chunk
			default:
				return 0, io.EOF
			}
		}
	}
	n := copy(p, o.pending)
	o.pending = o.pending[n:]
	return n, nil
}

// stop stops reading: it closes the read end, which unblocks the goroutine
// (on Windows, Close cancels the pending read).
func (o *turboCGIOutput) stop() {
	o.stopOnce.Do(func() {
		close(o.stopped)
		o.file.Close()
	})
}

// watch follows the CGI's process, already started. When it ends, it stops
// reading the output after turboCGIOutputGrace without new data, counted at
// the earliest from when it ended (what it wrote just before may not have
// reached the reading goroutine yet), without killing the processes it left.
// When ctx expires (the time limit, or the client went away), it stops reading
// at once: exec has already killed the group with cmd.Cancel, and if the
// process had already ended, what it left is killed. The channel it returns is
// closed with everything settled and after whoever reads the output has called
// stop, which it must do before waiting for it: until then the group is not
// released and can still be killed (P12 kills it if the response can't be used).
// On Windows, releasing it closes the Job Object, and killing it afterwards no longer reached anyone.
func (o *turboCGIOutput) watch(ctx context.Context, cmd *exec.Cmd, group *turboCGIGroup) <-chan struct{} {
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		cmd.Wait()
		close(exited)
	}()
	go func() {
		defer close(done)
		defer func() {
			<-o.stopped
			group.release()
		}()
		select {
		case <-exited:
		case <-ctx.Done():
			o.stop()
			<-exited
			group.kill() // If the process had already ended, exec killed no one: what it left doesn't go on
			return
		}
		exitedAt := turboCGINow()
		for {
			// First whether the goroutine waits, and then since when: read the other way round, a wait that has
			// just started was taken for one lasting since the previous data, and reading stopped too early.
			waiting := o.reading.Load()
			idle := time.Duration(turboCGINow() - max(o.lastData.Load(), exitedAt))
			if idle >= turboCGIOutputGrace && waiting {
				o.stop()
				return
			}
			select {
			case <-o.stopped:
				if ctx.Err() != nil { // ctx expired too: what it left doesn't go on
					group.kill()
				}
				return
			case <-o.ended: // All the output read
				if ctx.Err() != nil {
					group.kill()
				}
				return
			case <-ctx.Done():
				group.kill()
				o.stop()
				return
			case <-time.After(max(turboCGIOutputGrace-idle, 50*time.Millisecond)):
			}
		}
	}()
	return done
}
