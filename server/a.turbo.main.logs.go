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

// The logs: turbo.visits and turbo.denials, written while their files are there, and the error lines of the
// connections and of the CGIs, which are grouped by kind.

import (
	"log"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"turbo/customNetHttp"
)

// serverErrorLog is the ErrorLog of both servers (Go's errors of the connections) and cgiErrorLog that of the CGIs
// (a CGI that fails, or whose client goes away): both write through errorLines, as warnings.
var (
	serverErrorLog = log.New(errorLines, "", 0)
	cgiErrorLog    = log.New(errorLines, "", 0)
)

// errorLines is where the error lines of the connections and of the CGIs are written: each kind once at once and
// then at most once a minute, with the count and the last line.
var errorLines = &aggregatedLog{}

// aggregatedLog writes lines that anyone can make the server write, one per connection or per frame (a failed TLS
// handshake, a bogus HTTP/2 preface, a GOAWAY with an error, a protocol error, a client gone from a CGI…), as
// warnings: the first of each kind at once, and those that follow within aggregatedLogInterval counted, and written
// when it ends with the count and the last one. One line each let anyone fill the log, and journald, past its rate
// limit, dropped Turbo's other messages. The kinds are the first words of a line, up to one with a digit (an
// address, a port); at most aggregatedLogKinds are kept apart, and the rest share one.
type aggregatedLog struct {
	mutex  sync.Mutex
	kinds  map[string]*aggregatedKind
	timer  *time.Timer // The next write of the lines counted, while there are any
	closed bool        // Since the shutdown wrote what was counted (close): each line is written at once
}

type aggregatedKind struct {
	count  int       // Lines counted and not written yet
	last   string    // The last of them
	logged time.Time // When a line of this kind was last written
}

const (
	aggregatedLogInterval = time.Minute
	aggregatedLogKinds    = 64
)

// aggregatedLogKind is the kind of a line: its first four words, up to one with a digit after the first (an address,
// a port; the first may be "http2:"), or for a panic that of panicLogKind.
func aggregatedLogKind(line string) string {
	if kind, isPanic := panicLogKind(line); isPanic {
		return kind
	}
	words := strings.Fields(line)
	kept := words[:0]
	for index, word := range words {
		if len(kept) == 4 || (index > 0 && strings.ContainsAny(word, "0123456789")) {
			break
		}
		kept = append(kept, word)
	}
	return strings.Join(kept, " ")
}

// panicLogKind is the kind of the line of a handler's panic, "http: panic serving <address>: <value>" with its stack:
// the value up to its first digit and the function in which it panicked (the frame after "panic("). All the panics
// were one kind, and within a minute only the last one's stack was written, the others' lost.
func panicLogKind(line string) (string, bool) {
	first, stack, _ := strings.Cut(line, "\n")
	for _, prefix := range []string{"http: panic serving ", "http2: panic serving "} {
		after, found := strings.CutPrefix(first, prefix)
		if !found {
			continue
		}
		_, value, _ := strings.Cut(after, ": ") // After the client's address
		if digit := strings.IndexAny(value, "0123456789"); digit != -1 {
			value = value[:digit]
		}
		function, panicked := "", false
		for _, frame := range strings.Split(stack, "\n") {
			switch {
			case strings.HasPrefix(frame, "panic("):
				panicked = true
			case panicked && frame != "" && !strings.HasPrefix(frame, "\t"): // The function after it, not its file
				function, _, _ = strings.Cut(frame, "(")
			}
			if function != "" {
				break
			}
		}
		kind := strings.TrimSpace(prefix) + " " + strings.TrimSpace(value)
		if function != "" {
			kind += " in " + function
		}
		return kind, true
	}
	return "", false
}

func (l *aggregatedLog) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	kind := aggregatedLogKind(line)
	now := time.Now()
	l.mutex.Lock()
	if l.closed {
		l.mutex.Unlock()
		slog.Warn(line)
		return len(p), nil
	}
	if l.kinds == nil {
		l.kinds = make(map[string]*aggregatedKind)
	}
	entry := l.kinds[kind]
	if entry == nil && len(l.kinds) >= aggregatedLogKinds-1 {
		// The kinds without a line counted nor written for an interval are forgotten: kept forever, the first 63
		// that ever came (part of each is what a client sends) left every later one in "(other)".
		for known, old := range l.kinds {
			if old.count == 0 && now.Sub(old.logged) >= aggregatedLogInterval {
				delete(l.kinds, known)
			}
		}
	}
	if entry == nil {
		if len(l.kinds) >= aggregatedLogKinds-1 { // The last place is for all the others
			kind = "(other)"
			entry = l.kinds[kind]
		}
		if entry == nil {
			entry = &aggregatedKind{}
			l.kinds[kind] = entry
		}
	}
	if entry.count == 0 && now.Sub(entry.logged) >= aggregatedLogInterval { // The first in a while: at once
		entry.logged = now
		l.mutex.Unlock()
		slog.Warn(line)
		return len(p), nil
	}
	entry.count++
	entry.last = line
	if l.timer == nil {
		l.timer = time.AfterFunc(aggregatedLogInterval, l.flush)
	}
	l.mutex.Unlock()
	return len(p), nil
}

// close writes the lines counted and, from then on, each line at once: the shutdown calls it last, and what was
// counted after its flush was lost.
func (l *aggregatedLog) close() {
	l.mutex.Lock()
	l.closed = true
	l.mutex.Unlock()
	l.flush()
}

// reopen groups the lines again, as at the start, with nothing counted (for the tests, after a shutdown).
func (l *aggregatedLog) reopen() {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.timer != nil {
		l.timer.Stop()
		l.timer = nil
	}
	l.closed, l.kinds = false, nil
}

// flush writes the lines counted, one per kind, with the count and the last one.
func (l *aggregatedLog) flush() {
	type counted struct {
		kind, last string
		count      int
	}
	var lines []counted
	now := time.Now()
	l.mutex.Lock()
	for kind, entry := range l.kinds {
		if entry.count > 0 {
			lines = append(lines, counted{kind, entry.last, entry.count})
			entry.count, entry.last, entry.logged = 0, "", now
		}
	}
	if l.timer != nil {
		l.timer.Stop()
		l.timer = nil
	}
	l.mutex.Unlock()
	sort.Slice(lines, func(i, j int) bool { return lines[i].kind < lines[j].kind })
	for _, line := range lines {
		slog.Warn("Repeated errors (logged once a minute at most)", "kind", line.kind, "count", line.count, "last", line.last)
	}
}

// visitsLogOpen and denialsLogOpen say, without logMutex, whether each log is open. Most servers have no turbo.visits:
// every request built its line and took the lock, one for all of them, only to find that out.
var visitsLogOpen, denialsLogOpen atomic.Bool

// logsOpenLocked notes which logs are open. Callers hold logMutex.
func logsOpenLocked() {
	visitsLogOpen.Store(visitsLogFile != nil)
	denialsLogOpen.Store(denialsLogFile != nil)
}

func serverSetLogState(logType string, logFile *os.File) {
	logMutex.Lock()
	defer logMutex.Unlock()
	defer logsOpenLocked()

	switch logType {
	case visitsLogName:
		if visitsLogFile == logFile {
			return
		}
		if visitsLogFile != nil {
			closeLog(visitsLogFile)
		}
		visitsLogFile = logFile
	case denialsLogName:
		if denialsLogFile == logFile {
			return
		}
		if denialsLogFile != nil {
			closeLog(denialsLogFile)
		}
		denialsLogFile = logFile
	}
}

// closeLog closes a log file, saying so if it fails (the last lines may be lost).
func closeLog(logFile *os.File) {
	if err := logFile.Close(); err != nil {
		slog.Warn("Can't close the log", "file", logFile.Name(), "error", err)
	}
}

func serverGetLogState(logType string) *os.File {
	logMutex.Lock()
	defer logMutex.Unlock()

	switch logType {
	case visitsLogName:
		return visitsLogFile
	case denialsLogName:
		return denialsLogFile
	}
	return nil
}

// refreshLogFiles opens or closes each log depending on whether its file exists in baseDir, and opens it again
// when the file at that path is no longer the one open (rotated by renaming it, as logrotate does). It runs with
// the periodic settings check, so requests never stat the files.
func refreshLogFiles(baseDir string) {
	for _, logType := range []string{visitsLogName, denialsLogName} {
		pathInfo, statErr := os.Stat(baseDir + logType)
		openFile := serverGetLogState(logType)
		if openFile != nil && statErr == nil {
			if openInfo, err := openFile.Stat(); err == nil && os.SameFile(openInfo, pathInfo) {
				continue // Still the same file
			}
		}
		if statErr == nil {
			logFile, openErr := os.OpenFile(baseDir+logType, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 -- fixed log name in the sites directory
			if openErr == nil {
				serverSetLogState(logType, logFile) // Closes the one that was open
				logOpenProblems.Delete(baseDir + logType)
			} else if previous, _ := logOpenProblems.Swap(baseDir+logType, openErr.Error()); previous != openErr.Error() {
				// Once while the error is the same (this runs every 30 s); the file that was open, if any, keeps
				// getting the lines
				slog.Warn("Can't open the log", "file", baseDir+logType, "error", openErr)
			}
		} else if openFile != nil {
			serverSetLogState(logType, nil)
		}
	}
}

// logOpenProblems is, per log path, the error with which it last couldn't be opened, so that it is warned about
// once while it lasts (a rotation that leaves the file with another owner, for example).
var logOpenProblems sync.Map

// logField writes a field of a log line as it is, or quoted and escaped if it has spaces, quotes, control
// characters (C1 ones too), other characters that don't print (such as U+2028, a line break for some tools) or
// invalid UTF-8, so that each line keeps its fields apart (an HTTP/2 path may have spaces) and shows in a terminal
// as it is.
func logField(field string) string {
	for _, r := range field {
		if r <= ' ' || r == '"' || r == utf8.RuneError || !strconv.IsPrint(r) {
			return strconv.Quote(field)
		}
	}
	return field
}

func serverWriteLogs(logType string, request *customNetHttp.Request, timestamp int64, prefix string) {
	open := &visitsLogOpen
	if logType == denialsLogName {
		open = &denialsLogOpen
	}
	if !open.Load() {
		return // Not open: nothing to build nor to wait for (a log opened right now gets the next line)
	}
	line := ""
	if request == nil {
		line = prefix + " " + "\n"
	} else {
		line = prefix + " " + request.RemoteAddr + " " + strconv.FormatInt(timestamp, 10) + " " + logField(request.Method) + " " + logField(request.Host) + " " + logField(request.RequestURI) + " " + "\n"
	}

	logMutex.Lock()
	defer logMutex.Unlock()
	logFile := visitsLogFile
	if logType == denialsLogName {
		logFile = denialsLogFile
	}
	if logFile != nil {
		_, _ = logFile.WriteString(line) // A log that can't be written has nowhere to report it per request
	}
}
