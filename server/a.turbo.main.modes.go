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

// The modes of a site's preprocessors: how the script of a request runs with the program of a preprocessor, written
// "<mode>><program>" ("cgi" without a mode). dynamic does everything the modes share, which is what Turbo controls of a
// request (the size of its body, the slots, its time, its output, what the script never gets of it), and the mode only
// runs the script. A mode is a file that registers itself: a binary without it doesn't have the mode, and refuses it.

import (
	"time"

	"turbo/customNetHttp"
)

// dynamicJob is a request ready for a mode to run its script, with what Turbo controls of it already done: its body
// read whole within MBB, a slot taken, its context ending when WT runs out or the client goes away, its output bounded
// for its client and filtered as a CGI's, and the session cookie of the panel and the headers with "_" taken out.
type dynamicJob struct {
	request     *customNetHttp.Request       // With its body in memory or in a temporary file, and its context
	output      customNetHttp.ResponseWriter // Where its response goes
	executable  string                       // The program of the preprocessor, {TURBO_CURRENT_DIR} replaced
	basePath    string                       // The content folder of the site (DOCUMENT_ROOT)
	requestPath string                       // The path of the script in the site, after the rewrite (SCRIPT_NAME)
	queryString string                       // The client's query without the parameters the rewrite's sets, then the rewrite's
	timeout     time.Duration                // WT: how long the script may run; 0, without a limit
}

// preprocessorMode is what a mode of preprocessor does.
type preprocessorMode interface {
	// serve runs the script of job and writes its response to job.output. It returns once the response is complete,
	// or cut.
	serve(job *dynamicJob)
	// idle runs once a minute, with Turbo's cleaning: a mode that keeps processes lets go of those it no longer uses,
	// and of those whose program no preprocessor names (inUse).
	idle(inUse func(executable string) bool)
	// stop ends whatever the mode keeps running, when Turbo stops: within the time it has (wait).
	stop(wait time.Duration)
}

// preprocessorModes are the modes this binary has, by name: each registers itself in the init of its file.
var preprocessorModes = map[string]preprocessorMode{}

func registerPreprocessorMode(name string, mode preprocessorMode) {
	preprocessorModes[name] = mode
}

// idlePreprocessorModes lets each mode let go of what it no longer uses: what the preprocessors of every site name is
// read once, under the read lock.
func idlePreprocessorModes() {
	inUse := map[string]bool{}
	withReadLock(func() {
		for _, extensions := range preprocessors {
			for _, value := range extensions {
				if _, executable, problem := preprocessorParts(value); problem == "" {
					inUse[executable] = true
				}
			}
		}
	})
	for _, mode := range preprocessorModes {
		mode.idle(func(executable string) bool { return inUse[executable] })
	}
}

// stopPreprocessorModes ends what every mode keeps running, within wait.
func stopPreprocessorModes(wait time.Duration) {
	for _, mode := range preprocessorModes {
		mode.stop(wait)
	}
}
