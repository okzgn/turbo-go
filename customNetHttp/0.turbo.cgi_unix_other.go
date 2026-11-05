//go:build unix && !linux

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

// The leader of a CGI's process group outside Linux (turbo:P12, see
// 0.turbo.cgi.go and 0.turbo.cgi_unix.go).

import "os/exec"

// turboCGIKeepsLeader: outside Linux the leader is reaped as soon as it ends
// (there is no waitid with WNOWAIT that Go reaches), as before: a group whose
// processes are all gone may, rarely, have its ID given to another.
const turboCGIKeepsLeader = false

// turboCGIWaitExit waits for the leader of a CGI's group to end, and reaps it.
func turboCGIWaitExit(cmd *exec.Cmd) {
	cmd.Wait()
}
