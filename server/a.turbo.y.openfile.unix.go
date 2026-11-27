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

package server

import (
	"os"
	"syscall"
)

// siteOpenFlags is how a name of a site is opened to be served: without waiting, so that a FIFO, whose open waits for
// a writer, comes back at once and is seen for what it is (openSiteFile). A file or a folder opens the same.
const siteOpenFlags = os.O_RDONLY | syscall.O_NONBLOCK

// logOpenFlags: a FIFO without a reader answers at once (ENXIO) instead of waiting for one.
const logOpenFlags = syscall.O_NONBLOCK
