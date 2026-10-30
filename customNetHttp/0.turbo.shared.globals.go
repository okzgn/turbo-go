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

import (
	"sync/atomic"
	"time"
)

// Estado de Turbo que lee el servidor HTTP (los parches de PATCHES.md). El
// resto del estado de Turbo vive en el paquete main.

// TurboServerName is the value of the Server header and of the default error
// template.
const TurboServerName = "OKZGN Turbo"

// Timeouts holds the server time limits (RT, RHT, WT, IT). It is published as
// an immutable value in TurboTimeLimits: writers store a new copy and each
// connection loads the current one, so a change from the panel applies without
// restarting.
type Timeouts struct{ RT, RHT, WT, IT time.Duration }

var TurboTimeLimits atomic.Pointer[Timeouts] // Server time limits

// TurboErrorTemplates holds the error templates by HTTP status code (0 is the
// default one). It is published as an immutable map: writers store a modified
// copy, so the server reads it without locks, also before any handler runs.
var TurboErrorTemplates atomic.Pointer[map[int]string]

// Size limits (MBB, MHB, MUB). The panel changes them while requests read them,
// so they are atomic.
var (
	TurboMaxBodySize    atomic.Int64 // Upload/body limit (MBB)
	TurboMaxHeaderBytes atomic.Int64 // Request header limit (MHB)
	TurboMaxURILength   atomic.Int64 // URI length limit (MUB)
)

// Limits of multipart forms (fixed).
var (
	TurboMaxFormParts         = 10000 // Maximum parts of a form
	TurboMaxFormHeaders int64 = 1000  // Maximum headers of the parts of a form
)

func init() {
	TurboTimeLimits.Store(&Timeouts{})
	TurboErrorTemplates.Store(&map[int]string{})
	TurboMaxBodySize.Store(1048576)
	TurboMaxHeaderBytes.Store(5000)
	TurboMaxURILength.Store(1000)
}
