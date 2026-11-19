//go:build !unix

package server

import "os"

// siteOpenFlags is how a name of a site is opened to be served. A folder of Windows has no FIFO to wait for (those of
// Unix: a.turbo.y.openfile.unix.go).
const siteOpenFlags = os.O_RDONLY

const logOpenFlags = 0
