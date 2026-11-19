//go:build unix

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
