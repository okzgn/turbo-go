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

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"maps"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"turbo/customNetHttp"
	"unicode/utf8"
)

// Locks: globalMutex guards the maps of this block (signedInTokens, charReplacements, fixedCharReplacements,
// sitesMap, siteSSLConfig, mimeTypes, customHeaders, preprocessors, indexFiles, domainAliases, dormantSites), together with
// siteCertificates, fixedHTTPResponses, currentCertDomain and configFileModTime: read them with RLock and change
// them with Lock (lockedCheck, withGlobalLock), never outside, as a concurrent map read and write ends the
// process. Values read on every request without it are atomic or published copies (atomicString,
// atomic.Pointer, sync.Map, atomic counters), and logMutex guards the log files.
var (
	servers               = make([]*customNetHttp.Server, 2) // Current servers
	signedInTokens        = make(map[string]int64)           // Signed-in tokens: when each session ends without requests
	sessionDeadlines      = make(map[string]int64)           // When each session ends however it is used (sessionMaxLifetime)
	deniedIPs             atomic.Pointer[map[string]int64]   // IPs denied by the administrator until a UNIX date (saved as "@"; published copy, see setDeniedIPs)
	panelUser             atomicString                       // Panel username
	panelPasswordHash     atomicString                       // Panel password hash, saved as "PH" (see setPanelPassword)
	userFromEnv           bool                               // TURBO_USER set: it has priority over turbo.config
	passwordFromEnv       bool                               // TURBO_PASSWORD set: it has priority over turbo.config
	sitesDir              atomicString                       // Sites directory, resolved (see resolveSitesDir)
	sitesDirValue         atomicString                       // Sites directory as written (TURBO_DIR or "M"), saved as such so the configuration isn't tied to this machine
	startDir              string                             // Directory where turbo.config is read first (working directory or TURBO_DIR), resolved
	charReplacements      = make(map[string]string)          // Characters to encode
	fixedCharReplacements = make(map[string]bool)            // Fixed character replacements

	sitesMap      = make(map[string]map[string]map[string]string) // Sites map and rewrites
	siteSSLConfig = make(map[string]map[string]interface{})       // Sites with SSL
	mimeTypes     = make(map[string]map[string]string)            // MIME types
	customHeaders = make(map[string]map[string]string)            // Custom headers
	preprocessors = make(map[string]map[string]string)            // Preprocessors
	indexFiles    = make(map[string]map[string]int)               // Index files: name -> position (tried from the lowest)
	domainAliases = make(map[string]string)                       // Domain aliases
	dormantSites  = make(map[string]map[string]string)            // Sites whose folder isn't there: site -> subdomain -> its section of turbo.config (JSON), applied when the folder appears

	serverTimeLimits    = &customNetHttp.TurboTimeLimits     // Server time limits (published copy, see setTimeLimits)
	serverRequestLimits requestLimits                        // Per-IP limits (CIL, CIS, CII)
	maxBodySize         = &customNetHttp.TurboMaxBodySize    // Server upload/body limit (MBB), read by the server on each request
	maxHeaderBytes      = &customNetHttp.TurboMaxHeaderBytes // Maximum header bytes to read (MHB)
	maxURILength        = &customNetHttp.TurboMaxURILength   // Maximum URI length (MUB)

	globalRequestLimit  atomic.Int64  // CGL: requests per second for the whole server; 0 = no limit
	cgiProcesses        atomic.Int64  // CGP: CGI processes at a time; 0 = automatic (see cgiProcessLimit)
	globalRequestWindow atomic.Uint64 // Unix second (high 32 bits) and the requests counted in it (low 32 bits)

	configCheckTicker = time.NewTicker(30 * time.Second)
	cleanupTicker     = time.NewTicker(60 * time.Second)

	tlsConfig = &tls.Config{NextProtos: []string{"h2", "http/1.1"}, Certificates: []tls.Certificate{}, MinVersion: tls.VersionTLS12}

	currentCertDomain string              // Certificate domain currently being processed
	certRetryDelay    = 30 * time.Second  // Delay before retrying a certificate while another one is being issued
	certPending       = map[string]bool{} // Sites with a certificate retry waiting (one each); guarded by globalMutex
	configFileModTime int64               // Config file modification time reference

	httpResponses      = &customNetHttp.TurboErrorTemplates // HTTP responses (published copy, see setHTTPResponses)
	fixedHTTPResponses = make(map[int]bool)                 // Fixed HTTP response codes

	visitsLogFile  *os.File // Visits log file pointer
	denialsLogFile *os.File // Denials log file pointer

	globalMutex  sync.RWMutex // Global mutex for shared state
	logMutex     sync.Mutex   // Guards the log file pointers, apart from globalMutex so logging never waits for it
	ipReferences sync.Map     // References per IP
)

// Limits of a site's custom headers (addHeader): the name and the value, in bytes.
const (
	maxHeaderKeyLength   = 48
	maxHeaderValueLength = 512
)

// Fixed names and texts (they were the keys of stringStore).
const (
	serverName          = customNetHttp.TurboServerName // Server header and default error template
	adminPathPrefix     = "admin"                       // Panel path: /admin:
	adminInsideName     = "inside"                      // Authenticated panel: /admin:inside:
	sessionHeaderName   = "ok"                          // Session header and login token prefix
	certificatesDirName = "turbo.certificates"          // Certbot's work directory
	panelCertDirName    = "turbo.panel"                 // Certificate of the panel's own host
	acmeWebrootDirName  = "webroot"                     // Inside turbo.panel: Certbot's webroot for the panel's certificate
	publicDirName       = "@"                           // Public content of each site
	certFileName        = "fullchain.pem"               // Certificate of each site
	keyFileName         = "privkey.pem"                 // Private key of each site
	configFileName      = "turbo.config"                // Configuration
	denialsLogName      = "turbo.denials"               // Denials log
	visitsLogName       = "turbo.visits"                // Visits log
	panelPageName       = "#.html"                      // Panel page
	contentTypeHeader   = "Content-Type"                // Header name
	msgMissingData      = "Missing data"                // Generic API error
	devGUIDirName       = "turbo.dev"                   // GUI override directory
)

// turboVersion is the release, set by release.sh with -ldflags "-X main.turboVersion=<version>".
var turboVersion string

// buildDescription says what this binary is: the release ("development" when built from the source without
// release.sh), the commit it was built from ("+modified" if the tree had changes; "unknown" without
// version control information) and the Go it was built with.
func buildDescription() (version string, commit string, goVersion string) {
	version, commit = turboVersion, "unknown"
	if version == "" {
		version = "development"
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		modified := false
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				commit = setting.Value
			case "vcs.modified":
				modified = setting.Value == "true"
			}
		}
		if modified && commit != "unknown" {
			commit += "+modified"
		}
	}
	return version, commit, runtime.Version()
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil))) // Levels and timestamps; systemd keeps stdout in the journal
	version, commit, goVersion := buildDescription()
	slog.Info("Starting", "server", serverName, "version", version, "commit", commit, "go", goVersion) // Which advisories apply

	// GUI access username & password
	panelUser.Set("Turbo")
	envValue, envExists := os.LookupEnv("TURBO_USER")
	if envExists && envValue == "" { // Set by mistake: an empty username or password would let anyone in
		slog.Error("TURBO_USER is set but empty: Turbo does not start")
		os.Exit(1)
	}
	if envExists && !panelUserValid(envValue) { // Saved as "U", turbo.config would be refused once it is unset
		slog.Error("TURBO_USER must have 1 to 24 characters, without control characters: Turbo does not start")
		os.Exit(1)
	}
	if envExists {
		slog.Info("Panel user taken from TURBO_USER")
		panelUser.Set(envValue)
		userFromEnv = true
	}

	envValue, envExists = os.LookupEnv("TURBO_PASSWORD")
	if envExists && envValue == "" {
		slog.Error("TURBO_PASSWORD is set but empty: Turbo does not start")
		os.Exit(1)
	}
	if envExists && (len(envValue) > maxPasswordBytes || !textAllowed(envValue, false)) { // The panel couldn't take it
		slog.Error("TURBO_PASSWORD must have at most " + strconv.Itoa(maxPasswordBytes) + " bytes, without control characters: Turbo does not start")
		os.Exit(1)
	}
	if envExists {
		slog.Info("Panel password taken from TURBO_PASSWORD")
		if len(envValue) < minNewPasswordBytes {
			slog.Warn("TURBO_PASSWORD has fewer than " + strconv.Itoa(minNewPasswordBytes) + " bytes: use a longer one, as the panel requires for a new password")
		}
		if err := setPanelPassword(envValue); err != nil {
			slog.Error("Can't hash TURBO_PASSWORD: Turbo does not start", "error", err)
			os.Exit(1)
		}
		passwordFromEnv = true
	} else if err := setPanelPassword("Admin"); err != nil {
		slog.Error("Can't hash the default password: Turbo does not start", "error", err)
		os.Exit(1)
	}

	sitesDirValue.Set("{" + currentDirPlaceholder + "}")
	envValue, envExists = os.LookupEnv("TURBO_DIR")
	if envExists {
		slog.Info("Sites directory taken from TURBO_DIR", "directory", envValue)
		sitesDirValue.Set(envValue)
	}
	resolvedDir, err := resolveSitesDir(sitesDirValue.Get())
	if err != nil {
		slog.Error("Invalid sites directory: Turbo does not start", "directory", sitesDirValue.Get(), "error", err)
		os.Exit(1)
	}
	sitesDir.Set(resolvedDir)
	startDir = resolvedDir

	if httpAddr, err = listenAddress("TURBO_HTTP_ADDR", httpAddr); err != nil {
		slog.Error("Invalid TURBO_HTTP_ADDR", "error", err)
		os.Exit(1)
	}
	if httpsAddr, err = listenAddress("TURBO_HTTPS_ADDR", httpsAddr); err != nil {
		slog.Error("Invalid TURBO_HTTPS_ADDR", "error", err)
		os.Exit(1)
	}

	setHTTPResponses(func(responses map[int]string) { responses[0] = serverName + `\n{TURBO_RESPONSE_CODE}` })
	fixedHTTPResponses = map[int]bool{0: true}

	charReplacements[";"] = "-.-" // Fixed replacements, also sent to the panel
	charReplacements["#"] = "-,-"
	charReplacements["&"] = "-_-"
	fixedCharReplacements = map[string]bool{";": true, "#": true, "&": true}

	if err := updateSettings(false); err != nil { // applying defaults would lose the configuration
		fmt.Fprintln(os.Stderr, configErrorMessage(err, true))
		os.Exit(1)
	}
	warnDefaultCredentials()
	clearInheritedCapabilities() // Before any CGI can run; opening the ports needs only Turbo's effective set
	servers[0] = createSafeServer(tlsConfig)
	servers[1] = createHTTPServer()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM) // Ctrl+C, and what systemd sends to stop the service
	runRecovering("renewCertificates", renewCertificates)
	renewTicker := time.NewTicker(24 * time.Hour)
	for {
		select {
		case received := <-stop:
			shutdown(received)
			return
		case <-renewTicker.C:
			runRecovering("renewCertificates", renewCertificates)
		case <-configCheckTicker.C:
			runRecovering("updateSettings", func() { logConfigError(updateSettings(true)) })
		case <-cleanupTicker.C:
			runRecovering("cleanOldValues", func() {
				cleanOldValues(&signedInTokens)
				cleanOldValues(&sessionDeadlines)
				withGlobalLock(cleanDeniedIPs)
				cleanLoginFailures()
				cleanIPReferences()
			})
		}
	}
}

// shutdownGrace is how long the requests in progress have to finish when Turbo is stopped (a variable so that tests
// can shorten it), and cgiEndWait how long, after it, the CGIs that were ended have to be gone.
var shutdownGrace = 10 * time.Second

const cgiEndWait = 3 * time.Second

// shutdown stops both servers: they stop accepting connections and wait up to shutdownGrace for the requests in
// progress. Then the connections still open are closed, which ends their CGIs with all they started (P12): without
// systemd, nothing else would, and they would go on after Turbo. Then the logs are closed, and main returns (exit
// code 0).
func shutdown(received os.Signal) {
	slog.Info("Stopping", "signal", received.String())
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	var wg sync.WaitGroup
	for _, server := range servers {
		if server == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := server.Shutdown(ctx); err != nil {
				slog.Warn("Requests unfinished at shutdown: their connections are closed", "error", err)
				_ = server.Close() // Its error is that of a listener already closed by Shutdown
			}
		}()
	}
	wg.Wait()
	waitCGIsEnded(cgiEndWait)
	errorLines.flush()                    // The errors counted and not written yet
	serverSetLogState(visitsLogName, nil) // Closed, so the last lines are written
	serverSetLogState(denialsLogName, nil)
	slog.Info("Stopped")
}

// waitCGIsEnded waits, up to wait, until no CGI is running (each releases its slot once it is gone).
func waitCGIsEnded(wait time.Duration) {
	deadline := time.Now().Add(wait)
	for {
		cgiSlots.mutex.Lock()
		running := cgiSlots.running
		if running > 0 && cgiSlots.freed == nil {
			cgiSlots.freed = make(chan struct{})
		}
		freed := cgiSlots.freed
		cgiSlots.mutex.Unlock()
		remaining := time.Until(deadline)
		if running <= 0 {
			return
		}
		if remaining <= 0 {
			slog.Warn("CGIs still running when Turbo exits", "count", running)
			return
		}
		timer := time.NewTimer(remaining)
		select {
		case <-freed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// runRecovering runs a periodic task of main() and logs a panic instead of ending the process.
func runRecovering(taskName string, task func()) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("Panic in "+taskName, "error", p)
		}
	}()
	task()
}

// setTimeLimits publishes a modified copy of the server time limits. Callers hold the global lock, so
// writes don't overlap, while connections read the published value without it.
func setTimeLimits(change func(*customNetHttp.Timeouts)) {
	limits := *serverTimeLimits.Load()
	change(&limits)
	serverTimeLimits.Store(&limits)
}

// atomicString is a string that is replaced as a whole and read without locks.
type atomicString struct{ value atomic.Pointer[string] }

func (s *atomicString) Get() string {
	if stored := s.value.Load(); stored != nil {
		return *stored
	}
	return ""
}

func (s *atomicString) Set(value string) { s.value.Store(&value) }

// setHTTPResponses publishes a modified copy of the error templates. Callers hold the global lock, so
// writes don't overlap, while the server reads the published map without it.
func setHTTPResponses(change func(map[int]string)) {
	responses := maps.Clone(*httpResponses.Load())
	change(responses)
	httpResponses.Store(&responses)
}

// deniedIPList returns the published list of denied IPs, which must not be modified.
func deniedIPList() map[string]int64 {
	if list := deniedIPs.Load(); list != nil {
		return *list
	}
	return nil
}

// deniedIPsLoading is the list of denied IPs being built while applySiteConfig applies a turbo.config: the
// published one stays in use meanwhile, and is replaced once, whole (publishLoadedDeniedIPs). Guarded by
// globalMutex.
var deniedIPsLoading map[string]int64

// deniedIPsInUse is the list of denied IPs as the validators see it: the one being built while a turbo.config is
// applied, or else the published one. Callers hold the global lock.
func deniedIPsInUse() map[string]int64 {
	if deniedIPsLoading != nil {
		return deniedIPsLoading
	}
	return deniedIPList()
}

// setDeniedIPs publishes a modified copy of the denied IPs, or changes the list being built while a turbo.config
// is applied. Callers hold the global lock, so writes don't overlap, while the rate limiter reads the published
// list without it.
func setDeniedIPs(change func(map[string]int64)) {
	if deniedIPsLoading != nil {
		change(deniedIPsLoading)
		return
	}
	list := maps.Clone(deniedIPList())
	if list == nil {
		list = make(map[string]int64)
	}
	change(list)
	publishDeniedIPs(list)
}

// publishLoadedDeniedIPs publishes, once, the list built while a turbo.config was applied. Callers hold the global
// lock.
func publishLoadedDeniedIPs() {
	if list := deniedIPsLoading; list != nil {
		deniedIPsLoading = nil
		publishDeniedIPs(list)
	}
}

// deniedNetworks is, for the denied IPv6 addresses, the /64 of each (limiterKey) with the latest of their dates:
// the rate limits count a /64 as one client, whose addresses change by themselves (privacy addresses), so a
// denial covers the whole /64. Published with deniedIPs.
var deniedNetworks atomic.Pointer[map[string]int64]

// publishDeniedIPs publishes a list of denied IPs, which mustn't be modified afterwards, and its /64s.
func publishDeniedIPs(list map[string]int64) {
	networks := make(map[string]int64)
	for ip, until := range list {
		if network := limiterKey(ip); network != ip {
			networks[network] = max(networks[network], until)
		}
	}
	deniedNetworks.Store(&networks)
	deniedIPs.Store(&list)
}

// deniedUntil returns the UNIX date until which ip is denied: its own, or that of a denied IPv6 address of its
// /64; 0 if it isn't. Without the global lock, like the rest of the limiter.
func deniedUntil(ip string) int64 {
	until := deniedIPList()[ip]
	if networks := deniedNetworks.Load(); networks != nil {
		if network := limiterKey(ip); network != ip {
			until = max(until, (*networks)[network])
		}
	}
	return until
}

// cleanDeniedIPs removes the expired denials. Callers hold the global lock.
func cleanDeniedIPs() {
	now := time.Now().Unix()
	setDeniedIPs(func(list map[string]int64) {
		for ip, deniedUntil := range list {
			if now > deniedUntil {
				delete(list, ip)
			}
		}
	})
}

// withReadLock runs fn holding the global read lock, releasing it even if fn panics.
func withReadLock(fn func()) {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	fn()
}

// withGlobalLock runs fn holding the global write lock, releasing it even if fn panics.
func withGlobalLock(fn func()) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	fn()
}

func createSafeServer(tlsConfig *tls.Config) *customNetHttp.Server {
	server := newHTTPSServer(tlsConfig)
	if len(siteCertificates) > 0 || panelCertificate != nil {
		return safeServerStart(server, tlsConfig)
	}

	return server
}

// newHTTPSServer builds the HTTPS server, without listening yet. Its time limits aren't set here: the server reads
// them from TurboTimeLimits on each connection (P6), so that a change from the panel applies at once.
func newHTTPSServer(tlsConfig *tls.Config) *customNetHttp.Server {
	return &customNetHttp.Server{
		ConnState: connHandler,
		Handler:   customNetHttp.HandlerFunc(serverHandlerFn("s")),
		ErrorLog:  serverErrorLog, // Connection errors (TLS, HTTP/2)
		TLSConfig: tlsConfig,
		HTTP2: &customNetHttp.HTTP2Config{
			MaxConcurrentStreams: http2MaxStreams,
			WriteByteTimeout:     http2WriteByteTimeout,
			SendPingTimeout:      http2SendPingTimeout,
			PingTimeout:          http2PingTimeout,
		},
	}
}

// The time limits of an HTTP/2 connection, besides those of its streams (P6). A connection has a single writer: a
// client that stops reading blocks it, and the write deadline of a stream (WT) only queues a reset that can't be
// written either, so every handler of the connection, with its CGI and its slot, waited for as long as the client
// kept the connection open. http2WriteByteTimeout closes a connection to which nothing could be written for that
// long; http2SendPingTimeout pings a connection from which nothing arrived for that long, and http2PingTimeout closes
// it if the ping isn't answered, so that a client gone without closing doesn't keep its streams open. Variables so
// that tests can shorten them.
var (
	http2WriteByteTimeout = 30 * time.Second
	http2SendPingTimeout  = 60 * time.Second
	http2PingTimeout      = 15 * time.Second
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
	mutex sync.Mutex
	kinds map[string]*aggregatedKind
	timer *time.Timer // The next write of the lines counted, while there are any
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
// a port; the first may be "http2:").
func aggregatedLogKind(line string) string {
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

func (l *aggregatedLog) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	kind := aggregatedLogKind(line)
	now := time.Now()
	l.mutex.Lock()
	if l.kinds == nil {
		l.kinds = make(map[string]*aggregatedKind)
	}
	entry := l.kinds[kind]
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

// safeServerStart serves HTTPS on httpsAddr (:443). While it isn't open (it couldn't be opened, or the server
// stopped with an error), nothing is redirected to HTTPS (httpsListening) and Turbo tries to open it again every
// httpsRetryDelay.
func safeServerStart(server *customNetHttp.Server, tlsConfig *tls.Config) *customNetHttp.Server {
	listener, err := tls.Listen("tcp", httpsAddr, tlsConfig) // #nosec G102 -- a web server listens on every interface by default; TURBO_HTTPS_ADDR narrows it
	if err != nil {
		slog.Error("Can't open the HTTPS address: will retry", "address", httpsAddr, "error", err)
		retryHTTPS(server, tlsConfig)
		return server
	}
	httpsListening.Store(true)

	go func() {
		err := server.Serve(listener)
		httpsListening.Store(false)
		if errors.Is(err, customNetHttp.ErrServerClosed) { // Stopped on purpose (shutdown)
			return
		}
		slog.Error("HTTPS server stopped: will retry", "error", err)
		_ = listener.Close() // After a failure: the error that matters is the one logged
		retryHTTPS(server, tlsConfig)
	}()

	return server
}

// httpsRetrying is set while a retry of safeServerStart is waiting: one at a time.
var httpsRetrying atomic.Bool

// retryHTTPS opens httpsAddr again after httpsRetryDelay, unless it is open by then.
func retryHTTPS(server *customNetHttp.Server, tlsConfig *tls.Config) {
	if !httpsRetrying.CompareAndSwap(false, true) {
		return
	}
	time.AfterFunc(httpsRetryDelay, func() {
		httpsRetrying.Store(false)
		if !httpsListening.Load() {
			safeServerStart(server, tlsConfig)
		}
	})
}

// createHTTPServer builds the HTTP server and starts it. Like the HTTPS one, it reads its time limits from
// TurboTimeLimits (P6).
func createHTTPServer() *customNetHttp.Server {
	server := &customNetHttp.Server{
		ConnState: connHandler,
		Handler:   customNetHttp.HandlerFunc(serverHandlerFn("")),
		ErrorLog:  serverErrorLog, // Connection errors
	}

	return httpServerStart(server)
}

// http2MaxStreams is the maximum of concurrent HTTP/2 streams per connection (Go's default is 250).
const http2MaxStreams = 50

// httpsRetryDelay is how long Turbo waits before trying again to open httpsAddr.
var httpsRetryDelay = 30 * time.Second

// Listening addresses: ":80" and ":443", or TURBO_HTTP_ADDR and TURBO_HTTPS_ADDR (for example
// "127.0.0.1:8080" behind a proxy). Set once at start.
var (
	httpAddr  = ":80"
	httpsAddr = ":443"
)

// listenAddress returns the address in the environment variable name ("host:port", ":port" or just
// the port), or def if it isn't set.
func listenAddress(name, def string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return def, nil
	}
	if !strings.Contains(value, ":") {
		value = ":" + value
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", err
	}
	if portNumber, err := strconv.Atoi(port); err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("invalid port: " + port)
	}
	return net.JoinHostPort(host, port), nil
}

// httpServerStart serves on httpAddr (:80). Without it Turbo can't work, so it ends with an error instead of
// staying alive without serving (systemd and the like then see the failure and restart it).
func httpServerStart(server *customNetHttp.Server) *customNetHttp.Server {
	listener, err := net.Listen("tcp", httpAddr) // #nosec G102 -- a web server listens on every interface by default; TURBO_HTTP_ADDR narrows it
	if err != nil {
		slog.Error("Can't open the HTTP address", "address", httpAddr, "error", err)
		os.Exit(1)
	}

	go func() {
		err := server.Serve(listener)
		if errors.Is(err, customNetHttp.ErrServerClosed) { // Stopped on purpose (shutdown)
			return
		}
		slog.Error("HTTP server stopped: Turbo exits", "error", err) // Without :80 Turbo can't work (as above)
		_ = listener.Close()
		os.Exit(1)
	}()

	return server
}

func serverSetLogState(logType string, logFile *os.File) {
	logMutex.Lock()
	defer logMutex.Unlock()

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

func serverHandlerFn(serverType string) func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
	return func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		currentTimestamp := time.Now().Unix()
		// A request in absolute form (GET http://host/x) is served as the same one in origin form; Go already took
		// its host as r.Host. ("OPTIONS *" never gets here: Go answers it.)
		if r.RequestURI != "" && r.RequestURI[0] != '/' {
			r.RequestURI = r.URL.RequestURI()
		}

		if panelAccess.Load().hosts[requestHostName(r.Host)] { // The panel's own host: only its pages run scripts
			w.Header().Set("Content-Security-Policy", panelCSP)
		}

		clientIP := ipAddr(r.RemoteAddr)

		if status, retryAfter := rateLimited(clientIP); status != 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
			reqMsg(w, status)
			return
		}

		serverWriteLogs(visitsLogName, r, currentTimestamp, "Visit")

		// HTTP/2 may carry a host field besides :authority, which is the host Go gives and the one that chooses
		// the site: one that names another host is malformed (RFC 9113, 8.3.1), and the same one is dropped, so the
		// CGI's HTTP_HOST is always the host that chose the site.
		if hosts, present := r.Header["Host"]; present {
			delete(r.Header, "Host")
			for _, host := range hosts {
				if requestHostName(host) != requestHostName(r.Host) {
					reqMsg(w, 400)
					return
				}
			}
		}
		// The rest is as it chose the site: the host's name in lower case, without a final dot, and its port only if
		// it is a number, so that a CGI's HTTP_HOST and SERVER_NAME, and the port of a redirection, never carry what
		// the choice of the site left out ("[example.com]x", or a port with markup over HTTP/2).
		r.Host = canonicalHost(r.Host)

		// A target that doesn't start with "/" (an opaque one, such as x:@evil.com, or "*" outside OPTIONS) names no
		// file of a site, and after the host of a redirection it would change the URL: refused.
		if r.RequestURI == "" || r.RequestURI[0] != '/' {
			reqMsg(w, 400)
			return
		}

		if panelACMEChallenge(w, r) || console(w, r) {
			return
		}

		// The read lock covers only resolving the request: the file or CGI is served after releasing it, and a
		// redirect or an error written meanwhile is held and sent after it too, so a slow response, or a client
		// that doesn't read, doesn't hold back the panel nor, through its pending Lock, other requests. An ACME
		// challenge stops the first pass to have its file looked at without the lock.
		var plan *servePlan
		acme := &acmeLookup{}
		held := newHeldResponse(w)
		withReadLock(func() { plan = resolveRequest(serverType, held, r, acme) })
		if acme.path != "" && !acme.checked {
			info, err := siteDirStat(acme.path)
			acme.checked, acme.exists = true, err == nil && info.Mode().IsRegular()
			held = newHeldResponse(w)
			withReadLock(func() { plan = resolveRequest(serverType, held, r, acme) })
		}
		held.sendTo(w)
		if plan != nil {
			plan.serve(w, r)
		}
	}
}

// heldResponse is the response while the global read lock is held: what resolveRequest writes (a redirect or an
// error, both small) is kept here and written to the client after the lock is released.
type heldResponse struct {
	header customNetHttp.Header
	status int
	body   bytes.Buffer
}

func newHeldResponse(w customNetHttp.ResponseWriter) *heldResponse {
	return &heldResponse{header: w.Header().Clone()}
}

func (held *heldResponse) Header() customNetHttp.Header { return held.header }

func (held *heldResponse) WriteHeader(code int) {
	if held.status == 0 {
		held.status = code
	}
}

func (held *heldResponse) Write(p []byte) (int, error) {
	if held.status == 0 {
		held.status = customNetHttp.StatusOK
	}
	return held.body.Write(p)
}

// sendTo writes to w what was held: the headers always, and the response if one was written.
func (held *heldResponse) sendTo(w customNetHttp.ResponseWriter) {
	header := w.Header()
	clear(header)
	for name, values := range held.header {
		header[name] = values
	}
	if held.status != 0 {
		w.WriteHeader(held.status)
		_, _ = w.Write(held.body.Bytes()) // A client that went away: nothing else to do
	}
}

// acmeLookup is how resolveRequest asks for the file of an ACME challenge to be looked at without the global
// lock: it leaves the path and returns, and the second pass gets whether it exists.
type acmeLookup struct {
	path            string
	checked, exists bool
}

// resolveRequest reads what the request needs from the shared settings. It writes redirects and errors
// itself and returns nil; otherwise it returns a plan that serves the response without the lock. For an ACME
// challenge it first only notes the path of its file in acme, and returns nil. Callers hold the global read lock.
func resolveRequest(serverType string, w customNetHttp.ResponseWriter, r *customNetHttp.Request, acme *acmeLookup) *servePlan {
	var siteFound bool
	validHost, wildcardDomain, subdomain, domain := host(r.Host)

	firstDomain := domain
	firstSubdomain := subdomain
	fullHost := subdomain
	if fullHost != "" {
		fullHost += "." + domain
	} else {
		fullHost = domain
	}

	if _, siteFound = domainAliases[fullHost]; siteFound { // The target is a site key ("*.example.com"), not a Host
		validHost, wildcardDomain, subdomain, domain = hostExist(domainAliases[fullHost])
		fullHost = subdomain
		if fullHost != "" {
			fullHost += "." + domain
		} else {
			fullHost = domain
		}
	}

	if !siteFound && wildcardDomain == "" { // Reset {FIRST_SITE} & {FIRST_SUBDOMAIN} if no Alias or Wildcard
		firstDomain = ""
		firstSubdomain = ""
	}

	effectiveDomain := domain
	if wildcardDomain != "" { // Change domain & site reference if wildcard is detected
		effectiveDomain = wildcardDomain
		if subdomain != "" {
			fullHost = subdomain + "." + wildcardDomain
		} else {
			fullHost = wildcardDomain
		}
	}

	if !validHost {
		reqMsg(w, 404)
		return nil
	}

	// An ACME challenge whose file is in the site goes straight to it, so that Certbot can validate a site with a
	// front controller or redirections; without the file, everything goes on as always.
	if path := acmeChallengeFilePath(effectiveDomain, subdomain, r); path != "" {
		if !acme.checked {
			acme.path = path
			return nil
		}
		if acme.exists && acme.path == path {
			return serve(serverType, domain, effectiveDomain, subdomain, firstDomain, firstSubdomain, w, r, true)
		}
	}

	if subdomain == "" && siteSSLConfig[effectiveDomain]["W"] == true {
		redir(serverType, domain, "www", w, r, 301)
		return nil
	}

	if subdomain == "www" && siteSSLConfig[effectiveDomain]["R"] == true {
		redir(serverType, domain, "", w, r, 301)
		return nil
	}

	if serverType == "" && httpsRedirect(fullHost, w, r) {
		return nil
	}

	return serve(serverType, domain, effectiveDomain, subdomain, firstDomain, firstSubdomain, w, r, false)
}

// acmeChallengePath starts the requests of the ACME http-01 challenges.
const acmeChallengePath = "/.well-known/acme-challenge/"

// acmeChallengeFilePath returns, for an ACME challenge, where its file would be in the public folder of the site
// (domain, subdomain), where serve would look for it; "" for any other request. Whether the file is there (a
// regular one) is looked at without the lock. Callers hold the global read lock.
func acmeChallengeFilePath(domain string, subdomain string, request *customNetHttp.Request) string {
	requestPath := cutAt(request.RequestURI, '?')
	token, isChallenge := strings.CutPrefix(requestPath, acmeChallengePath)
	if !isChallenge || !acmeToken.MatchString(token) {
		return ""
	}
	wildcardMatch, _, _, wildcardDomain := detectWildcards(subdomain, domain)
	if !wildcardMatch {
		return ""
	}
	siteDir := sitesDir.Get() + changeWildcards(domain) + "/"
	if subdomain != "" {
		siteDir += changeWildcards(wildcardDomain) + "/"
	}
	return siteDir + publicDirName + acmeChallengePath + token // The token has only [A-Za-z0-9_-]
}

func resetSettings() {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	sitesMap = make(map[string]map[string]map[string]string) // Sites map & rewrites
	siteSSLConfig = make(map[string]map[string]interface{})  // Sites with SSL
	mimeTypes = make(map[string]map[string]string)           // MIME types
	customHeaders = make(map[string]map[string]string)       // Headers
	preprocessors = make(map[string]map[string]string)       // Preprocessors
	indexFiles = make(map[string]map[string]int)             // Indexes
	domainAliases = make(map[string]string)                  // Domain aliases
	dormantSites = make(map[string]map[string]string)        // Those of the new sites directory come with its configuration
	siteCertificates = make(map[string]*tls.Certificate)
	certificatesByName.Store(&map[string]*tls.Certificate{})
	panelCertificate, panelCertificateStamp = nil, "" // Read again from the new sites directory
	warnedDiskSites = make(map[string]bool)
	logMutex.Lock()
	for _, logFile := range []*os.File{visitsLogFile, denialsLogFile} {
		if logFile != nil {
			closeLog(logFile)
		}
	}
	visitsLogFile = nil
	denialsLogFile = nil
	logMutex.Unlock()
	configFileLoaded = false
}

// configFileLoaded is set when the configuration in use came from a turbo.config of the sites directory (or setM
// kept it for a directory without one), so that the file missing later keeps it instead of bringing back the
// defaults. Guarded by globalMutex.
var configFileLoaded bool

// sitesDirError is a sites directory that can't be read. Turbo doesn't start with it (its sites and their settings
// would be missing), and a reload keeps the configuration in use.
type sitesDirError struct {
	dir string
	err error
}

func (e *sitesDirError) Error() string {
	permissions := ""
	if info, err := os.Stat(e.dir); err == nil {
		permissions = " (permissions " + info.Mode().Perm().String() + ")"
	}
	return "Can't read the sites directory " + e.dir + permissions + ": " + e.err.Error() + "\n  Check that it exists and that the user running Turbo can read it."
}

// updateSettings reads turbo.config if it changed and activates the site folders found on disk. If turbo.config
// can't be read or isn't valid JSON, the configuration in use is kept and the error (a *configFileError) is
// returned; it isn't read again until the file changes.
func updateSettings(checkSitesFlag bool) error {
	settingsUpdateMutex.Lock()
	defer settingsUpdateMutex.Unlock()
	return updateSettingsFollowing(checkSitesFlag, 0, reloadOptions{})
}

// settingsUpdateMutex keeps reloads of the configuration from overlapping: the periodic one and setM's, which
// changes the sites directory in between. It is taken before globalMutex.
var settingsUpdateMutex sync.Mutex

// beforeSitesScan runs when a reload has read turbo.config and is about to activate the sites it finds on disk
// (a hook for tests).
var beforeSitesScan = func() {}

// reloadOptions are how the reload of setM reads the turbo.config of the sites directory it just chose, and how a
// reload reads the one that "M" names.
type reloadOptions struct {
	keepWithoutConfig bool          // Without a turbo.config there, the settings in use stay instead of the defaults
	ignorePointer     bool          // A turbo.config there that only points to another directory counts as none
	keepSession       string        // If the credentials change, the session that stays (the one of setM); the others end
	carried           *parsedConfig // A whole turbo.config whose "M" names that directory, without turbo.config: applied there
}

// updateSettingsFollowing is updateSettings counting how many times "M" moved it to another sites directory,
// to stop if two configs point at each other. Callers hold settingsUpdateMutex.
func updateSettingsFollowing(checkSitesFlag bool, redirects int, options reloadOptions) error {
	baseDir := sitesDir.Get()
	var lastConfigModTime int64
	withReadLock(func() { lastConfigModTime = configFileModTime })

	refreshLogFiles(baseDir)

	dirEntries, err := os.ReadDir(baseDir)
	if err != nil { // Without the sites, the defaults would leave every site and its settings out
		return &sitesDirError{dir: baseDir, err: err}
	}
	if checkSitesFlag { // Only with the sites directory readable: a disk that doesn't answer deactivates no site
		checkSites()
	}

	// Anything at the path counts as turbo.config, also a broken link or a folder: only a missing one means none.
	var configModTime int64 = 1
	if configFileInfo, err := os.Stat(baseDir + configFileName); err == nil {
		configModTime = configFileInfo.ModTime().UnixNano()
	} else if linkInfo, lerr := os.Lstat(baseDir + configFileName); lerr == nil {
		configModTime = linkInfo.ModTime().UnixNano()
	} else if !os.IsNotExist(lerr) {
		configModTime = 2 // It can't even be looked at: readSiteConfigFrom says why
	}
	if configModTime == 1 && configFileLoaded && lastConfigModTime != 1 { // It was there: keep what it said
		withGlobalLock(func() { configFileModTime = 1 })
		slog.Warn("turbo.config has disappeared: the configuration in use stays until it exists again", "file", baseDir+configFileName)
		lastConfigModTime = 1
	}
	withoutConfig := configModTime == 1
	if options.ignorePointer && !withoutConfig && lastConfigModTime != configModTime {
		if data, err := os.ReadFile(baseDir + configFileName); err == nil && isSitesDirPointer(data) { // #nosec G304 -- turbo.config of the sites directory chosen by the administrator
			slog.Info("The turbo.config of the sites directory only points to another directory: it is not followed, and saving will write the whole configuration there", "file", baseDir+configFileName)
			withoutConfig = true
		}
	}

	var configErr error
	configRead := false
	sitesActivated := false // Sites found on disk, also checked against PA
	// The whole turbo.config that named this directory, which has none of its own, applies here: its sites are these.
	carried := options.carried != nil && lastConfigModTime != configModTime && withoutConfig && options.keepWithoutConfig
	if lastConfigModTime != configModTime && withoutConfig && options.keepWithoutConfig {
		withGlobalLock(func() {
			configFileModTime = configModTime
			configFileLoaded = true // Kept as if it came from a file there
		})
		if carried {
			slog.Info("Sites directory without turbo.config: the turbo.config that names it applies here, and saving writes it here", "directory", baseDir)
		} else {
			slog.Info("Sites directory without turbo.config: the global settings, the credentials and the lists in use are kept", "directory", baseDir)
		}
	}
	readConfig := lastConfigModTime != configModTime && !(withoutConfig && options.keepWithoutConfig)
	var config parsedConfig
	if readConfig { // Read and checked before taking the lock
		config, configErr = parseSiteConfig(baseDir + configFileName)
	}
	// Every sites directory that this turbo.config leads to, through a pointer or the "M" of a whole one, must be
	// usable before anything is applied (sitesDirChainProblem): following it emptied the configuration in use first.
	// Outside setM, a pointer must lead to a configuration: applied on its own, it would leave the defaults, the
	// default credentials and an open panel included. One without "M" ({}, or only "^") points nowhere: it is an
	// empty configuration, loaded as such.
	if readConfig && configErr == nil && config.raw != nil {
		if problem := sitesDirChainProblem(config.raw, baseDir, redirects, options.keepWithoutConfig); problem != nil {
			data, _ := os.ReadFile(baseDir + configFileName) // #nosec G304 -- turbo.config of the sites directory in use, for the message
			configErr = &configFileError{path: baseDir + configFileName, data: data, err: problem}
		}
	}
	// A turbo.config that only points to another directory is followed without applying it: it has no settings,
	// and applying it would put the defaults in use until the target is read (after setM, it would empty the
	// settings in use before the target, maybe without turbo.config, keeps them).
	var pointerTarget, pointerValue string
	if readConfig && configErr == nil && config.raw != nil && isSitesDirPointerMap(config.raw) {
		if value, _ := config.raw["."]["M"].(string); value != "" {
			if resolved, err := resolveSitesDir(value); err == nil && dirExists(resolved) && !sameDir(resolved, baseDir) {
				pointerTarget, pointerValue = resolved, value
			}
		}
	}
	// A whole turbo.config whose "M" names another sites directory (checked above). With a turbo.config of its own
	// there (whole, or a pointer on to one), that one applies whole after this one. Without one, this turbo.config is
	// followed like a pointer, without applying it here, and applied there, where its sites are: applied here
	// (against that directory) and emptied when following "M", every site was left with the defaults, its scripts
	// served as text.
	var carry *parsedConfig
	if readConfig && configErr == nil && config.raw != nil && !isSitesDirPointerMap(config.raw) && redirects < 2 {
		if value, _ := config.raw["."]["M"].(string); value != "" {
			if resolved, err := resolveSitesDir(value); err == nil && dirExists(resolved) && !sameDir(resolved, baseDir) {
				if _, statErr := os.Lstat(resolved + configFileName); os.IsNotExist(statErr) {
					pointerTarget, pointerValue, carry = resolved, value, &config
				}
			}
		}
	}
	diskSites := scanDiskSites(baseDir, dirEntries)
	restoring := dormantSectionsFound(diskSites)
	var look *diskLook
	switch {
	case readConfig && configErr == nil && pointerTarget == "":
		look = lookAheadSettings(config, baseDir, diskSites, restoring)
	case carried:
		look = lookAheadSettings(*options.carried, baseDir, diskSites, restoring)
	default:
		look = lookAheadSettings(parsedConfig{}, baseDir, diskSites, restoring)
	}

	// In a single section: what came from the file is replaced and the sites found on disk are activated, so no
	// request sees a half-loaded configuration; the certificates are published once, at the end, so TLS keeps
	// answering meanwhile. What the validators look at on the disk was looked at before taking the lock.
	beforeSitesScan()
	withDiskLook(look, func() {
		if readConfig {
			configFileModTime = configModTime // Not read again until it changes, also if it is invalid
			if pointerTarget != "" {
				sitesDir.Set(pointerTarget)
				sitesDirValue.Set(pointerValue)
			} else if configErr == nil {
				certificatePublishPaused = true
				credentials := panelUser.Get() + "\x00" + panelPasswordHash.Get()
				applySiteConfig(config)
				if panelUser.Get()+"\x00"+panelPasswordHash.Get() != credentials { // As with setU and setP
					closeOtherSessions(options.keepSession)
				}
				configFileLoaded = configModTime != 1
				configFileDigest = config.digest
			}
		} else if carried {
			certificatePublishPaused = true
			credentials := panelUser.Get() + "\x00" + panelPasswordHash.Get()
			applySiteConfig(*options.carried) // Its "M" names this directory: unchanged
			if panelUser.Get()+"\x00"+panelPasswordHash.Get() != credentials {
				closeOtherSessions(options.keepSession)
			}
		}
		if sitesDir.Get() == baseDir { // Not the folders of a directory that "M" leaves: they aren't its sites
			sitesActivated = activateDiskSites(diskSites, checkSitesFlag)
			dropAliasesOfSites() // Once all the sites are in: a site wins over an alias of its host
		}
		if certificatePublishPaused {
			certificatePublishPaused = false
			publishCertificates()
		}
	})
	if readConfig && configErr == nil {
		configRead = true
		switch {
		case configModTime == 1:
			slog.Info("No turbo.config: default configuration")
		case carry != nil:
			slog.Info("turbo.config read: it applies in the sites directory that its \"M\" names, which has no turbo.config", "directory", pointerTarget)
		default:
			slog.Info("turbo.config read and applied")
		}
		if newDir := sitesDir.Get(); !sameDir(newDir, baseDir) && redirects < 2 { // "M" points elsewhere: read the config there
			slog.Info("Sites directory", "directory", newDir)
			// Without a turbo.config there, the settings just read stay, as setM keeps them, to be written there
			// with the next save; the defaults would open the panel. A whole turbo.config read here applies there.
			_, statErr := os.Lstat(newDir + configFileName)
			keep := options.keepWithoutConfig || os.IsNotExist(statErr)
			resetSettings()
			withGlobalLock(func() { configFileModTime = 0 })
			return updateSettingsFollowing(checkSitesFlag, redirects+1, reloadOptions{keepWithoutConfig: keep, keepSession: options.keepSession, carried: carry})
		}
	}
	if carried {
		configRead = true
	}

	var knownStamp string
	withReadLock(func() { knownStamp = panelCertificateStamp })
	panelLook := lookAtPanelCertificate(baseDir, knownStamp) // Read without the lock
	withGlobalLock(func() { applyPanelCertificate(baseDir, panelLook) })
	loadPendingCertificates() // Sites with HTTPS on whose certificate couldn't be loaded yet

	if configRead || sitesActivated { // After the sites on disk are activated, which PA is checked against
		withReadLock(warnPanelOrigin)
	}
	return configErr
}

// lookAheadSettings looks at the disk, before the reload takes the global lock, for what the validators will look
// at under it: the sites directory of M, the folders of each site of config, the certificate files of each site
// of config, of the disk and of restoring (the settings kept for the sites of the disk that come back; loaded when
// the site has HTTPS on) and the executables of their preprocessors.
func lookAheadSettings(config parsedConfig, baseDir string, disk []diskSite, restoring map[diskSite]map[string]interface{}) *diskLook {
	look := newDiskLook()
	if value, isString := config.raw["."]["M"].(string); isString {
		if resolved, err := resolveSitesDir(value); err == nil {
			look.stat(resolved)
		}
		if inUse, err := resolveSitesDir(sitesDir.Get()); err == nil {
			look.stat(inUse)
		}
	}
	for domain, subdomains := range config.raw {
		switch domain {
		case "_", "@", "#", ".", "^": // Not sites
			continue
		}
		look.siteFolders(baseDir, domain, "")
		for subdomain, content := range subdomains {
			if subdomain != "" {
				look.siteFolders(baseDir, domain, subdomain)
			}
			settings, _ := content.(map[string]interface{})
			look.siteSection(baseDir, domain, subdomain, settings)
		}
	}
	for _, site := range disk {
		look.siteFiles(baseDir+siteFolder(site.site, site.subdomain), false)
	}
	for site, settings := range restoring {
		look.siteSection(baseDir, site.site, site.subdomain, settings)
	}
	return look
}

// httpsSetting says whether an "S" of turbo.config turns HTTPS on, as its validator reads it: anything but 0.
func httpsSetting(value interface{}) bool {
	switch typed := value.(type) {
	case string:
		return typed != "" && typed != "0"
	case float64:
		return typed != 0
	case bool:
		return typed
	}
	return false
}

// connHandler closes new connections from an IP that is already blocked. Requests are counted, and
// answered with 429, in the handler (rateLimited).
func connHandler(conn net.Conn, connState customNetHttp.ConnState) {
	if connState != customNetHttp.StateNew {
		return
	}

	if blocked, _ := ipBlocked(ipAddr(conn.RemoteAddr().String())); blocked {
		_ = conn.Close() // Refused: whatever happens to the connection doesn't matter
	}
}

// ipBlocked reports whether the IP is denied or blocked by the limiter, and the seconds left, without
// counting a request.
func ipBlocked(ip string) (bool, int64) {
	nowUnix := time.Now().Unix() // Denials are dates, saved in turbo.config
	if until := deniedUntil(ip); until > nowUnix {
		return true, until - nowUnix
	}
	ipRef, found := ipReferences.Load(limiterKey(ip))
	if !found {
		return false, 0
	}
	ipData := ipRef.(*IPReference)
	ipData.mutex.Lock()
	defer ipData.mutex.Unlock()
	if left := ipData.blockedUntil - monotonicNow(); left > 0 {
		return true, (left + int64(time.Second) - 1) / int64(time.Second)
	}
	return false, 0
}

// rateLimited counts a request of the IP in the per-IP and global limiters. When the request must be
// rejected, it returns the status (429 for the IP, 503 for the whole server) and the seconds to send in
// Retry-After; otherwise status is 0.
func rateLimited(ip string) (status int, retryAfter int64) {
	if perIPNotAvailable(ip, true) {
		if blocked, retryAfter := ipBlocked(ip); blocked {
			return 429, retryAfter
		}
		return 429, 1
	}
	if globalRateExceeded() {
		return 503, 1
	}
	return 0, 0
}

// The limiters measure time with the monotonic clock, from the start of the process: moving the wall clock back
// (NTP, a restored virtual machine) neither blocks the clients nor stretches the windows. Denied IPs, saved as
// dates, keep the wall clock.
var (
	processStart = time.Now()
	monotonicNow = func() int64 { return int64(time.Since(processStart)) } // Nanoseconds; a variable so that tests can move it
)

// monotonicSecond is the second of the monotonic clock, aligned with the seconds of the wall clock at start.
func monotonicSecond() int64 {
	return (monotonicNow() + int64(processStart.Nanosecond())) / int64(time.Second)
}

// globalRateExceeded counts a request for the whole server and reports whether it goes over CGL in the current
// second. It doesn't blame any IP and takes no lock: a request that starts a new second resets the count.
// The windows are fixed seconds, so a burst across two of them can reach twice CGL; sharing the server among
// clients is what CII and CIS do.
func globalRateExceeded() bool {
	return globalRateExceededAt(monotonicSecond())
}

// globalRateExceededAt is globalRateExceeded for a request that read the time now. The second and its count
// change together, and only forwards: a request that read the previous second counts in the current one.
func globalRateExceededAt(now int64) bool {
	limit := globalRequestLimit.Load()
	if limit == 0 {
		return false
	}
	for {
		window := globalRequestWindow.Load()
		second, count := int64(window>>32), int64(window&0xffffffff)
		next := uint64(now)<<32 | 1 // #nosec G115 -- seconds since the process started: positive, and below 2^32 for 136 years
		if now <= second {
			if count > limit { // Already over: nothing to count, and the count can't overflow
				return true
			}
			next = window + 1
		}
		if globalRequestWindow.CompareAndSwap(window, next) {
			return int64(next&0xffffffff) > limit
		}
	}
}

// requestLimits are the per-IP limits of the panel: CIL (how long an IP's count lasts) and CIS (the window of
// CII requests) in nanoseconds, and CII in requests. The panel changes them while requests read them, so they are
// atomic; they start with the defaults of turbo.config.
type requestLimits struct{ CIL, CIS, CII atomic.Int64 }

func init() {
	serverRequestLimits.CIL.Store(10 * int64(time.Second))
	serverRequestLimits.CIS.Store(int64(time.Second))
	serverRequestLimits.CII.Store(100)
}

// The limiter keeps an entry per IP for about CIL after its last window, some 200 bytes each. ipReferenceLimit
// bounds them: beyond it, new IPs share one entry (overflowIPKey), limited as a single client, while the IPs
// already known keep theirs. A variable so that tests can lower it.
var (
	ipReferenceLimit int64 = 200000
	ipReferenceCount atomic.Int64
)

const overflowIPKey = "" // No IP has this key

// limiterKey is the key of an IP in the per-IP limiter and the failed-login limit: an IPv4 address on its own
// (also written as ::ffff:a.b.c.d), and an IPv6 address by its /64, the block a client usually gets, so that a
// client can't get a new quota from each address of it.
func limiterKey(ip string) string {
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	address = address.Unmap().WithZone("")
	if address.Is4() {
		return address.String()
	}
	prefix, _ := address.Prefix(64)
	return prefix.String()
}

// limiterReference returns the limiter entry of key, creating it if there is room, or the shared one if not.
func limiterReference(key string) *IPReference {
	if ipRef, found := ipReferences.Load(key); found { // Most requests: no entry to allocate
		return ipRef.(*IPReference)
	}
	if ipReferenceCount.Load() >= ipReferenceLimit {
		key = overflowIPKey
		if ipRef, found := ipReferences.Load(key); found {
			return ipRef.(*IPReference)
		}
	}
	ipRef, loaded := ipReferences.LoadOrStore(key, &IPReference{windowStart: monotonicNow()})
	if !loaded {
		ipReferenceCount.Add(1)
	}
	return ipRef.(*IPReference)
}

// cleanIPReferences forgets the IPs whose counting window ended more than CIL ago and that aren't blocked:
// their next request would start from zero anyway.
func cleanIPReferences() {
	now := monotonicNow()
	intervalLimit := serverRequestLimits.CIL.Load()
	ipReferences.Range(func(ip, ipRef any) bool {
		ipData := ipRef.(*IPReference)
		ipData.mutex.Lock()
		idle := now-ipData.windowStart > intervalLimit && ipData.blockedUntil <= now
		ipData.mutex.Unlock()
		if idle && ipReferences.CompareAndDelete(ip, ipRef) {
			ipReferenceCount.Add(-1)
		}
		return true
	})
}

// perIPNotAvailable counts a request of the IP (if incrementCounter) and reports whether it must be rejected:
// the IP is denied, it is blocked, or it goes over CII requests per CIS window, counted from the start of its
// count (which restarts after CIL): with t elapsed, CII × (⌊t/CIS⌋ + 1) requests are allowed, the current one
// included. Going over blocks the IP for 5 seconds.
func perIPNotAvailable(ip string, incrementCounter bool) bool {
	if deniedUntil(ip) > time.Now().Unix() { // Without the global lock, like the rest of the limiter
		return true
	}

	ipData := limiterReference(limiterKey(ip))
	ipData.mutex.Lock()
	defer ipData.mutex.Unlock()

	now := monotonicNow()
	if ipData.blockedUntil > now {
		return true
	}
	if incrementCounter {
		ipData.requestCount++
	}

	intervalLimit := serverRequestLimits.CIL.Load()
	windowLimit := serverRequestLimits.CIS.Load()
	maxRequests := serverRequestLimits.CII.Load()

	timeDiff := now - ipData.windowStart
	if timeDiff > intervalLimit || timeDiff < 0 { // A new count (a test clock may go back)
		ipData.windowStart, timeDiff = now, 0
		ipData.requestCount = 0
		if incrementCounter {
			ipData.requestCount = 1
		}
	}
	if windowLimit == 0 || maxRequests == 0 {
		return false
	}
	if ipData.requestCount > maxRequests*(timeDiff/windowLimit+1) {
		ipData.blockedUntil = now + 5*int64(time.Second)
		serverWriteLogs(denialsLogName, nil, 0, ip+" conn denial")
		return true
	}
	return false
}

// constructSiteWithoutIndex creates the entries of a site (rewrites, preprocessors, indexes, MIME types, headers and
// settings, all empty): from turbo.config, which gives it the indexes it saved. Callers hold the global lock.
func constructSiteWithoutIndex(domain string, subdomain string) {
	if _, exists := sitesMap[domain]; !exists {
		sitesMap[domain] = make(map[string]map[string]string)
	}
	sitesMap[domain][subdomain] = make(map[string]string) // Rewrites
	if subdomain != "" {
		domain = subdomain + "." + domain
	}
	preprocessors[domain] = make(map[string]string)      // Preprocessors
	indexFiles[domain] = make(map[string]int)            // Indexes
	mimeTypes[domain] = make(map[string]string)          // MIME types
	customHeaders[domain] = make(map[string]string)      // Headers
	siteSSLConfig[domain] = make(map[string]interface{}) // Site configuration
	siteSSLConfig[domain]["S"] = 0
	siteSSLConfig[domain]["C"] = false
	siteSSLConfig[domain]["R"] = false
	siteSSLConfig[domain]["W"] = false
	siteSSLConfig[domain]["E"] = ""
	siteSSLConfig[domain]["A"] = ""
}

// constructSiteLocked adds a new site (from the panel or found in the sites directory), with index.html as its
// index. Sites read from turbo.config use constructSiteWithoutIndex and keep the indexes saved there. Callers hold the
// global lock.
func constructSiteLocked(domain string, subdomain string) {
	constructSiteWithoutIndex(domain, subdomain)
	siteKey := domain
	if subdomain != "" {
		siteKey = subdomain + "." + domain
	}
	addIndex(siteKey, "index.html")
}

// addIndex appends an index to a site, after the existing ones. An index already there keeps its place.
// Callers hold the global lock.
func addIndex(siteKey string, name string) {
	if _, exists := indexFiles[siteKey][name]; exists {
		return
	}
	last := 0
	for _, position := range indexFiles[siteKey] {
		last = max(last, position)
	}
	indexFiles[siteKey][name] = last + 1
}

// orderedIndexes returns the indexes of a site in the order they are tried. Callers hold the global lock.
func orderedIndexes(siteKey string) []string {
	names := make([]string, 0, len(indexFiles[siteKey]))
	for name := range indexFiles[siteKey] {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return indexFiles[siteKey][names[i]] < indexFiles[siteKey][names[j]] })
	return names
}

// deleteSite deletes a site from the panel, with what was kept of it if its folder had gone (dormantSites): a
// folder with its name, later, is a new site.
func deleteSite(domain string, subdomain string) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	deleteSiteLocked(domain, subdomain)
	forgetDormantLocked(domain, subdomain)
}

// deleteSiteLocked is deleteSite for callers that hold the global lock. Deleting a root domain deletes its
// subdomains too, as their folders go with it.
func deleteSiteLocked(domain string, subdomain string) {
	if subdomain != "" {
		delete(sitesMap[domain], subdomain)
		if siteKeyOwner(subdomain+"."+domain, domain, subdomain) == "" { // Never what another site keeps there
			forgetSiteKey(subdomain + "." + domain)
		}
		return
	}
	subdomains := sitesMap[domain]
	delete(sitesMap, domain)
	for key := range subdomains {
		if key != "" && siteKeyOwner(key+"."+domain, domain, key) == "" {
			forgetSiteKey(key + "." + domain)
		}
	}
	if siteKeyOwner(domain, domain, "") == "" {
		forgetSiteKey(domain)
	}
}

// reservedSiteNames are the files and folders that Turbo keeps in the sites directory: a site with one of these
// names would have its folder there.
var reservedSiteNames = map[string]bool{devGUIDirName: true, certificatesDirName: true, panelCertDirName: true, configFileName: true, visitsLogName: true, denialsLogName: true}

// siteNameProblem says why the site (domain, subdomain) can't be activated, or "": a folder that Turbo keeps for
// itself (also for its subdomains), or a key that another site already has (the site "c.a.b" and the subdomain
// "c" of "a.b" would share their settings). Callers hold the global lock.
func siteNameProblem(domain string, subdomain string) string {
	if reservedSiteNames[changeWildcards(domain)] {
		return "Name reserved by Turbo: " + domain
	}
	siteKey := domain
	if subdomain != "" {
		siteKey = subdomain + "." + domain
	}
	if owner := siteKeyOwner(siteKey, domain, subdomain); owner != "" {
		return "The key " + siteKey + " already belongs to another site (" + owner + ")"
	}
	return ""
}

// newSiteProblem is siteNameProblem for a site created from the panel, which also can't take the host of an
// alias (aliases are looked up first: the site would never be served). Callers hold the global lock.
func newSiteProblem(domain string, subdomain string) string {
	siteKey := domain
	if subdomain != "" {
		siteKey = subdomain + "." + domain
	}
	if target, isAlias := domainAliases[siteKey]; isAlias {
		return siteKey + " is an alias of " + target + ": delete it first"
	}
	return siteNameProblem(domain, subdomain)
}

// siteKeyOwner returns the site (as "subdomain.domain", or the domain) other than (domain, subdomain) whose
// settings are kept under siteKey, or "". Callers hold the global lock.
func siteKeyOwner(siteKey string, domain string, subdomain string) string {
	if _, taken := sitesMap[siteKey][""]; taken && (siteKey != domain || subdomain != "") {
		return siteKey
	}
	for i := 0; i < len(siteKey); i++ {
		if siteKey[i] != '.' {
			continue
		}
		otherSubdomain, otherDomain := siteKey[:i], siteKey[i+1:]
		if otherDomain == domain && otherSubdomain == subdomain {
			continue
		}
		if _, taken := sitesMap[otherDomain][otherSubdomain]; taken {
			return otherSubdomain + "." + otherDomain
		}
	}
	return ""
}

// warnedDiskSites are the site folders found on disk that can't be activated, already logged once. Guarded by
// globalMutex.
var warnedDiskSites = make(map[string]bool)

// dropAliasesOfSites removes, with a warning, the aliases whose host a site serves: the site wins. Callers hold
// the global lock.
func dropAliasesOfSites() {
	for _, alias := range sortedKeys(domainAliases) {
		if served, _, _, _ := hostExist(alias); served {
			slog.Warn("Alias discarded: its host is a site's", "alias", alias, "site", domainAliases[alias])
			delete(domainAliases, alias)
		}
	}
}

// forgetSiteKey removes the settings and the certificate of a site key, and the aliases that point to it.
// Callers hold the global lock.
func forgetSiteKey(siteKey string) {
	setSiteCertificate(siteKey, nil)
	delete(preprocessors, siteKey)
	delete(indexFiles, siteKey)
	delete(siteSSLConfig, siteKey)
	delete(mimeTypes, siteKey)
	delete(customHeaders, siteKey)
	for alias, target := range domainAliases {
		if target == siteKey {
			delete(domainAliases, alias)
		}
	}
}

// checkSites deactivates the sites whose folder, or its public folder (@), is gone, keeping their settings for
// when it comes back (keepDormantLocked). Callers have checked that the sites directory can be read: if it can't,
// the disk says nothing about the sites.
func checkSites() {
	type activeSite struct{ subdomain, domain string }
	var active []activeSite
	withReadLock(func() { // Only the names: the disk is looked at without the lock
		for domain := range sitesMap {
			for subdomain := range sitesMap[domain] {
				active = append(active, activeSite{subdomain, domain})
			}
		}
	})

	var missing []activeSite
	for _, site := range active {
		if siteFolderGoneWith(siteDirStat, site.domain, site.subdomain) {
			missing = append(missing, site)
		}
	}

	beforeMissingSitesDeleted()
	for _, site := range missing {
		deleted := false
		withGlobalLock(func() {
			if !siteExists(site.domain, site.subdomain) { // Deleted meanwhile
				return
			}
			// Looked at again holding the lock, which hardUpload holds while it swaps @ for the uploaded files,
			// between two renames during which @ isn't there: the site stays active. Only for a site that is
			// missing, rarely: the disk of every site is looked at above, without the lock.
			if !siteFolderGoneWith(siteDirStat, site.domain, site.subdomain) {
				return
			}
			keepDormantLocked(site.domain, site.subdomain)
			deleteSiteLocked(site.domain, site.subdomain)
			deleted = true
		})
		if !deleted {
			continue
		}

		name := site.domain
		if site.subdomain != "" {
			name = site.subdomain + "." + site.domain
		}
		slog.Info("Site folder gone: the site is deactivated, and its settings are kept for when the folder comes back", "site", name)
	}
}

// siteFolderGoneWith reports, looking with stat, whether the folder of a site or its public folder (@) is no
// longer there: it doesn't exist, or isn't a folder. Any other error (permissions, I/O, a network disk that
// doesn't answer) says nothing about the site, which is left as it is.
func siteFolderGoneWith(stat func(string) (os.FileInfo, error), domain string, subdomain string) bool {
	folder := sitesDir.Get() + siteFolder(domain, subdomain)
	for _, path := range []string{strings.TrimSuffix(folder, "/"), folder + publicDirName} {
		info, err := stat(path)
		if err != nil {
			return errors.Is(err, fs.ErrNotExist)
		}
		if !info.IsDir() {
			return true
		}
	}
	return false
}

// keepDormantLocked keeps the settings of a site whose folder is gone (for a domain, also those of its
// subdomains, whose folders go with it), as turbo.config has them, before it is deactivated: they come back with
// its folder, instead of the defaults (with which its scripts were served as text), and saving keeps them in
// turbo.config. Callers hold the global lock.
func keepDormantLocked(domain string, subdomain string) {
	subdomains := []string{subdomain}
	if subdomain == "" {
		subdomains = sortedKeys(sitesMap[domain])
	}
	for _, sub := range subdomains {
		if _, active := sitesMap[domain][sub]; active {
			setDormantLocked(domain, sub, createSubdomainData(domain, sub))
		}
	}
}

// keepDormantFromFile keeps, for a site of the turbo.config being applied whose folder or public folder isn't
// there, or can't be looked at (for a domain, with its subdomains), its section, to be applied when the folder can
// be used; saving keeps it in turbo.config. Any error of the disk counts: permissions, I/O or a network disk that
// doesn't answer say nothing about the site, which, readable again, would otherwise come from the disk with the
// defaults (its scripts served as text). A name that can't be a site's, or a folder and an @ that are there (the
// check of the site logs why it can't be used), keeps nothing. Callers hold the global lock, within
// applySiteConfig.
func keepDormantFromFile(domain string, subdomain string) {
	name := domain
	if subdomain != "" {
		name = subdomain + "." + changeWildcards(domain, "x")
	}
	if valid, _ := hostOk(name, false); !valid || reservedSiteNames[changeWildcards(domain)] || siteFolderPresentWith(diskStat, domain, subdomain) {
		return
	}
	subdomains := []string{subdomain}
	if subdomain == "" {
		subdomains = sortedKeys(rawConfigMap[domain])
	}
	for _, sub := range subdomains {
		section, isMap := rawConfigMap[domain][sub].(map[string]interface{})
		if _, content := subdomainContentCheckers[sub]; content || !isMap {
			continue
		}
		if sub != "" {
			if valid, _ := hostOk(sub+"."+changeWildcards(domain, "x"), false); !valid {
				continue
			}
		}
		setDormantLocked(domain, sub, jsonSection(section))
	}
	slog.Info("turbo.config site whose folder isn't there or can't be read: its settings apply when it can be used", "site", domain, "subdomain", subdomain)
}

// siteFolderPresentWith reports, looking with stat, whether the folder of a site and its public folder (@) are both
// there as folders.
func siteFolderPresentWith(stat func(string) (os.FileInfo, error), domain string, subdomain string) bool {
	folder := sitesDir.Get() + siteFolder(domain, subdomain)
	for _, path := range []string{strings.TrimSuffix(folder, "/"), folder + publicDirName} {
		if info, err := stat(path); err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

// jsonSection is the JSON of a site's section of turbo.config as it was read, keys in byte order.
func jsonSection(section map[string]interface{}) string {
	var builder strings.Builder
	encoder := json.NewEncoder(&builder)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(section) != nil { // Decoded from JSON: it always encodes
		return "{}"
	}
	return strings.TrimSuffix(builder.String(), "\n")
}

// setDormantLocked keeps the section of turbo.config of an inactive site. Callers hold the global lock.
func setDormantLocked(domain string, subdomain string, section string) {
	if dormantSites[domain] == nil {
		dormantSites[domain] = make(map[string]string)
	}
	dormantSites[domain][subdomain] = section
}

// forgetDormantLocked drops what is kept of a site (for a domain, also of its subdomains): one created or
// deleted from the panel starts anew. Callers hold the global lock.
func forgetDormantLocked(domain string, subdomain string) {
	if subdomain == "" {
		delete(dormantSites, domain)
		return
	}
	delete(dormantSites[domain], subdomain)
	if len(dormantSites[domain]) == 0 {
		delete(dormantSites, domain)
	}
}

// restoreDormantLocked activates a site whose folder is back with the settings kept for it, applied as when
// turbo.config is read. Callers hold the global lock.
func restoreDormantLocked(domain string, subdomain string, kept string) {
	delete(dormantSites[domain], subdomain) // Only this one: its subdomains come back with their own folders
	if len(dormantSites[domain]) == 0 {
		delete(dormantSites, domain)
	}
	var settings map[string]interface{}
	if json.Unmarshal([]byte(kept), &settings) != nil { // Written by Turbo: it always decodes
		constructSiteLocked(domain, subdomain)
		return
	}
	constructSiteWithoutIndex(domain, subdomain)
	for _, settingKey := range subdomainContentOrder {
		if value, present := settings[settingKey]; present {
			subdomainContentCheckers[settingKey](false, value, true, domain, subdomain)
		}
	}
}

// dormantSectionsFound returns, decoded, the settings kept for the inactive sites among those found on disk, which
// activating them restores: the reload looks at their files before taking the lock, as it does for turbo.config's.
func dormantSectionsFound(found []diskSite) map[diskSite]map[string]interface{} {
	var sections map[diskSite]map[string]interface{}
	withReadLock(func() {
		for _, site := range found {
			kept, dormant := dormantSites[site.site][site.subdomain]
			if !dormant || siteExists(site.site, site.subdomain) {
				continue
			}
			var settings map[string]interface{}
			if json.Unmarshal([]byte(kept), &settings) == nil {
				if sections == nil {
					sections = make(map[diskSite]map[string]interface{})
				}
				sections[site] = settings
			}
		}
	})
	return sections
}

// beforeMissingSitesDeleted runs when checkSites has found sites missing on disk and is about to deactivate them
// (a hook for tests).
var beforeMissingSitesDeleted = func() {}

// httpsEnabled reports whether the site has HTTPS redirection on. A host that isn't a configured site has none.
func httpsEnabled(siteKey string) bool {
	certIndex, isSet := siteSSLConfig[siteKey]["S"].(int)
	return isSet && certIndex != 0
}

// redir redirects to the same request on subdomain.host, keeping the scheme and the port of the Host header.
func redir(schemeSuffix string, host string, subdomain string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, statusCode int) {
	if subdomain != "" {
		subdomain += "."
	}
	port := ""
	if _, hostPort, err := net.SplitHostPort(request.Host); err == nil {
		port = ":" + hostPort
	}
	customNetHttp.Redirect(responseWriter, request, "http"+schemeSuffix+"://"+subdomain+host+port+request.RequestURI, statusCode)
}

// httpsPortSuffix is ":<port>" of TURBO_HTTPS_ADDR for the redirections to HTTPS, or "" for the default 443.
func httpsPortSuffix() string {
	if _, port, err := net.SplitHostPort(httpsAddr); err == nil && port != "443" {
		return ":" + port
	}
	return ""
}

// servePlan is what serving a request needs from the shared settings, copied under the read lock.
type servePlan struct {
	root          string            // Content directory of the site
	path          string            // Rewritten path
	queryString   string            // Query added by the rewrite (for CGI)
	indexes       []string          // Index file names
	headers       map[string]string // Site headers, for the files and CGI responses it serves
	mimeTypes     map[string]string // MIME types by extension
	preprocessors map[string]string // Preprocessors by extension
}

// cloneOrNil copies a site map, or returns nil for an empty one to save the allocation.
func cloneOrNil(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	return maps.Clone(values)
}

func serve(serverType string, host string, domain string, subdomain string, firstDomain string, firstSubdomain string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, acmeChallenge bool) *servePlan {
	wildcardMatch, _, _, wildcardDomain := detectWildcards(subdomain, domain)

	if !wildcardMatch {
		reqMsg(responseWriter, 404)
		return nil
	}

	if serverType == "" && subdomain != "" && !acmeChallenge && httpsRedirect(wildcardDomain+"."+domain, responseWriter, request) {
		return nil
	}

	var continueServe bool
	var rewrittenPath, queryString string
	if acmeChallenge { // Neither redirections nor rewrites: the file of the challenge, as it is
		rewrittenPath, continueServe = cleanRequestPath(cutAt(request.RequestURI, '?'))
	} else {
		rewrittenPath, queryString, continueServe = choose(responseWriter, request, host, domain, wildcardDomain, subdomain, firstDomain, firstSubdomain)
	}
	if !continueServe {
		return nil
	}

	// The content directory, and the key of the site's settings ("sub.example.com", or "example.com" for the domain)
	root := sitesDir.Get() + changeWildcards(domain) + "/"
	siteKey := domain
	if subdomain != "" {
		root += changeWildcards(wildcardDomain) + "/" + publicDirName
		siteKey = wildcardDomain + "." + domain
	} else {
		root += publicDirName
	}

	plan := &servePlan{
		root:          root,
		path:          rewrittenPath,
		queryString:   queryString,
		mimeTypes:     cloneOrNil(mimeTypes[siteKey]),
		preprocessors: cloneOrNil(preprocessors[siteKey]),
		headers:       cloneOrNil(customHeaders[siteKey]),
	}
	if len(indexFiles[siteKey]) > 0 {
		plan.indexes = orderedIndexes(siteKey)
	}

	return plan
}

// serve answers with the file of the plan, or runs its preprocessor, without the global lock. Files are looked
// up and opened through an os.Root of the site's content directory, so that nothing outside it is reached, not
// even through a symbolic link. The file is opened once and served from that handle.
func (plan *servePlan) serve(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	rewrittenPath := plan.path
	contentRoot, err := os.OpenRoot(plan.root)
	if err != nil {
		reqMsg(responseWriter, 404)
		return
	}
	defer contentRoot.Close()
	opened := &openedFileFS{root: contentRoot.FS()}
	defer opened.close()
	fileInfo, err := opened.open(rootName(rewrittenPath))
	if err != nil || (!fileInfo.IsDir() && strings.HasSuffix(rewrittenPath, "/")) { // "x.php/" names no folder: its extension would be lost
		reqMsg(responseWriter, 404)
		return
	}

	if fileInfo.IsDir() {
		trailingSlash := "/"
		if rewrittenPath == trailingSlash || rewrittenPath[len(rewrittenPath)-1] == '/' {
			trailingSlash = ""
		}
		indexFile := " " // Hide default indexes when indexFiles is empty

		for _, indexName := range plan.indexes {
			indexFile = trailingSlash + indexName
			indexInfo, err := opened.open(rootName(rewrittenPath + indexFile))
			if err == nil && !indexInfo.IsDir() {
				rewrittenPath += indexFile
				indexFile = ""
				break
			}
		}

		if indexFile != "" {
			reqMsg(responseWriter, 404)
			return
		}
	}

	extension := ext(rewrittenPath)
	responseHeaders := responseWriter.Header()
	for name, value := range plan.headers {
		responseHeaders.Set(name, value)
	} // The site's headers, only for what is served

	if preprocessor := plan.preprocessors[extension]; preprocessor != "" { // Verify preprocessors
		executable, problem := preprocessorCommand(preprocessor)
		if problem == "" {
			if info, err := os.Stat(executable); err != nil || info.IsDir() {
				problem = "the executable does not exist or is a folder"
			}
		}
		if problem != "" { // Fail closed: never serve the source of a preprocessed file
			if missingPreprocessorLogDue(plan.root + "|" + extension) {
				slog.Error("Preprocessor unavailable (reported once a minute)", "site", plan.root, "extension", extension, "reason", problem, "preprocessor", strings.TrimPrefix(preprocessor, invalidPreprocessorMark))
			}
			reqMsg(responseWriter, 500)
			return
		}
		opened.close() // The CGI opens the script itself
		dynamic(plan.root, rewrittenPath, plan.queryString, executable, responseWriter, request)
		return
	}

	if mimeType, found := plan.mimeTypes[extension]; found {
		responseHeaders.Set(contentTypeHeader, mimeType)
	}
	customNetHttp.ServeFileFS(responseWriter, request, opened, rootName(rewrittenPath))
}

// Missing preprocessors are logged at most once a minute per site and extension: each request to that extension
// would add a line otherwise.
var (
	missingPreprocessorMutex  sync.Mutex
	missingPreprocessorLogged = make(map[string]int64) // Site root and extension -> monotonic time of the last line
)

// missingPreprocessorLogDue reports whether the missing preprocessor of key should be logged now.
func missingPreprocessorLogDue(key string) bool {
	now := monotonicNow()
	missingPreprocessorMutex.Lock()
	defer missingPreprocessorMutex.Unlock()
	if last, found := missingPreprocessorLogged[key]; found && now-last < int64(time.Minute) {
		return false
	}
	if len(missingPreprocessorLogged) > 10000 { // Bounded: forgotten all at once, at worst one more line each
		clear(missingPreprocessorLogged)
	}
	missingPreprocessorLogged[key] = now
	return true
}

// openedFileFS is the fs.FS that serve hands to ServeFileFS: it gives back the file already opened through the
// site's os.Root, so that ServeFileFS doesn't look it up and open it again, and opens any other name through the
// Root.
type openedFileFS struct {
	root fs.FS
	name string
	file fs.File
}

// open opens name through the Root, keeping it (and closing the one kept before), and returns its information.
func (opened *openedFileFS) open(name string) (fs.FileInfo, error) {
	opened.close()
	file, err := opened.root.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close() // #nosec G104 -- it is discarded: the error that matters is Stat's
		return nil, err
	}
	opened.name, opened.file = name, file
	return info, nil
}

// Open hands over the kept file once, for whoever opens it to close it.
func (opened *openedFileFS) Open(name string) (fs.File, error) {
	if file := opened.file; file != nil && name == opened.name {
		opened.file = nil
		return file, nil
	}
	return opened.root.Open(name)
}

// close closes the kept file, if it wasn't handed over.
func (opened *openedFileFS) close() {
	if opened.file != nil {
		opened.file.Close() // #nosec G104 -- read-only file
		opened.file = nil
	}
}

// rootName turns a clean request path ("/a/b") into a name inside an os.Root ("a/b", or "." for "/").
func rootName(requestPath string) string {
	if name := strings.Trim(requestPath, "/"); name != "" {
		return name
	}
	return "."
}

func dynamic(basePath string, requestPath string, queryString string, scriptPath string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	handler := new(customNetHttp.CgiHandler)
	handler.Path = scriptPath
	handler.Logger = cgiErrorLog                             // Counted as the connections' errors: one per request a client could make
	handler.Timeout = serverTimeLimits.Load().WT             // Zero (no write timeout) leaves the CGI without limit
	handler.Env = append(handler.Env, "REDIRECT_STATUS=CGI") // PHP refuses to run as a CGI without it while cgi.force_redirect is on (the default)
	handler.InheritEnv = cgiTempVariables
	if request.ContentLength > maxBodySize.Load() {
		reqMsg(responseWriter, 413)
		return
	}
	// The body is read whole, up to MBB, before the CGI takes a slot and starts: a client that sends it slowly, or
	// not at all, holds no slot (with the network body, the CGI waited for it until RT), and a CGI always gets
	// CONTENT_LENGTH (chunked, or HTTP/2 without Content-Length). It reaches the CGI through a pipe.
	request.Body = customNetHttp.MaxBytesReader(responseWriter, request.Body, maxBodySize.Load())
	body, size, cleanup, err := bufferedRequestBody(request.Body)
	if err != nil {
		var tooLarge *customNetHttp.MaxBytesError
		if errors.As(err, &tooLarge) {
			reqMsg(responseWriter, 413)
		} else {
			reqMsg(responseWriter, 400)
		}
		return
	}
	defer cleanup()
	request.Body, request.ContentLength, request.TransferEncoding = body, size, nil
	if !acquireCGISlot(cgiSlotWait) { // Too many CGIs running: the server stays responsive
		responseWriter.Header().Set("Retry-After", "2")
		reqMsg(responseWriter, 503)
		return
	}
	// The CGI's output waits in output for the client (newCGIOutput), so that the CGI, done, frees its slot at once,
	// however slowly the client reads: holding it until the client had read everything let a few clients that don't
	// read keep every slot, and every site's CGIs answered 503.
	output := newCGIOutput(cgiResponseWriter{responseWriter})
	slotHeld, completed := true, false
	defer func() {
		if completed {
			output.finish() // What is left reaches the client, the slot already free
		} else {
			output.abort() // Cut (the client went away, or WT ran out): nothing more is written
		}
		if slotHeld {
			releaseCGISlot()
		}
	}()
	withoutSessionCookie(request)
	// A header with "_" in its name becomes the same variable as the one with "-" (X_Forwarded_For and
	// X-Forwarded-For are both HTTP_X_FORWARDED_FOR), and the client's could win over what a proxy in front set: as
	// Apache does, they don't reach the CGI.
	for name := range request.Header {
		if strings.IndexByte(name, '_') != -1 {
			delete(request.Header, name)
		}
	}
	if request.URL.RawQuery != "" && queryString != "" {
		queryString = request.URL.RawQuery + "&" + queryString
	} else if request.URL.RawQuery != "" {
		queryString = request.URL.RawQuery
	}
	// The client's query goes first and the rewrite's after it: an application that reads the last value of a
	// repeated parameter (PHP does) gets the rewrite's.
	handler.Env = append(handler.Env, "QUERY_STRING="+queryString) // If not set, not includes rewrite query string
	handler.Env = append(handler.Env, "DOCUMENT_ROOT="+basePath)
	handler.Env = append(handler.Env, "SCRIPT_FILENAME="+basePath+requestPath)
	// The script's URL path, after the rewrite, and no extra path: what the handler derives from Root is a path on
	// disk, which an application would show (PHP_SELF) or put in its links. REQUEST_URI stays the original one.
	handler.Env = append(handler.Env, "SCRIPT_NAME="+requestPath, "PATH_INFO=")
	if handler.Timeout > 0 {
		// The connection's write deadline (WT from the end of the request) would pass right when the CGI is cut:
		// moved 2 s after the CGI's own, which starts now (not before the body was read nor a slot was free), the 504
		// of a CGI that runs out of time reaches the client.
		_ = customNetHttp.NewResponseController(responseWriter).SetWriteDeadline(time.Now().Add(handler.Timeout + 2*time.Second)) // Not supported only by test writers
	}
	handler.ServeHTTP(output, request)
	completed = true
	releaseCGISlot() // The CGI has ended: its slot is free while its output reaches the client
	slotHeld = false
}

// How much of a CGI's output may wait for its client: in memory, cgiOutputMemory per response and cgiOutputBudget for
// all of them; beyond, in a temporary file, cgiOutputFileMax per response and cgiOutputFileBudget for all of them.
// Within them a CGI never waits for its client, so it ends, and frees its slot, as soon as it is done; beyond them
// it waits for its client, as it did writing straight to it (as nginx's FastCGI buffers do).
const (
	cgiOutputMemory     = 1 << 20
	cgiOutputBudget     = 64 << 20
	cgiOutputFileMax    = 256 << 20
	cgiOutputFileBudget = 1 << 30
)

// cgiOutputInUse and cgiOutputFilesInUse are what the outputs of the CGIs take, in memory and in temporary files,
// while they wait for their clients.
var cgiOutputInUse, cgiOutputFilesInUse atomic.Int64

// cgiOutput is the ResponseWriter a CGI writes to: the headers go to the client's writer at once, and the body is
// kept (in memory, then in a temporary file) and sent by a goroutine of its own, so that a client that reads slowly,
// or not at all, doesn't hold the CGI (with its slot). Writing to the client fails when it goes away or when WT runs
// out; then the CGI's next write fails too, and the CGI handler ends it.
type cgiOutput struct {
	customNetHttp.ResponseWriter // cgiResponseWriter: the headers the CGI may set, and the client's writer

	mutex       sync.Mutex
	more        *sync.Cond  // Signals a new chunk, the end, or that something was sent
	chunks      [][]byte    // In memory, waiting to be sent, in order; all of them before what is in file
	pending     int         // Bytes in chunks
	file        *os.File    // Where the output goes once the memory is full, until all of it is sent
	fileRead    int64       // What of file was sent
	fileWritten int64       // What of file was written
	noFile      bool        // The temporary file couldn't be used: beyond the memory, the CGI waits
	flushing    bool        // A Flush was asked: done after what was written before it
	closed      bool        // The CGI is done (or cut): nothing more comes
	err         error       // Writing to the client failed, or the response was cut
	sending     bool        // The sender is running
	cut         atomic.Bool // The response was cut: the sender stops between two writes
	done        chan struct{}
}

// errCGIOutputCut is the error of a CGI's write once its response was cut.
var errCGIOutputCut = errors.New("the response was cut")

func newCGIOutput(w customNetHttp.ResponseWriter) *cgiOutput {
	output := &cgiOutput{ResponseWriter: w, done: make(chan struct{})}
	output.more = sync.NewCond(&output.mutex)
	return output
}

// Write keeps a copy of p to be sent: in memory while this response and all of them are within their limits (a
// response with nothing waiting always gets a chunk in), else at the end of its temporary file, while within its
// limits; else it waits until the client takes some.
func (output *cgiOutput) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	size := int64(len(p))
	output.mutex.Lock()
	defer output.mutex.Unlock()
	for {
		if output.err != nil {
			return 0, output.err
		}
		inFile := output.fileWritten - output.fileRead
		if inFile == 0 && (output.pending == 0 || output.pending+len(p) <= cgiOutputMemory && cgiOutputInUse.Load()+size <= cgiOutputBudget) {
			output.chunks = append(output.chunks, append([]byte(nil), p...)) // io.Copy reuses its buffer
			output.pending += len(p)
			cgiOutputInUse.Add(size)
			break
		}
		if !output.noFile && inFile+size <= cgiOutputFileMax && cgiOutputFilesInUse.Load()+size <= cgiOutputFileBudget && output.spill(p) {
			break
		}
		output.more.Wait()
	}
	if !output.sending {
		output.sending = true
		go output.send()
	}
	output.more.Broadcast()
	return len(p), nil
}

// spill writes p at the end of the temporary file, creating it the first time, and reports whether it could.
// Callers hold output.mutex (the sender reads another part of the file meanwhile).
func (output *cgiOutput) spill(p []byte) bool {
	if output.file == nil {
		file, err := os.CreateTemp("", "turbo-cgi-output-*") // 0600, in Turbo's temporary folder
		if err != nil {
			output.noFile = true
			return false
		}
		output.file = file
	}
	if _, err := output.file.WriteAt(p, output.fileWritten); err != nil {
		output.noFile = true
		return false
	}
	output.fileWritten += int64(len(p))
	cgiOutputFilesInUse.Add(int64(len(p)))
	return true
}

// Flush asks for what was written so far to be flushed to the client once it is sent.
func (output *cgiOutput) Flush() {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	output.flushing = true
	if !output.sending {
		output.sending = true
		go output.send()
	}
	output.more.Broadcast()
}

// Unwrap lets NewResponseController reach the server's ResponseWriter.
func (output *cgiOutput) Unwrap() customNetHttp.ResponseWriter {
	return output.ResponseWriter
}

// send writes the output to the client in order, the memory first and then the file, until the CGI is done and
// all of it is sent, or writing fails.
func (output *cgiOutput) send() {
	defer close(output.done)
	buffer := make([]byte, 32<<10)
	for {
		output.mutex.Lock()
		for len(output.chunks) == 0 && output.fileWritten == output.fileRead && !output.flushing && !output.closed && output.err == nil {
			output.more.Wait()
		}
		if output.err != nil || (len(output.chunks) == 0 && output.fileWritten == output.fileRead && !output.flushing && output.closed) {
			output.mutex.Unlock()
			return
		}
		chunks, flush := output.chunks, output.flushing
		output.chunks, output.pending, output.flushing = nil, 0, false // Taken: cgiOutputInUse still counts them until sent
		var fromFile int64                                             // With the memory sent, the next part of the file
		if len(chunks) == 0 {
			fromFile = min(output.fileWritten-output.fileRead, int64(len(buffer)))
		}
		file, readAt := output.file, output.fileRead
		output.mutex.Unlock()

		var err error
		for _, chunk := range chunks {
			if err == nil && output.cut.Load() {
				err = errCGIOutputCut
			}
			if err == nil {
				_, err = output.ResponseWriter.Write(chunk)
			}
			cgiOutputInUse.Add(-int64(len(chunk)))
		}
		if err == nil && fromFile > 0 && !output.cut.Load() {
			read, readErr := file.ReadAt(buffer[:fromFile], readAt)
			if read > 0 {
				_, err = output.ResponseWriter.Write(buffer[:read])
			}
			if err == nil && readErr != nil && !errors.Is(readErr, io.EOF) {
				err = readErr
			}
			output.mutex.Lock()
			if output.err == nil { // Not dropped meanwhile (dropLocked counted it already)
				output.fileRead += int64(read)
				cgiOutputFilesInUse.Add(-int64(read))
				if output.fileRead == output.fileWritten { // All of the file sent: it is used again from the start
					output.fileRead, output.fileWritten = 0, 0
					_ = output.file.Truncate(0)
				}
			}
			output.mutex.Unlock()
		}
		if err == nil && flush {
			err = customNetHttp.NewResponseController(output.ResponseWriter).Flush()
			if errors.Is(err, customNetHttp.ErrNotSupported) {
				err = nil
			}
		}
		output.mutex.Lock()
		if err != nil && output.err == nil {
			output.err = err
			output.dropLocked()
		}
		output.more.Broadcast()
		output.mutex.Unlock()
	}
}

// dropLocked forgets what wasn't sent, in memory and in the file. Callers hold output.mutex.
func (output *cgiOutput) dropLocked() {
	for _, chunk := range output.chunks {
		cgiOutputInUse.Add(-int64(len(chunk)))
	}
	output.chunks, output.pending = nil, 0
	cgiOutputFilesInUse.Add(-(output.fileWritten - output.fileRead))
	output.fileRead, output.fileWritten = 0, 0
}

// end waits until the sender stops, and removes the temporary file.
func (output *cgiOutput) end() {
	output.mutex.Lock()
	sending := output.sending
	output.more.Broadcast()
	output.mutex.Unlock()
	if sending {
		<-output.done
	}
	output.mutex.Lock()
	defer output.mutex.Unlock()
	output.dropLocked() // Nothing is left after a sender that finished; after one that failed, what it didn't send
	if output.file != nil {
		_ = output.file.Close()
		_ = os.Remove(output.file.Name())
		output.file = nil
	}
}

// finish waits until all the output is sent, or writing to the client failed: the CGI is done.
func (output *cgiOutput) finish() {
	output.mutex.Lock()
	output.closed = true
	output.mutex.Unlock()
	output.end()
}

// abort drops what wasn't sent and waits until the sender stops writing: the response was cut, and the handler,
// which owns the client's writer, is about to end.
func (output *cgiOutput) abort() {
	output.cut.Store(true)
	output.mutex.Lock()
	output.closed = true
	if output.err == nil {
		output.err = errCGIOutputCut
	}
	output.dropLocked()
	output.mutex.Unlock()
	output.end()
}

// cgiTempVariables are the variables of the temporary folder that a CGI inherits from Turbo, when they are set:
// PHP keeps uploads and sessions there (without them, on Windows, it fell back to the Windows folder).
var cgiTempVariables = []string{"TMPDIR", "TEMP", "TMP"}

// cgiResponseWriter is what a CGI's answer is written to. How the response is framed is the server's: the
// hop-by-hop headers a CGI may write (Transfer-Encoding, Connection and the like) are dropped, and so is a
// Content-Length given more than once, which would leave the client, or a proxy, unable to tell where the
// response ends, and a header value with control characters, which would make it unreadable.
type cgiResponseWriter struct {
	customNetHttp.ResponseWriter
}

// cgiHopByHopHeaders are the headers about the connection, not the content, that a CGI can't set.
var cgiHopByHopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Transfer-Encoding", "Upgrade"}

func (w cgiResponseWriter) WriteHeader(code int) {
	header := w.Header()
	for _, name := range cgiHopByHopHeaders {
		header.Del(name)
	}
	if lengths := header.Values("Content-Length"); len(lengths) > 1 || len(lengths) == 1 && !onlyDigits(lengths[0]) {
		header.Del("Content-Length") // Go takes "+4" or "-0" as a number, but would send it as written
	}
	for name, values := range header {
		kept := values[:0]
		for _, value := range values {
			if headerValueAllowed(value) {
				kept = append(kept, value)
			}
		}
		if len(kept) == 0 {
			delete(header, name)
		} else {
			header[name] = kept
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

// onlyDigits says whether a text is one or more ASCII digits.
func onlyDigits(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return false
		}
	}
	return text != ""
}

// headerValueAllowed says whether a header value can go in a response: no control characters but the tab (bytes
// above 0x7f, the obs-text of HTTP, are allowed).
func headerValueAllowed(value string) bool {
	for i := 0; i < len(value); i++ {
		if c := value[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// Unwrap lets NewResponseController reach the server's ResponseWriter.
func (w cgiResponseWriter) Unwrap() customNetHttp.ResponseWriter {
	return w.ResponseWriter
}

// cgiBodyMemory is how much of a body of unknown length is kept in memory for a CGI; the rest goes to a temporary
// file.
const cgiBodyMemory = 1 << 20

// cgiFileBody is a body kept in a temporary file, as the CGI gets it: not an *os.File, so that exec hands it over
// through a pipe. The CGI, and what it starts, never inherit the file, which on Windows couldn't be removed while
// one of them kept it open. Closing it is cleanup's.
type cgiFileBody struct{ io.Reader }

func (cgiFileBody) Close() error { return nil }

// bufferedRequestBody reads a request body, already bounded by MBB, before the CGI starts, so that the CGI gets
// CONTENT_LENGTH and doesn't wait for the client: in memory up to cgiBodyMemory, and in a temporary file beyond.
// cleanup closes and removes that file.
func bufferedRequestBody(body io.Reader) (io.ReadCloser, int64, func(), error) {
	var memory bytes.Buffer
	size, err := io.CopyN(&memory, body, cgiBodyMemory+1)
	if err == io.EOF {
		return io.NopCloser(&memory), size, func() {}, nil
	}
	if err != nil {
		return nil, 0, nil, err
	}
	file, err := os.CreateTemp("", "turbo-cgi-*")
	if err != nil {
		return nil, 0, nil, err
	}
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}
	if size, err = io.Copy(file, io.MultiReader(&memory, body)); err == nil {
		_, err = file.Seek(0, io.SeekStart)
	}
	if err != nil {
		cleanup()
		return nil, 0, nil, err
	}
	return cgiFileBody{file}, size, cleanup, nil
}

// cgiSlotWait is how long a CGI request waits for a free slot before getting 503.
const cgiSlotWait = 2 * time.Second

// cgiSlots counts the CGI processes running; freed is closed (and replaced) each time one ends.
var cgiSlots struct {
	mutex   sync.Mutex
	running int64
	freed   chan struct{}
}

// cgiProcessLimit is how many CGI processes may run at a time: CGP, or max(16, 4 × CPUs) with CGP at 0.
func cgiProcessLimit() int64 {
	if limit := cgiProcesses.Load(); limit > 0 {
		return limit
	}
	return max(16, 4*int64(runtime.NumCPU()))
}

// acquireCGISlot takes a CGI slot, waiting up to wait for one; it reports whether it got it.
func acquireCGISlot(wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		cgiSlots.mutex.Lock()
		if cgiSlots.running < cgiProcessLimit() {
			cgiSlots.running++
			cgiSlots.mutex.Unlock()
			return true
		}
		if cgiSlots.freed == nil {
			cgiSlots.freed = make(chan struct{})
		}
		freed := cgiSlots.freed
		cgiSlots.mutex.Unlock()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		timer := time.NewTimer(remaining)
		select {
		case <-freed:
			timer.Stop()
		case <-timer.C:
			return false
		}
	}
}

// releaseCGISlot gives back the slot of a CGI that ended.
func releaseCGISlot() {
	cgiSlots.mutex.Lock()
	defer cgiSlots.mutex.Unlock()
	cgiSlots.running--
	if cgiSlots.freed != nil {
		close(cgiSlots.freed)
		cgiSlots.freed = nil
	}
}

// withoutSessionCookie removes the panel session cookie from the request, so a CGI never receives it. Only that
// pair is cut from the raw header: the other cookies reach the CGI exactly as the browser sent them.
func withoutSessionCookie(request *customNetHttp.Request) {
	var kept []string
	removed := false
	for _, value := range request.Header["Cookie"] {
		var pairs []string
		for _, pair := range strings.Split(value, ";") {
			if name, _, _ := strings.Cut(pair, "="); strings.TrimSpace(name) == sessionCookieName || strings.TrimSpace(name) == sessionCookieNameTLS {
				removed = true
				continue
			}
			pairs = append(pairs, pair)
		}
		if len(pairs) > 0 {
			kept = append(kept, strings.TrimLeft(strings.Join(pairs, ";"), " "))
		}
	}
	if !removed {
		return
	}
	if len(kept) == 0 {
		request.Header.Del("Cookie")
	} else {
		request.Header["Cookie"] = kept
	}
}

// foldRewrites is set where the file system ignores case (Windows, macOS): there "/PRIVATE/x" opens the file of
// "/private/x", so the rewrites of "/private/" must take it too.
var foldRewrites = runtime.GOOS == "windows" || runtime.GOOS == "darwin"

// rewriteKey looks key up among the rewrites of a site: as written and, with foldRewrites, else the first (in
// order) that differs only in case.
func rewriteKey(rewrites map[string]string, key string) (string, bool) {
	if _, found := rewrites[key]; found || !foldRewrites {
		return key, found
	}
	match := ""
	for candidate := range rewrites {
		if strings.EqualFold(candidate, key) && (match == "" || candidate < match) {
			match = candidate
		}
	}
	return match, match != ""
}

// rewrite finds the rewrite of a decoded, clean request path: the path itself, then the folder named without its
// final "/" (a rewrite of "/private/" takes "/private", which would serve that folder's index), then each folder
// that contains it, longest first, then "/". It returns the target and the key that matched.
func rewrite(requestURI string, domain string, subdomain string) (string, string) {
	rewrites := sitesMap[domain][subdomain]
	if key, found := rewriteKey(rewrites, requestURI); found {
		return rewrites[key], key
	}
	if requestURI == "/" { // Nothing else to try for the root
		return "", ""
	}
	if !strings.HasSuffix(requestURI, "/") {
		if key, found := rewriteKey(rewrites, requestURI+"/"); found {
			return rewrites[key], key
		}
	}
	requestURI = requestURI[1:]
	for {
		slash := strings.LastIndexByte(requestURI, '/')
		if slash == -1 {
			break
		}
		slash++
		if key, found := rewriteKey(rewrites, "/"+requestURI[:slash]); found {
			return rewrites[key], key
		}
		requestURI = requestURI[:slash-1]
	}
	if key, found := rewriteKey(rewrites, "/"); found {
		return rewrites[key], key
	} // At the end of large unmatched string is obligatory to check if match with a top level rewrite
	return "", ""
}

// rewriteRedirect answers a rewrite to "http(s)://" with a 302: to the exact target when it has a path or
// a query, or to the target domain followed by the original URI when it is only a domain.
func rewriteRedirect(secure bool, target string, query string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	scheme := "http://"
	if secure {
		scheme = "https://"
	}
	if target == "" || target[0] == '/' { // A placeholder for the host gave nothing (no alias, for example)
		slog.Warn("Rewrite without a host when responding: 500", "host", request.Host, "path", request.RequestURI)
		reqMsg(responseWriter, 500)
		return
	}
	if strings.IndexByte(target, '/') == -1 && query == "" {
		customNetHttp.Redirect(responseWriter, request, scheme+target+request.RequestURI, 302)
		return
	}
	if query != "" {
		target += "?" + query
	}
	customNetHttp.Redirect(responseWriter, request, scheme+target, 302)
}

func choose(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, host string, domain string, subdomain string, currentSubdomain string, firstDomain string, firstSubdomain string) (string, string, bool) {
	pathWithoutQuery, ok := cleanRequestPath(cutAt(request.RequestURI, '?')) // Decoded and inside the site
	if !ok {
		reqMsg(responseWriter, 404) // The same answer whether the file exists or not
		return "", "", false
	}
	rewriteResult, matchedRewrite := rewrite(pathWithoutQuery, domain, subdomain) // domain is the site map key and subdomain is the site subdomain map key, both in sitesMap
	if rewriteResult == "" {
		return pathWithoutQuery, "", true
	} // This is for unmatched URIs for rewrite
	rewriteResult = shortcutWords(request, rewriteResult, domain, subdomain, host, currentSubdomain, firstDomain, firstSubdomain, matchedRewrite, pathWithoutQuery)
	rewriteResult, query, _ := strings.Cut(rewriteResult, "?")
	switch rewriteResult[0] {
	case 'H', 'S':
		rewriteRedirect(rewriteResult[0] == 'S', rewriteResult[1:], query, responseWriter, request)
		return "", "", false
	case 'N':
		rewriteResult = rewriteResult[1:]
	}
	if rewriteResult == "" { // A rewrite whose placeholders expand to nothing
		rewriteResult = "/"
	}
	// Placeholders may have produced ".." or "\\": the target is cleaned as a request path
	cleanPath, ok := cleanRequestPath(rewriteResult)
	if !ok {
		reqMsg(responseWriter, 404)
		return "", "", false
	}
	return cleanPath, query, true
}

// shortcutWords replaces the placeholders of a rewrite target, as stored ("N<path>", or "H"/"S" with the host for
// http:// and https://). requestPath is the decoded, clean path that rewriteMatch, the matched rewrite key, was
// compared with. Each value is encoded for where it goes: in the path, segment by segment, keeping "/"; in the
// query, as one value; in the host, so that it can't change the shape of the URL. {REWRITE_COMPLEMENT} in the path
// takes the path alone, and in a redirection the request's query is added to the target's (an internal target
// already gets it). Unknown placeholders give nothing.
func shortcutWords(request *customNetHttp.Request, input string, domain string, subdomain string, host string, currentSubdomain string, firstDomain string, firstSubdomain string, rewriteMatch string, requestPath string) string {
	const (
		inHost = iota
		inPath
		inQuery
	)
	position := inPath
	redirection := input != "" && (input[0] == 'H' || input[0] == 'S')
	if redirection {
		position = inHost
	}
	var result strings.Builder
	addQuery := false
	write := func(literal string) {
		for _, char := range literal {
			switch {
			case char == '/' && position == inHost:
				position = inPath
			case char == '?' && position != inQuery:
				position = inQuery
			}
			result.WriteRune(char)
		}
	}
	remaining := input
	for {
		openBraceIdx := strings.IndexByte(remaining, '{')
		closeBraceIdx := strings.IndexByte(remaining, '}')
		if remaining == "" || openBraceIdx == -1 || closeBraceIdx == -1 || closeBraceIdx < openBraceIdx {
			break
		}
		write(remaining[:openBraceIdx])
		placeholder := remaining[openBraceIdx+1 : closeBraceIdx]
		remaining = remaining[closeBraceIdx+1:]
		replacer, placeholderExists := shortcutWordReplacers[placeholder]
		if !placeholderExists {
			continue
		}
		value := replacer(request, domain, subdomain, host, currentSubdomain, firstDomain, firstSubdomain, rewriteMatch, requestPath)
		switch position {
		case inHost:
			result.WriteString(url.QueryEscape(value)) // A host name is left as it is; "/", "?" or "@" can't change the URL
		case inPath:
			if placeholder == "REWRITE_COMPLEMENT" { // The path here; a redirection adds the query to the target's
				// Without the query that the replacer adds: a "?" before it comes from the decoded path (%3F), and is
				// escaped with the segment
				if queryStart := strings.IndexByte(request.RequestURI, '?'); queryStart != -1 {
					value = strings.TrimSuffix(value, request.RequestURI[queryStart:])
				}
				addQuery = redirection // An internal target already gets the request's query (CGI, QUERY_STRING)
			}
			segments := strings.Split(value, "/")
			for i, segment := range segments {
				segments[i] = url.PathEscape(segment)
			}
			result.WriteString(strings.Join(segments, "/"))
		default:
			result.WriteString(url.QueryEscape(value))
		}
	}
	write(remaining)
	if _, query, hasQuery := strings.Cut(request.RequestURI, "?"); addQuery && hasQuery && query != "" {
		if strings.IndexByte(result.String(), '?') == -1 {
			result.WriteByte('?')
		} else {
			result.WriteByte('&')
		}
		for i := 0; i < len(query); i++ { // Control characters stay encoded, as in the rest of the target
			if c := query[i]; c < 0x20 || c == 0x7f {
				fmt.Fprintf(&result, "%%%02X", c)
			} else {
				result.WriteByte(c)
			}
		}
	}
	return result.String()
}

// parsedConfig is a turbo.config read and checked but not applied: its content (nil without a file) and schema.
type parsedConfig struct {
	raw    map[string]map[string]interface{}
	schema int
	digest [sha256.Size]byte // Of the file read, for configFileDigest
}

// parseSiteConfig reads and checks the turbo.config at configPath without changing anything in use, so it runs
// without the global lock. A file that can't be read or isn't valid gives a *configFileError; a missing
// one, a parsedConfig without content (the defaults).
func parseSiteConfig(configPath string) (parsedConfig, error) {
	if _, statErr := os.Lstat(configPath); statErr != nil && os.IsNotExist(statErr) {
		return parsedConfig{}, nil
	}
	configBytes, err := os.ReadFile(configPath) // #nosec G304 -- path under the sites directory chosen by the administrator (TURBO_DIR or M)
	if err != nil {
		return parsedConfig{}, &configFileError{path: configPath, err: err}
	}
	var raw map[string]map[string]interface{}
	if err = parseConfig(configBytes, &raw); err != nil {
		return parsedConfig{}, &configFileError{path: configPath, data: configBytes, err: err}
	}
	if err = panelSettingsProblem(raw["."]); err != nil {
		return parsedConfig{}, &configFileError{path: configPath, data: configBytes, err: err}
	}
	if err = siteSectionsProblem(raw); err != nil { // Before dropControlChars, which would drop a section that is a string
		return parsedConfig{}, &configFileError{path: configPath, data: configBytes, err: err}
	}
	dropControlChars(raw)
	schemaRead, err := migrateConfig(raw, configBytes)
	if err != nil {
		return parsedConfig{}, &configFileError{path: configPath, data: configBytes, err: err}
	}
	if pointsToItself(raw, configPath) {
		return parsedConfig{}, &configFileError{path: configPath, data: configBytes, err: configSelfPointerError{}}
	}
	return parsedConfig{raw: raw, schema: schemaRead, digest: sha256.Sum256(configBytes)}, nil
}

// applySiteConfig puts in use a turbo.config from parseSiteConfig, or the defaults without one. The file is the
// source of truth: all that came from it before is emptied first, and what isn't in it stops applying;
// sites, keys and entries are applied in a fixed order, so the result never depends on the order of a map.
// Callers hold the global lock.
func applySiteConfig(config parsedConfig) {
	if config.raw == nil {
		configSchemaRead = configSchema
		setDefaultSettings()
		return
	}
	clearFileSettings()
	defer publishLoadedDeniedIPs() // The file's denied IPs replace the ones in use at once, when all is applied
	rawConfigMap = config.raw
	configSchemaRead = config.schema
	if configSchemaRead < configSchema {
		slog.Warn("Configuration in schema " + strconv.Itoa(configSchemaRead) + ": the migration will apply when saving")
	} else if configSchemaRead > configSchema {
		slog.Warn("Configuration in schema " + strconv.Itoa(configSchemaRead) + ", later than this version's (" + strconv.Itoa(configSchema) + "): what is understood is loaded, and it will not be saved without confirmation")
	}
	loadCredentials(rawConfigMap["."])
	loadPanelCertSettings(rawConfigMap["."])
	var keyExists bool
	var stringValue string
	var configKey string
	for _, configKey = range []string{"_", "@", "#"} { // Replacements first: they don't depend on the rest
		if _, keyExists = rawConfigMap[configKey]; keyExists { // This is for another kind of lists in config file
			for _, subKey := range sortedKeys(rawConfigMap[configKey]) {
				subValue := rawConfigMap[configKey][subKey]
				stringValue, keyExists = configNumberOrString(subValue) // A string, or a JSON integer (the date of a denied IP)
				if !keyExists {
					slog.Warn("turbo.config entry discarded: wrong type (a string or an integer is expected)", "list", configKey, "key", subKey)
					continue
				}
				applied, problem := adminAddHandlers[configKey](subKey, stringValue)
				if applied || strings.HasSuffix(problem, "unchanged") {
					continue
				}
				switch {
				case configKey == "_" && problem != "Fixed replacement":
					slog.Warn("turbo.config character replacement discarded", "character", subKey, "replacement", stringValue, "reason", problem)
				case configKey == "@" && problem != "Expired UNIX date": // An expired denial is no mistake: it ended
					slog.Warn("turbo.config denied IP discarded", "ip", subKey, "date", stringValue, "reason", problem)
				case configKey == "#":
					slog.Warn("turbo.config response discarded", "code", subKey, "reason", problem)
				}
			}
			continue
		}
	}
	if _, keyExists = rawConfigMap["@"]; keyExists {
		slog.Info("Denied IPs active", "total", len(deniedIPsInUse()))
	}
	// The conditions between settings are checked once all of them are in
	loadingConfig = true
	for configKey = range defaultSettingValidators { // Default settings check
		if _, keyExists = rawConfigMap[configKey]; keyExists {
			if _, keyExists = rawConfigMap[configKey]["C"]; keyExists { // "Save" is an action, not a setting: never run while loading
				slog.Warn("turbo.config key ignored: saving is a panel action (setC), not a setting", "key", "C")
			}
			for _, subValue := range defaultSettingKeysGroup[configKey] {
				if rawValue, present := rawConfigMap[configKey][subValue]; present {
					var reason string
					if stringValue, keyExists = configNumberOrString(rawValue); keyExists {
						var applied bool
						if applied, reason = defaultSettingValidators[configKey][subValue](stringValue, internalAuth); applied {
							continue
						}
						if _, keyExists = defaultSettingErrorExceptions[configKey][subValue][reason]; keyExists { // A refusal that keeps the setting as it is ("Value unchanged")
							continue
						}
					} else {
						reason = "wrong type (a string or an integer is expected)"
					}
					slog.Warn("turbo.config setting discarded: the default value is used", "key", subValue, "value", configValueForLog(subValue, rawValue), "reason", reason)
				}
				defaultSettingsResetFallbacks[configKey][subValue]()
			}
		} else {
			for subMap := range defaultSettingsResetFallbacks[configKey] {
				defaultSettingsResetFallbacks[configKey][subMap]()
			} // Reset specific defaults if doesn't exists
		}
	}
	loadingConfig = false
	enforceSettingInvariants()
	for _, domain := range sortedKeys(rawConfigMap) { // Site & subdomains existence check, in a fixed order
		if _, keyExists = defaultSettingValidators[domain]; keyExists {
			continue
		}
		if !siteExistenceCheck(domain, "") {
			keepDormantFromFile(domain, "") // Its folder may appear later
			continue
		}
		for _, subKey := range sortedKeys(rawConfigMap[domain]) {
			if _, keyExists = subdomainContentCheckers[subKey]; keyExists {
				continue
			}
			if subKey != "" && !siteExistenceCheck(domain, subKey) {
				keepDormantFromFile(domain, subKey)
				continue
			}
			subdomainData, keyExists := rawConfigMap[domain][subKey].(map[string]interface{})
			if !keyExists {
				continue
			}
			for _, settingKey := range subdomainContentOrder { // Subdomains content check
				if _, keyExists = subdomainData[settingKey]; keyExists {
					subdomainContentCheckers[settingKey](false, subdomainData[settingKey], true, domain, subKey)
				}
			}
		}
	}
	rawConfigMap = make(map[string]map[string]interface{})
}

// subdomainContentOrder is the order in which the content of a site of turbo.config is applied.
var subdomainContentOrder = []string{"!", "=", "$", ".", "?", "-", "&"}

// sortedKeys returns the keys of values in byte order.
func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// sortedKeyUnion returns the keys of both maps, each once, in byte order.
func sortedKeyUnion[V any, W any](a map[string]V, b map[string]W) []string {
	keys := make([]string, 0, len(a)+len(b))
	for key := range a {
		keys = append(keys, key)
	}
	for key := range b {
		if _, inA := a[key]; !inA {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// clearFileSettings empties, before a turbo.config is applied, everything that comes from it: the sites with
// their settings and certificates (also those kept for sites without their folder), the denied IPs, and the
// character replacements and responses that aren't fixed. Callers hold the global lock, and pause the publication
// of certificates (certificatePublishPaused) until the new ones are loaded.
func clearFileSettings() {
	sitesMap = make(map[string]map[string]map[string]string)
	dormantSites = make(map[string]map[string]string)
	siteSSLConfig = make(map[string]map[string]interface{})
	mimeTypes = make(map[string]map[string]string)
	customHeaders = make(map[string]map[string]string)
	preprocessors = make(map[string]map[string]string)
	indexFiles = make(map[string]map[string]int)
	domainAliases = make(map[string]string)
	siteCertificates = make(map[string]*tls.Certificate)
	deniedIPsLoading = make(map[string]int64) // Published whole when applySiteConfig ends: the list in use stays meanwhile
	for char := range charReplacements {
		if !fixedCharReplacements[char] {
			delete(charReplacements, char)
		}
	}
	responses := make(map[int]string)
	for code, response := range *httpResponses.Load() {
		if fixedHTTPResponses[code] {
			responses[code] = response
		}
	}
	httpResponses.Store(&responses)
}

// certificatePublishPaused, while a turbo.config is applied, keeps setSiteCertificate from publishing each
// certificate: the ones in use stay published until all are loaded. Guarded by globalMutex.
var certificatePublishPaused bool

// diskSite is a site folder found on disk with its public folder: a site, or a subdomain of one.
type diskSite struct {
	site      string
	subdomain string
}

// scanDiskSites lists the site folders of baseDir that have a public folder (@), the ones a reload activates.
// It reads the disk, so it runs without the global lock.
func scanDiskSites(baseDir string, dirEntries []os.DirEntry) []diskSite {
	var found []diskSite
	for _, entry := range dirEntries { // This is used when input is like: #.domain.com
		entryName := entry.Name()
		if entryName == panelCertDirName { // Never a site: nothing of it is served
			continue
		}
		wildcardName := putWildcards(entryName)
		if hostValid, _ := hostOk(wildcardName, false); !hostValid {
			continue
		}
		if _, err := os.ReadDir(baseDir + entryName + "/" + publicDirName); err != nil {
			continue
		}
		subdirEntries, err := os.ReadDir(baseDir + entryName)
		if err != nil {
			continue
		}
		found = append(found, diskSite{wildcardName, ""})
		for _, subEntry := range subdirEntries {
			subWildcardName := putWildcards(subEntry.Name())
			if hostValid, _ := hostOk(subWildcardName+"."+changeWildcards(wildcardName, "x"), false); !hostValid {
				continue
			}
			if info, err := os.Stat(baseDir + entryName + "/" + subEntry.Name() + "/" + publicDirName); err != nil || !info.IsDir() {
				continue
			}
			found = append(found, diskSite{wildcardName, subWildcardName})
		}
	}
	return found
}

// activateDiskSites activates the sites found on disk that aren't active yet, and reports whether there was any:
// with the settings kept for them if their folder had gone or turbo.config has them (dormantSites), or else with
// the defaults. Callers hold the global lock.
func activateDiskSites(found []diskSite, logThem bool) bool {
	activated := false
	for _, disk := range found {
		if siteExists(disk.site, disk.subdomain) {
			continue
		}
		if problem := siteNameProblem(disk.site, disk.subdomain); problem != "" {
			if name := disk.subdomain + "/" + disk.site; !warnedDiskSites[name] {
				warnedDiskSites[name] = true
				slog.Warn("Site folder on disk that is not activated", "site", disk.site, "subdomain", disk.subdomain, "reason", problem)
			}
			continue
		}
		siteKey := disk.site
		if disk.subdomain != "" {
			siteKey = disk.subdomain + "." + disk.site
		}
		activated = true
		if kept, dormant := dormantSites[disk.site][disk.subdomain]; dormant {
			restoreDormantLocked(disk.site, disk.subdomain, kept)
			slog.Info("Site folder back: the site is activated with its settings", "site", siteKey)
			continue
		}
		constructSiteLocked(disk.site, disk.subdomain) // With index.html, as a new site
		subdomainContentCheckers["!"](false, siteSSLConfig[siteKey], true, disk.site, disk.subdomain)
		if logThem {
			slog.Info("Site created on disk and activated", "site", siteKey)
		}
	}
	return activated
}

// configNumberOrString returns a value of turbo.config as the text its validator takes: a string as it is, and a
// JSON number only if it is an integer ("MBB": 5242880 is "5242880"). ok is false for anything else.
func configNumberOrString(value interface{}) (text string, ok bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case float64:
		if typed == math.Trunc(typed) && math.Abs(typed) < 1<<53 {
			return strconv.FormatInt(int64(typed), 10), true
		}
	}
	return "", false
}

// configValueForLog is a value of turbo.config to show in the log: the password and its hash never are.
func configValueForLog(key string, value interface{}) string {
	if key == "P" || key == "PH" {
		return "(hidden)"
	}
	text := fmt.Sprint(value)
	if len(text) > 120 {
		text = text[:120] + "..."
	}
	return text
}

func setDefaultSettings() {
	for group := range defaultSettingsResetFallbacks {
		for setting := range defaultSettingsResetFallbacks[group] {
			defaultSettingsResetFallbacks[group][setting]()
		}
	}
}

func siteExistenceCheck(domain string, subdomain string) bool {
	var passed bool
	var checker string
	for checker = range siteExistenceCheckers {
		if passed, _ = siteExistenceCheckers[checker](true, domain, subdomain); !passed {
			return false
		}
	}
	return true
}

// IPReference is the limiter entry of an IP. Times are of the monotonic clock (monotonicNow).
type IPReference struct {
	mutex        sync.Mutex
	blockedUntil int64 // Blocked until then
	windowStart  int64 // Start of the current count
	requestCount int64 // Requests counted since windowStart
}
