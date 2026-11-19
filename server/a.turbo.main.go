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

// Package server is Turbo: the HTTP server, its panel and all they need, with their tests. The program, in the root
// of the module, only calls Main.
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
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
	"turbo/internal/expr"
)

// Locks: globalMutex guards the maps of this block (signedInTokens, charReplacements, fixedCharReplacements,
// sitesMap, siteSSLConfig, mimeTypes, customHeaders, preprocessors, indexFiles, domainAliases, dormantSites), together with
// siteCertificates, fixedHTTPResponses, currentCertDomain and configFileStamp: read them with RLock and change
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
	siteSSLConfig = make(map[string]*siteSettings)                // The settings of each site ("!"), by its key
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
	fileWriteTimeout    atomic.Int64  // WFT: how long the response of a site's file may take to be written, in nanoseconds; 0 = WT
	cgiProcesses        atomic.Int64  // CGP: CGI processes at a time; 0 = automatic (see cgiProcessLimit)
	globalRequestWindow atomic.Uint64 // Unix second (high 32 bits) and the requests counted in it (low 32 bits)

	configCheckTicker = time.NewTicker(30 * time.Second)
	cleanupTicker     = time.NewTicker(60 * time.Second)

	// TLS 1.2 only with forward secrecy and AEAD suites (decision D4): none with CBC, whose padding and MAC have been
	// attacked more than once (Lucky 13). TLS 1.3 has only AEAD suites, which Go doesn't let configure.
	tlsConfig = &tls.Config{NextProtos: []string{"h2", "http/1.1"}, Certificates: []tls.Certificate{}, MinVersion: tls.VersionTLS12, CipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}}

	currentCertDomain string              // Certificate domain currently being processed
	certRetryDelay    = 30 * time.Second  // Delay before retrying a certificate while another one is being issued
	certPending       = map[string]bool{} // Sites with a certificate retry waiting (one each); guarded by globalMutex
	configFileStamp   configStamp         // turbo.config as it was when last read; the zero value reads it again

	httpResponses      = &customNetHttp.TurboErrorTemplates // HTTP responses (published copy, see setHTTPResponses)
	fixedHTTPResponses = make(map[int]bool)                 // Fixed HTTP response codes

	visitsLogFile  *os.File // Visits log file pointer
	denialsLogFile *os.File // Denials log file pointer

	globalMutex  stateLock  // Global mutex for shared state, which counts its write locks
	logMutex     sync.Mutex // Guards the log file pointers, apart from globalMutex so logging never waits for it
	ipReferences sync.Map   // References per IP
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

// turboVersion is the release: what the program gives to Main, which release.sh sets in it with
// -ldflags "-X main.turboVersion=<version>".
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

// Main is the program: it starts Turbo and serves until the process ends. version is the release, empty in a
// build made without release.sh.
func Main(version string) {
	turboVersion = version
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
	} else if err := setPanelPassword(defaultPanelPassword); err != nil {
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
	if cleanInterruptedWork(sitesDir.Get(), startDir) { // What a stop cut halfway, before Turbo serves
		logConfigError(updateSettings(true)) // A site whose @ was put back is activated now
	}
	warnDefaultCredentials()
	warnUnlimitedTimeouts()
	clearInheritedCapabilities() // Before any CGI can run; opening the ports needs only Turbo's effective set
	servers[0] = createSafeServer(tlsConfig)
	servers[1] = createHTTPServer()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM) // Ctrl+C, and what systemd sends to stop the service
	runRecovering("renewCertificates", renewCertificates)
	renewTicker := time.NewTicker(24 * time.Hour)
	runMaintenance(stop, renewTicker.C, configCheckTicker.C, cleanupTicker.C)
}

// runMaintenance does the periodic work of Turbo until a signal arrives in stop, which shuts the servers down: with
// each tick of renew, the certificates that are due are renewed; of config, turbo.config and the sites directory
// are read again; of cleanup, what has expired is forgotten (sessions, denied IPs, failed logins, the limiter's
// entries). A panic in one of them is logged, and the rest goes on (runRecovering).
func runMaintenance(stop chan os.Signal, renew <-chan time.Time, config <-chan time.Time, cleanup <-chan time.Time) {
	for {
		select {
		case received := <-stop:
			shutdown(received, stop)
			return
		case <-renew:
			runRecovering("renewCertificates", renewCertificates)
		case <-config:
			runRecovering("updateSettings", func() { logConfigError(updateSettings(true)) })
		case <-cleanup:
			runRecovering("cleanOldValues", func() {
				cleanOldValues(&signedInTokens)
				cleanOldValues(&sessionDeadlines)
				withGlobalLock(cleanDeniedIPs)
				cleanLoginFailures()
				cleanIPReferences()
			})
			runRecovering("idlePreprocessorModes", idlePreprocessorModes)
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
// code 0). A second signal (from again, if it isn't nil) ends that wait at once: it was ignored until the wait ended.
// The rest goes on as always, so no CGI is left behind.
func shutdown(received os.Signal, again <-chan os.Signal) {
	slog.Info("Stopping", "signal", received.String())
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if again != nil {
		go func() {
			select {
			case second := <-again:
				slog.Warn("Second signal while stopping: the requests in progress are no longer waited for", "signal", second.String())
				cancel()
			case <-ctx.Done():
			}
		}()
	}
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
	stopPreprocessorModes(cgiEndWait)     // What the modes keep running, once no request uses it
	errorLines.close()                    // The errors counted and not written yet, and then each one at once
	scriptLines.close()                   // So do the lines of the scripts
	serverSetLogState(visitsLogName, nil) // Closed, so the last lines are written
	serverSetLogState(denialsLogName, nil)
	slog.Info("Stopped")
}

// waitCGIsEnded waits, up to wait, until no CGI is running (each releases its slot once it is gone) and their
// outputs have ended, with their temporary files: a CGI frees its slot when it is done, before its output has reached
// its client.
func waitCGIsEnded(wait time.Duration) {
	deadline := time.Now().Add(wait)
	for {
		cgiSlots.mutex.Lock()
		running, outputs := cgiSlots.running, cgiSlots.outputs
		if (running > 0 || outputs > 0) && cgiSlots.freed == nil {
			cgiSlots.freed = make(chan struct{})
		}
		freed := cgiSlots.freed
		cgiSlots.mutex.Unlock()
		remaining := time.Until(deadline)
		if running <= 0 && outputs <= 0 {
			return
		}
		if remaining <= 0 {
			slog.Warn("CGIs still running when Turbo exits", "count", running, "outputs", outputs)
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

// runRecovering runs a periodic task of Main() and logs a panic instead of ending the process.
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
	loopback := limiterKey("::1")
	for ip, until := range list {
		if network := limiterKey(ip); network != ip && network != loopback { // Never ::1's /64 (the "@" validator refuses it)
			networks[network] = max(networks[network], until)
		}
	}
	deniedNetworks.Store(&networks)
	deniedIPs.Store(&list)
}

// deniedUntil returns the UNIX date until which the client is denied: its IP, or a denied IPv6 address of its
// /64; 0 if it isn't. Without the global lock, like the rest of the limiter.
func deniedUntil(client clientAddress) int64 {
	until := deniedIPList()[client.ip]
	if networks := deniedNetworks.Load(); networks != nil && client.key != client.ip {
		until = max(until, (*networks)[client.key])
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
		Handler:   customNetHttp.HandlerFunc(serverHandlerFn(true)),
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

// safeServerStart serves HTTPS on httpsAddr (:443). While it isn't open (it couldn't be opened, or the server
// stopped with an error), nothing is redirected to HTTPS (httpsListening) and Turbo tries to open it again every
// httpsRetryDelay.
func safeServerStart(server *customNetHttp.Server, tlsConfig *tls.Config) *customNetHttp.Server {
	// One at a time: a second one (the retry, while a certificate just loaded opens it too) found the address taken,
	// logged that as an error and left another retry waiting.
	if !httpsStarting.CompareAndSwap(false, true) {
		return server
	}
	defer httpsStarting.Store(false)
	if httpsListening.Load() {
		return server
	}
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

// httpsStarting is set while safeServerStart opens httpsAddr.
var httpsStarting atomic.Bool

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
		Handler:   customNetHttp.HandlerFunc(serverHandlerFn(false)),
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

// serverHandlerFn returns the handler of the requests of a server: the one of HTTPS (overTLS), or the one of HTTP.
func serverHandlerFn(overTLS bool) func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
	return func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		currentTimestamp := time.Now().Unix()
		// A request in absolute form (GET http://host/x) is served as the same one in origin form; Go already took
		// its host as r.Host. ("OPTIONS *" never gets here: Go answers it.) The target of a CONNECT, a host and a port
		// (the authority form), names no file of a site: it stays as it is, and is refused below. Taken for an
		// absolute form, it was served as GET /.
		if r.RequestURI != "" && r.RequestURI[0] != '/' && r.URL.IsAbs() {
			r.RequestURI = r.URL.RequestURI()
		}

		if status, retryAfter := rateLimited(clientOf(r.RemoteAddr)); status != 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
			reqMsg(w, status)
			return
		}

		serverWriteLogs(visitsLogName, r, currentTimestamp, "Visit")

		// The Host as it chooses the site (canonicalHost), so that a CGI's HTTP_HOST and SERVER_NAME, and the port of a
		// redirection, never carry what the choice of the site left out. One that isn't a host gets 400: it was served
		// as another host ("[example.com]x" as example.com), or carried any text to a CGI (the zone of an IPv6 address).
		canonical, valid := canonicalHost(r.Host)
		if !valid {
			reqMsg(w, 400)
			return
		}
		// HTTP/2 may carry a host field besides :authority, which is the host Go gives and the one that chooses
		// the site: one that names another host is malformed (RFC 9113, 8.3.1), and the same one is dropped, so the
		// CGI's HTTP_HOST is always the host that chose the site.
		if hosts, present := r.Header["Host"]; present {
			delete(r.Header, "Host")
			for _, field := range hosts {
				if other, valid := canonicalHost(field); !valid || requestHostName(other) != requestHostName(canonical) {
					reqMsg(w, 400)
					return
				}
			}
		}
		r.Host = canonical
		if panelAccess.Load().hosts[panelHostName(r)] { // The panel's own host, named as PA names it: only its pages run scripts
			w.Header().Set("Content-Security-Policy", panelCSP)
		}

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
		withReadLock(func() { plan = resolveRequest(overTLS, held, r, acme) })
		if acme.path != "" && !acme.checked {
			info, err := siteDirStat(acme.path)
			acme.checked, acme.exists = true, err == nil && info.Mode().IsRegular()
			held = newHeldResponse(w)
			withReadLock(func() { plan = resolveRequest(overTLS, held, r, acme) })
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
	w      customNetHttp.ResponseWriter // The response itself, for its headers
	header customNetHttp.Header         // A copy of them, made when the first one is asked for
	status int
	body   bytes.Buffer
}

func newHeldResponse(w customNetHttp.ResponseWriter) *heldResponse {
	return &heldResponse{w: w}
}

// Header returns the headers held, which start as a copy of those of the response. The copy waits for the first
// call: a request that gets a plan, as most do, writes nothing here.
func (held *heldResponse) Header() customNetHttp.Header {
	if held.header == nil {
		if held.header = held.w.Header().Clone(); held.header == nil {
			held.header = make(customNetHttp.Header)
		}
	}
	return held.header
}

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

// sendTo writes to w what was held: the headers, if any was asked for, and the response if one was written.
func (held *heldResponse) sendTo(w customNetHttp.ResponseWriter) {
	if held.header != nil {
		header := w.Header()
		clear(header)
		for name, values := range held.header {
			header[name] = values
		}
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
func resolveRequest(overTLS bool, w customNetHttp.ResponseWriter, r *customNetHttp.Request, acme *acmeLookup) *servePlan {
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
	site := siteMatch{siteDomain: effectiveDomain, domain: domain, subdomain: subdomain, firstDomain: firstDomain, firstSubdomain: firstSubdomain}
	if path := acmeChallengeFilePath(effectiveDomain, subdomain, r); path != "" {
		if !acme.checked {
			acme.path = path
			return nil
		}
		if acme.exists && acme.path == path {
			return serve(overTLS, site, w, r, true)
		}
	}

	if subdomain == "" && settingsOf(effectiveDomain).rootToWWW {
		redir(requestScheme(overTLS), domain, "www", w, r, 301)
		return nil
	}

	if subdomain == "www" && settingsOf(effectiveDomain).wwwToRoot {
		redir(requestScheme(overTLS), domain, "", w, r, 301)
		return nil
	}

	if !overTLS && httpsRedirect(fullHost, w, r) {
		return nil
	}

	return serve(overTLS, site, w, r, false)
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

// constructSiteWithoutIndex creates the entries of a site (rewrites, preprocessors, indexes, MIME types, headers and
// settings), all empty: its section of turbo.config fills them, indexes included, or newSiteContentLocked for a
// site that no section describes. Callers hold the global lock.
func constructSiteWithoutIndex(domain string, subdomain string) {
	if _, exists := sitesMap[domain]; !exists {
		sitesMap[domain] = make(map[string]map[string]string)
	}
	sitesMap[domain][subdomain] = make(map[string]string) // Rewrites
	if subdomain != "" {
		domain = subdomain + "." + domain
	}
	preprocessors[domain] = make(map[string]string) // Preprocessors
	indexFiles[domain] = make(map[string]int)       // Indexes
	mimeTypes[domain] = make(map[string]string)     // MIME types
	customHeaders[domain] = make(map[string]string) // Headers
	siteSSLConfig[domain] = &siteSettings{}         // Site settings: all off, without e-mail nor adapter
}

// siteSettings are the settings of a site, the "!" of its section in turbo.config and in the panel, each with the
// letter that names it there.
type siteSettings struct {
	https       bool             // "S": its HTTP requests are redirected to HTTPS, with its certificate
	certificate certificateState // "C": whether its certificate files are there, or why Certbot didn't get them
	wwwToRoot   bool             // "R": www.<site> is redirected to <site>
	rootToWWW   bool             // "W": <site> is redirected to www.<site>
	email       string           // "E": the e-mail of its certificate; with one, Turbo renews it
	adapter     string           // "A": the DNS adapter of Certbot for it ("dns-<provider>"), or empty for the webroot
	// "Z": a request that accepts br or gzip is answered with the file.br or file.gz that is next to the file it
	// names, when there is one (servePrecompressed)
	precompressed bool
}

// certificateState is the "C" of a site: whether its certificate is there (active) or, after an attempt of Certbot
// that failed, why (failure), which the next "Create SSL" answers, once.
type certificateState struct {
	active  bool
	failed  bool
	failure string
}

// certificateStateOf is the state that an attempt of Certbot leaves: true, or why it failed (startCertbot).
func certificateStateOf(status interface{}) certificateState {
	switch result := status.(type) {
	case bool:
		return certificateState{active: result}
	case string:
		return certificateState{failed: true, failure: result}
	}
	return certificateState{failed: true, failure: "Invalid certificate response"}
}

// asSetting is the state as "C" has it in a section of turbo.config: a bool, or the text of the failure.
func (state certificateState) asSetting() interface{} {
	if state.failed {
		return state.failure
	}
	return state.active
}

// settingsOf returns the settings of a site, or those of a new one for a key without them (a domain that only
// has subdomains). Callers hold the global lock.
func settingsOf(siteKey string) siteSettings {
	if settings := siteSSLConfig[siteKey]; settings != nil {
		return *settings
	}
	return siteSettings{}
}

// asSection returns the settings as a "!" section of turbo.config gives them to its checker
// (subdomainContentCheckers), or none for a site without them.
func (settings *siteSettings) asSection() map[string]interface{} {
	if settings == nil {
		return nil
	}
	https := 0
	if settings.https {
		https = 1
	}
	return map[string]interface{}{
		"S": https, "C": settings.certificate.asSetting(), "R": settings.wwwToRoot, "W": settings.rootToWWW,
		"E": settings.email, "A": settings.adapter, "Z": settings.precompressed,
	}
}

// constructSiteLocked adds a site created from the panel, with index.html as its index: its folder, created after
// it, has no certificate yet. A site whose folder is already there and that no section of turbo.config describes
// gets newSiteContentLocked; one read from a section keeps what the section says, indexes included. Callers hold
// the global lock.
func constructSiteLocked(domain string, subdomain string) {
	constructSiteWithoutIndex(domain, subdomain)
	siteKey := domain
	if subdomain != "" {
		siteKey = subdomain + "." + domain
	}
	addIndex(siteKey, "index.html")
}

// newSiteContentLocked gives a site just built with constructSiteWithoutIndex, whose folder is there and which no
// section of turbo.config describes, what a new site has: index.html as its index and, with the other settings at
// their defaults, the state of its certificate (C). It is for a site found on disk, and for one that turbo.config
// names without a "" section (only through its subdomains, or as {} or null), which, built with nothing, answered
// 404 to "/". The reload looked at its certificate files before taking the lock (lookAheadSettings). Callers hold
// the global lock.
func newSiteContentLocked(domain string, subdomain string) {
	siteKey := domain
	if subdomain != "" {
		siteKey = subdomain + "." + domain
	}
	addIndex(siteKey, "index.html")
	subdomainContentCheckers["!"](false, siteSSLConfig[siteKey].asSection(), true, domain, subdomain)
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

// deleteSite deletes an active site (deleteSiteFromPanel), with anything kept of it (dormantSites): a folder with
// its name, later, is a new site.
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

// undoSiteCheckLocked undoes constructSiteLocked for a site that addSite or addSubdomain built to check it, or that
// can't stay: its entry and the settings of its key, and the entry of its domain only if constructSiteLocked made it
// (domainExisted false). Not deleteSiteLocked, which for a root deletes the whole domain: a domain can have subdomains
// without its root (a folder whose root was refused while another site had its key), and they lost their
// preprocessors, headers, certificate and aliases. Callers hold the global lock.
func undoSiteCheckLocked(domain string, subdomain string, domainExisted bool) {
	delete(sitesMap[domain], subdomain)
	if !domainExisted {
		delete(sitesMap, domain)
	}
	siteKey := domain
	if subdomain != "" {
		siteKey = subdomain + "." + domain
	}
	if siteKeyOwner(siteKey, domain, subdomain) == "" { // Never what another site keeps there
		forgetSiteKey(siteKey)
	}
}

// reservedSiteNames are the files and folders that Turbo keeps in the sites directory: a site with one of these
// names would have its folder there.
var reservedSiteNames = map[string]bool{devGUIDirName: true, certificatesDirName: true, panelCertDirName: true, configFileName: true, visitsLogName: true, denialsLogName: true}

// reservedSubdomainNames are the files that Turbo keeps in the folder of a site, where the folder of a subdomain with
// one of these names would be: its certificate and its key, also while a new pair is put in place (installCertificate).
// With that folder there, no certificate of the site could be installed.
var reservedSubdomainNames = map[string]bool{certFileName: true, keyFileName: true, certFileName + ".new": true, keyFileName + ".new": true}

// siteNameProblem says why the site (domain, subdomain) can't be activated, or "": a folder that Turbo keeps for
// itself (also for its subdomains), or a key that another site already has (the site "c.a.b" and the subdomain
// "c" of "a.b" would share their settings). Callers hold the global lock.
func siteNameProblem(domain string, subdomain string) string {
	if reservedSiteNames[changeWildcards(domain)] {
		return "Name reserved by Turbo: " + domain
	}
	if reservedSubdomainNames[subdomain] {
		return "Name reserved by Turbo: " + subdomain
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
	if siteNamedAsIP(siteKey) {
		return "Only the site * serves an IP address: a site named " + siteKey + " would never be reached"
	}
	if target, isAlias := domainAliases[siteKey]; isAlias {
		return siteKey + " is an alias of " + target + ": delete it first"
	}
	return siteNameProblem(domain, subdomain)
}

// siteNamedAsIP reports whether a site key is an IP address ("192.168.1.10"): only the site "*" serves an IP
// address (host), so such a site is never reached.
func siteNamedAsIP(siteKey string) bool {
	_, err := netip.ParseAddr(siteKey)
	return err == nil
}

// warnSiteNamedAsIPLocked warns, once, of a site named as an IP address that a folder or turbo.config activates: it
// is activated, as before, but never reached. addSite and addSubdomain refuse one (newSiteProblem). Callers hold the
// global lock.
func warnSiteNamedAsIPLocked(siteKey string) {
	if key := "ip:" + siteKey; siteNamedAsIP(siteKey) && !warnedDiskSites[key] {
		warnedDiskSites[key] = true
		slog.Warn("Site named as an IP address: only the site * (the folder #) serves an IP address, so it is never reached", "site", siteKey)
	}
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

	// hardUpload swaps @ for the uploaded files holding the lock, between two renames during which @ isn't there:
	// a look made while it did that says nothing, and the site stays active until the next one.
	swaps := publicSwaps.Load()
	var missing []activeSite
	listings := folderListings{}
	for _, site := range active {
		if siteFolderGone(site.domain, site.subdomain, listings) {
			missing = append(missing, site)
		}
	}

	beforeMissingSitesDeleted()
	var gone []activeSite
	listings = folderListings{} // Looked at again, also without the lock (a slow disk would hold every request)
	for _, site := range missing {
		if siteFolderGone(site.domain, site.subdomain, listings) {
			gone = append(gone, site)
		}
	}
	for _, site := range gone {
		deleted := false
		withGlobalLock(func() {
			if !siteExists(site.domain, site.subdomain) || publicSwaps.Load() != swaps { // Deleted, or an @ swapped, meanwhile
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

// publicSwaps counts the swaps of a site's public folder (@) by hardUpload, each made holding the global lock: a
// look of checkSites made while one happened says nothing about the site.
var publicSwaps atomic.Int64

// siteDirRead lists a folder for checkSites (a variable so that tests can make it fail).
var siteDirRead = os.ReadDir

// namesIgnoreCase is whether the file names of the system ignore case, as they do by default on Windows and macOS.
var namesIgnoreCase = runtime.GOOS == "windows" || runtime.GOOS == "darwin"

// sitesDirFolds is set when the sites directory in use was found to take a name in other capitals for the same file
// (probeNameFolding), on any system: a volume of Windows (NTFS, FAT, a share) mounted on Linux, or a folder with
// casefold. Turbo then treats names there as Windows and macOS always do: the rewrites of "/private/" also take
// "/PRIVATE/", which opens the same folder, and, outside macOS, the names that Windows takes specially (short names,
// streams, devices) are refused, as those volumes have them.
var sitesDirFolds atomic.Bool

// namesFold reports whether names that differ in their capitals are the same file in the sites directory.
func namesFold() bool {
	return namesIgnoreCase || sitesDirFolds.Load()
}

// windowsNamesApply reports whether the names that Windows takes specially are refused in the paths of the requests:
// on Windows, and where the sites directory folds names (sitesDirFolds) outside macOS, whose own volumes fold them
// without having those names.
func windowsNamesApply() bool {
	return runtime.GOOS == "windows" || runtime.GOOS != "darwin" && sitesDirFolds.Load()
}

// probeNameFolding looks at whether the sites directory baseDir takes a name in other capitals for the same file: the
// folder of one of its sites (a host name, in lower case), asked for in capitals, is the same folder. Without a
// site whose name has letters, or if it can't be looked at, it reports false: the default of the system applies.
func probeNameFolding(baseDir string, sites []diskSite) bool {
	for _, site := range sites {
		name := changeWildcards(site.site)
		upper := strings.ToUpper(name)
		if site.subdomain != "" || upper == name {
			continue
		}
		lowerInfo, err := os.Stat(baseDir + name)
		if err != nil {
			continue
		}
		upperInfo, err := os.Stat(baseDir + upper)
		return err == nil && os.SameFile(lowerInfo, upperInfo)
	}
	return false
}

// folderListings are the folders that a pass of checkSites listed, each listed once.
type folderListings map[string]folderListing

type folderListing struct {
	names map[string]bool // In lower case, where names ignore case
	err   error
}

// has reports whether the folder parent has an entry called name, listing it the first time.
func (listings folderListings) has(parent string, name string) (bool, error) {
	listing, listed := listings[parent]
	if !listed {
		entries, err := siteDirRead(parent)
		listing = folderListing{names: make(map[string]bool, len(entries)), err: err}
		for _, entry := range entries {
			entryName := entry.Name()
			if namesFold() {
				entryName = strings.ToLower(entryName)
			}
			listing.names[entryName] = true
		}
		listings[parent] = listing
	}
	if listing.err != nil {
		return false, listing.err
	}
	if namesFold() {
		name = strings.ToLower(name)
	}
	return listing.names[name], nil
}

// siteFolderGone reports whether the folder of a site or its public folder (@) is no longer there: it isn't a
// folder, or it doesn't exist and its parent folder, which can be listed, doesn't have it. Any other answer
// (permissions, I/O, a network share that doesn't answer, whose errors Windows also gives as "not found") says
// nothing about the site, which is left as it is.
func siteFolderGone(domain string, subdomain string, listings folderListings) bool {
	folder := sitesDir.Get() + siteFolder(domain, subdomain)
	for _, path := range []string{strings.TrimSuffix(folder, "/"), folder + publicDirName} {
		info, err := siteDirStat(path)
		if err == nil {
			if !info.IsDir() {
				return true
			}
			continue
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return false
		}
		cut := strings.LastIndexByte(path, '/') + 1
		listed, listErr := listings.has(path[:cut], path[cut:])
		return listErr == nil && !listed
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
	kept := false
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
		kept = true
	}
	if kept { // A site without sections ({}, null) has nothing to keep: its folder brings it as a new site
		slog.Info("turbo.config site whose folder isn't there or can't be read: its settings apply when it can be used", "site", domain, "subdomain", subdomain)
	}
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

// forgetDormantLocked drops what is kept of a site (for a domain, also of its subdomains): one deleted, with its
// folder, starts anew if a folder with its name comes later. Callers hold the global lock.
func forgetDormantLocked(domain string, subdomain string) {
	if subdomain == "" {
		delete(dormantSites, domain)
		return
	}
	forgetDormantEntryLocked(domain, subdomain)
}

// forgetDormantEntryLocked drops what is kept of that one site: for a domain, not what is kept of its subdomains,
// which the panel lists, and deletes, each on its own. Callers hold the global lock.
func forgetDormantEntryLocked(domain string, subdomain string) {
	delete(dormantSites[domain], subdomain)
	if len(dormantSites[domain]) == 0 {
		delete(dormantSites, domain)
	}
}

// keptSiteMessage is the answer to creating, from the panel, a site that Turbo keeps without its folder: created
// anew, it lost its settings with the session alone (its preprocessors included, its scripts then served as text
// when its folder came back), and the settings of its subdomains with it.
func keptSiteMessage(name string) string {
	return name + " is kept, with its settings, while its folder or its @ isn't there or can't be read: make them usable again or, once its folder is gone, forget it first (Sites without their folder)"
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
	return settingsOf(siteKey).https
}

// requestScheme is the scheme of the requests that a server gets: "https" for the one of TLS.
func requestScheme(overTLS bool) string {
	if overTLS {
		return "https"
	}
	return "http"
}

// redir redirects to the same request on subdomain.host, with the scheme given and the port of the Host header.
func redir(scheme string, host string, subdomain string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, statusCode int) {
	if subdomain != "" {
		subdomain += "."
	}
	port := ""
	if _, hostPort, err := net.SplitHostPort(request.Host); err == nil {
		port = ":" + hostPort
	}
	customNetHttp.Redirect(responseWriter, request, scheme+"://"+subdomain+host+port+request.RequestURI, statusCode)
}

// httpsPortSuffix is ":<port>" of TURBO_HTTPS_ADDR for the redirections to HTTPS, or "" for the default 443.
func httpsPortSuffix() string {
	if _, port, err := net.SplitHostPort(httpsAddr); err == nil && port != "443" {
		return ":" + port
	}
	return ""
}

// servePlan is what serving a request needs from the shared settings, read under the read lock. Those of its site
// are the ones of its view (siteView), which the plans of the site share: nothing writes to them.
type servePlan struct {
	root          string            // Content directory of the site
	path          string            // Rewritten path
	rewritten     bool              // The path is the target of a rewrite, not the one the request named
	queryString   string            // Query added by the rewrite (for CGI)
	indexes       []string          // Index file names
	headers       map[string]string // Site headers written as they are, for the files and CGI responses it serves
	mimeTypes     map[string]string // MIME types by extension
	preprocessors map[string]string // Preprocessors by extension
	precompressed bool              // The site answers with file.br or file.gz to those that accept them ("Z")

	// What the expressions of the site's headers read and need (computeHeaders): the site and the names that led to
	// it, the rewrite key that matched and the decoded, clean path the request named, whether it came by TLS, and
	// whether it is the file of an ACME challenge, which is served without them.
	headerExpressions []headerExpression
	brokenHeader      string
	brokenWhy         string
	vary              []string
	rewriteVary       []string // What the expression of the rewrite read: also on the answers given before the file
	site              siteMatch
	rewriteMatch      string
	requestPath       string
	overTLS           bool
	acmeChallenge     bool
}

// cloneOrNil copies a site map, or returns nil for an empty one to save the allocation.
func cloneOrNil(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	return maps.Clone(values)
}

// siteMatch is the site that serves a request and the names that led to it, each with the placeholder of the
// rewrites that it fills. The site is named as sitesMap has it, which is where its rewrites are; the host, as the
// request named it or, for an alias, as its target does.
type siteMatch struct {
	siteDomain     string // The site in sitesMap: a domain, or the wildcard that took the host ("*.example.com", "*"). {WILDCARD_DOMAIN}
	siteSubdomain  string // Its subdomain there: "" for the site itself, a name ("api") or a wildcard ("*", "*.api"). {WILDCARD_SUBDOMAIN}
	domain         string // The domain of the host served. {DOMAIN}
	subdomain      string // The labels of the host before its domain. {SUBDOMAIN}
	firstDomain    string // The domain of the host as the request named it, when an alias or a wildcard took it; else empty. {FIRST_DOMAIN}
	firstSubdomain string // Its labels before that domain, in the same cases. {FIRST_SUBDOMAIN}
}

// serve returns the plan to serve the request with the site that resolveRequest found for its host (site, still
// without its subdomain in sitesMap, which is looked for here), or answers it and returns nil. Callers hold the
// global read lock.
func serve(overTLS bool, site siteMatch, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, acmeChallenge bool) *servePlan {
	wildcardMatch, _, _, siteSubdomain := detectWildcards(site.subdomain, site.siteDomain)

	if !wildcardMatch {
		reqMsg(responseWriter, 404)
		return nil
	}
	site.siteSubdomain = siteSubdomain

	if !overTLS && site.subdomain != "" && !acmeChallenge && httpsRedirect(site.siteSubdomain+"."+site.siteDomain, responseWriter, request) {
		return nil
	}

	var chosen chosenPath
	continueServe := false
	if acmeChallenge { // Neither redirections nor rewrites: the file of the challenge, as it is
		chosen.path, continueServe = cleanRequestPath(cutAt(request.RequestURI, '?'))
		chosen.requested = chosen.path
	} else {
		chosen, continueServe = choose(overTLS, responseWriter, request, site)
	}
	if !continueServe {
		return nil
	}

	// The content directory, and the key of the site's settings ("sub.example.com", or "example.com" for the domain)
	root, siteKey := "", site.siteDomain
	if site.subdomain != "" {
		root = sitesDir.Get() + changeWildcards(site.siteDomain) + "/" + changeWildcards(site.siteSubdomain) + "/" + publicDirName
		siteKey = site.siteSubdomain + "." + site.siteDomain
	} else {
		root = sitesDir.Get() + changeWildcards(site.siteDomain) + "/" + publicDirName
	}

	view := siteViewOf(siteKey)
	return &servePlan{
		root:              root,
		path:              chosen.path,
		rewritten:         chosen.rewritten,
		queryString:       chosen.query,
		indexes:           view.indexes,
		headers:           view.headers,
		mimeTypes:         view.mimeTypes,
		preprocessors:     view.preprocessors,
		precompressed:     view.precompressed,
		headerExpressions: view.headerExpressions,
		brokenHeader:      view.brokenHeader,
		brokenWhy:         view.brokenWhy,
		vary:              joinedVary(view.vary, chosen.vary),
		rewriteVary:       chosen.vary,
		site:              site,
		rewriteMatch:      chosen.match,
		requestPath:       chosen.requested,
		overTLS:           overTLS,
		acmeChallenge:     acmeChallenge,
	}
}

// serve answers with the file of the plan, or runs its preprocessor, without the global lock. Files are looked
// up and opened through an os.Root of the site's content directory, so that nothing outside it is reached, not
// even through a symbolic link. The file is opened once and served from that handle.
func (plan *servePlan) serve(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	rewrittenPath := plan.path
	// An answer given before the file (a 404, the redirection of a folder) depends on what the expression of the
	// rewrite read as much as the file does: a shared cache would keep it for everyone.
	varyEarly := func() { addVary(responseWriter.Header(), plan.rewriteVary) }
	contentRoot, err := os.OpenRoot(plan.root)
	if err != nil {
		varyEarly()
		reqMsg(responseWriter, 404)
		return
	}
	defer contentRoot.Close()
	opened := &openedFileFS{root: contentRoot}
	defer opened.close()
	fileInfo, err := opened.open(rootName(rewrittenPath))
	if err != nil || (!fileInfo.IsDir() && strings.HasSuffix(rewrittenPath, "/")) { // "x.php/" names no folder: its extension would be lost
		varyEarly()
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
			varyEarly()
			reqMsg(responseWriter, 404)
			return
		}
		// "/docs" for the folder "/docs/": served there, as it was, the relative links of its index led to the folder
		// above ("/logo.png" for "logo.png"). The target of a rewrite is a path of the site, not the visitor's.
		if trailingSlash != "" && !plan.rewritten {
			varyEarly()
			folderRedirect(responseWriter, request, plan.path)
			return
		}
	}

	extension := ext(rewrittenPath)
	// V-04: with preprocessors, a name that some file system takes for another one's is never served. The extension
	// of the name asked for chooses the preprocessor, but the file that opens may be a script under another name: its
	// short name where the volume has them (NTFS, FAT or a share of Windows mounted on Linux: "LONGNA~1.PHT" for
	// "longname.phtml"), one of its streams ("x.php:$DATA"), or a name that differs in characters the file system
	// folds or ignores (an extension outside ASCII). Windows refuses the first two for every site (cleanRequestPath).
	if len(plan.preprocessors) > 0 && ambiguousScriptName(rewrittenPath, extension) {
		varyEarly()
		reqMsg(responseWriter, 404)
		return
	}
	computed, answer := plan.computeHeaders(responseWriter, request, rewrittenPath) // Before anything is set or run
	if !answer {
		return
	}
	responseHeaders := responseWriter.Header()
	for name, value := range plan.headers { // The site's headers, only for what is served
		setSiteHeader(responseHeaders, name, value)
	}
	for _, header := range computed {
		setSiteHeader(responseHeaders, header.name, header.value)
	}
	vary := plan.vary
	if plan.acmeChallenge {
		vary = nil
	}

	if preprocessor := plan.preprocessors[extension]; preprocessor != "" && !plan.acmeChallenge { // Verify preprocessors; an ACME challenge is a file to give as it is, also without an extension
		mode, executable, problem := preprocessorParts(preprocessor)
		if problem == "" {
			if info, err := os.Stat(executable); err != nil || info.IsDir() {
				problem = "the executable does not exist or is a folder"
			}
		}
		if problem != "" { // Fail closed: never serve the source of a preprocessed file
			if missingPreprocessorLogDue(plan.root + "|" + extension) {
				slog.Error("Preprocessor unavailable (reported once a minute)", "site", plan.root, "extension", extension, "reason", problem, "preprocessor", strings.TrimLeft(preprocessor, invalidPreprocessorMark))
			}
			siteErrorMsg(responseWriter, 500)
			return
		}
		opened.close() // The CGI opens the script itself
		dynamic(mode, plan.root, rewrittenPath, plan.queryString, executable, vary, responseWriter, request)
		return
	}

	addVary(responseHeaders, vary)
	if mimeType, found := plan.mimeTypes[extension]; found {
		responseHeaders.Set(contentTypeHeader, mimeType)
	}
	// WFT: a file gets its own time to be written, counted from here. WT, the time of every response, is also how long
	// a CGI may run: raised for the downloads that take longer than it (which it cuts), it was raised for the CGIs too.
	// With 0, WT applies as it always did. The server clears the deadline after each response (HTTP/1), and in HTTP/2
	// it is the stream's.
	if limit := fileWriteTimeout.Load(); limit > 0 {
		_ = customNetHttp.NewResponseController(responseWriter).SetWriteDeadline(time.Now().Add(time.Duration(limit))) // Not supported only by test writers
	}
	if plan.precompressed && plan.servePrecompressed(responseWriter, request, opened, rewrittenPath) {
		return
	}
	// Go's file server redirects a URL that ends in "/index.html" to its folder ("./"), which serves the site's index.
	// Where index.html isn't an index of the site, that led to another file or to 404, and it was never served; and a
	// rewrite of that URL to another file was never applied. There the file opened is served as it is.
	if strings.HasSuffix(request.URL.Path, "/index.html") && (plan.rewritten || !plan.hasIndex("index.html")) {
		if content, canSeek := opened.file.(io.ReadSeeker); canSeek {
			if info, err := opened.file.Stat(); err == nil {
				customNetHttp.ServeContent(responseWriter, request, info.Name(), info.ModTime(), content)
				return
			}
		}
	}
	customNetHttp.ServeFileFS(responseWriter, request, opened, rootName(rewrittenPath))
}

// hasIndex reports whether name is one of the indexes of the plan's site.
func (plan *servePlan) hasIndex(name string) bool {
	for _, index := range plan.indexes {
		if index == name {
			return true
		}
	}
	return false
}

// folderRedirect answers a request that names a folder without its final "/" with a redirection to the same path
// with it, and the same query: 301 for GET and HEAD, and 308 for the rest, which keep their method and body. The
// target is the clean path, which starts with a single "/" (never "//host"), each segment encoded.
func folderRedirect(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, cleanPath string) {
	segments := strings.Split(cleanPath, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	target := strings.Join(segments, "/") + "/"
	if _, query, hasQuery := strings.Cut(request.RequestURI, "?"); hasQuery {
		target += "?" + query
	}
	code := 301
	if request.Method != customNetHttp.MethodGet && request.Method != customNetHttp.MethodHead {
		code = 308
	}
	customNetHttp.Redirect(responseWriter, request, target, code)
}

// ambiguousScriptName reports whether the path of a file, with its extension as ext gives it, could be another
// file's on some file system: a segment with "~" and a digit (a short name) or with ":" (a stream), or an extension
// with characters outside ASCII.
func ambiguousScriptName(filePath string, extension string) bool {
	for i := 0; i < len(extension); i++ {
		if extension[i] >= 0x80 {
			return true
		}
	}
	for i := 0; i < len(filePath); i++ {
		if filePath[i] == ':' || filePath[i] == '~' && i+1 < len(filePath) && filePath[i+1] >= '0' && filePath[i+1] <= '9' {
			return true
		}
	}
	return false
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
	root *os.Root
	name string
	file fs.File
}

// notServedTypes are the types of what a site never serves: a FIFO, a socket or a device isn't content, and reading
// one waits, or takes what was meant for another program.
const notServedTypes = fs.ModeNamedPipe | fs.ModeSocket | fs.ModeDevice | fs.ModeCharDevice

// openSiteFile opens name through the Root of a site, and returns it with its information, unless it is one of
// notServedTypes, which is answered as a name that isn't there. Opening a FIFO waits for a writer, and held a thread of
// the server for each request: on Unix the name is opened without waiting (siteOpenFlags), and what was opened is
// looked at, in one walk of its path. Looking at the name before opening it walked the path twice through the Root, for
// every file: half as long again to serve one on Windows, which has no FIFO in a folder, and a fifth on Linux.
func openSiteFile(root *os.Root, name string) (*os.File, fs.FileInfo, error) {
	file, err := root.OpenFile(name, siteOpenFlags, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err == nil && info.Mode()&notServedTypes != 0 {
		err = fs.ErrNotExist
	}
	if err != nil {
		file.Close() // #nosec G104 -- it is discarded: the error that matters is the one returned
		return nil, nil, err
	}
	return file, info, nil
}

// open opens name through the Root, keeping it (and closing the one kept before), and returns its information. Only a
// file or a folder is opened (openSiteFile).
func (opened *openedFileFS) open(name string) (fs.FileInfo, error) {
	opened.close()
	file, info, err := openSiteFile(opened.root, name)
	if err != nil {
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
	file, _, err := openSiteFile(opened.root, name)
	if err != nil {
		return nil, err
	}
	return file, nil
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

// foldRewrites is set where the file system ignores case (Windows, macOS): there "/PRIVATE/x" opens the file of
// "/private/x", so the rewrites of "/private/" must take it too.
var foldRewrites = runtime.GOOS == "windows" || runtime.GOOS == "darwin"

// rewriteKey looks key up among the rewrites of a site: as written and, where names fold, else the first, in byte
// order, that differs from it only in case. That one is found by foldKey in folded, which has those of the site by
// it (rewriteFolds); it is nil where names don't fold.
func rewriteKey(rewrites map[string]string, folded map[string]string, key string) (string, bool) {
	if _, found := rewrites[key]; found || folded == nil {
		return key, found
	}
	match, found := folded[foldKey(key)]
	return match, found
}

// rewriteFolds returns what rewriteKey needs to look up, among the rewrites of a site that has some, a key written
// in other capitals: those rewrites by foldKey where names fold (foldRewrites, or a sites directory that does), nil
// where they don't. Callers hold the global lock.
func rewriteFolds(domain string, subdomain string) map[string]string {
	if foldRewrites || sitesDirFolds.Load() {
		return foldedRewritesOf(domain, subdomain)
	}
	return nil
}

// rewrite finds the rewrite of a decoded, clean request path: the path itself, then the folder named without its
// final "/" (a rewrite of "/private/" takes "/private", which would serve that folder's index), then each folder
// that contains it, longest first, then "/". It returns the target and the key that matched. What doesn't depend on
// the key is found once: a site without rewrites, as most are, has nothing to look for, and whether names fold is the
// same for every key of a request, asked once its path isn't a rewrite as it is written.
func rewrite(requestURI string, domain string, subdomain string) (string, string) {
	rewrites := sitesMap[domain][subdomain]
	if len(rewrites) == 0 {
		return "", ""
	}
	if target, found := rewrites[requestURI]; found {
		return target, requestURI
	}
	folded := rewriteFolds(domain, subdomain)
	if folded != nil {
		if key, found := folded[foldKey(requestURI)]; found {
			return rewrites[key], key
		}
	}
	if requestURI == "/" { // Nothing else to try for the root
		return "", ""
	}
	if !strings.HasSuffix(requestURI, "/") {
		if key, found := rewriteKey(rewrites, folded, requestURI+"/"); found {
			return rewrites[key], key
		}
	}
	path := requestURI // Each folder is its beginning, up to a "/": no text is made for it
	requestURI = requestURI[1:]
	for {
		slash := strings.LastIndexByte(requestURI, '/')
		if slash == -1 {
			break
		}
		slash++
		if key, found := rewriteKey(rewrites, folded, path[:slash+1]); found {
			return rewrites[key], key
		}
		requestURI = requestURI[:slash-1]
	}
	if key, found := rewriteKey(rewrites, folded, "/"); found {
		return rewrites[key], key
	} // At the end of large unmatched string is obligatory to check if match with a top level rewrite
	return "", ""
}

// redirectHostStarters are what the host of a redirection can't start with: a browser skips "/" and "\" after the
// scheme, and "?" and "#" leave it empty.
const redirectHostStarters = `/\?#`

// rewriteRedirect answers a rewrite to "http(s)://" with a 302: to the exact target when it has a path or
// a query, or to the target domain followed by the original URI when it is only a domain. site and source name the
// rewrite, for the log.
func rewriteRedirect(secure bool, target string, query string, site string, source string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	scheme := "http://"
	if secure {
		scheme = "https://"
	}
	// A placeholder for the host gave nothing (no alias, for example), or the host starts with what a browser skips
	// ("/", "\"), and would take what follows for it: kept by an earlier version, or given by an expression
	if target == "" || strings.IndexByte(redirectHostStarters, target[0]) != -1 {
		// Once a minute for each rewrite, and with nothing of the request: a key of what the client sends (its host, with
		// any port) wrote a line for each request
		if logDueOnceAMinute("redirect|" + site + "|" + source) {
			slog.Warn("Rewrite without a host when responding: 500 (reported once a minute)", "site", site, "source", source)
		}
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

// chosenPath is what choose found for a request: the path to serve and the query a rewrite adds, whether that path is
// the target of a rewrite, the rewrite key that matched, the decoded, clean path the request named, and the headers
// that the expression of the rewrite read (Vary).
type chosenPath struct {
	path      string
	query     string
	rewritten bool
	match     string
	requested string
	vary      []string
}

// choose returns the path to serve (chosenPath), and whether to go on (false once it has answered: a redirection, or
// a path that can't be served).
func choose(overTLS bool, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, site siteMatch) (chosenPath, bool) {
	pathWithoutQuery, ok := cleanRequestPath(cutAt(request.RequestURI, '?')) // Decoded and inside the site
	if !ok {
		reqMsg(responseWriter, 404) // The same answer whether the file exists or not
		return chosenPath{}, false
	}
	rewriteResult, matchedRewrite := rewrite(pathWithoutQuery, site.siteDomain, site.siteSubdomain)
	if rewriteResult == "" {
		return chosenPath{path: pathWithoutQuery, requested: pathWithoutQuery}, true
	} // This is for unmatched URIs for rewrite
	var vary []string
	if source, isExpression := strings.CutPrefix(rewriteResult, "X"); isExpression {
		read := &expressionRequest{request: request, site: site, rewriteMatch: matchedRewrite, requestPath: pathWithoutQuery, overTLS: overTLS}
		var answered bool
		if rewriteResult, vary, answered = expressionTarget(responseWriter, read, source); answered {
			return chosenPath{}, false
		}
		if rewriteResult == "" { // The expression gave nothing: no rewrite for this request
			return chosenPath{path: pathWithoutQuery, requested: pathWithoutQuery, vary: vary}, true
		}
	} else if problem := textTargetProblem(rewriteResult); problem != "" { // Refused when added and read: checked again
		siteName := joinedSite(site.siteSubdomain, site.siteDomain)
		if logDueOnceAMinute(siteName + "|rewrite|" + matchedRewrite) {
			slog.Error("Rewrite whose target can't be answered: 500 (reported once a minute)", "site", siteName, "source", matchedRewrite, "reason", problem)
		}
		reqMsg(responseWriter, 500)
		return chosenPath{}, false
	} else {
		rewriteResult = shortcutWords(request, rewriteResult, site, matchedRewrite, pathWithoutQuery)
	}
	rewriteResult, query, _ := strings.Cut(rewriteResult, "?")
	switch rewriteResult[0] {
	case 'H', 'S':
		addVary(responseWriter.Header(), vary)
		rewriteRedirect(rewriteResult[0] == 'S', rewriteResult[1:], query, joinedSite(site.siteSubdomain, site.siteDomain), matchedRewrite, responseWriter, request)
		return chosenPath{}, false
	case 'N':
		rewriteResult = rewriteResult[1:]
	}
	if rewriteResult == "" { // A rewrite whose placeholders expand to nothing
		rewriteResult = "/"
	}
	// Placeholders may have produced ".." or "\\": the target is cleaned as a request path
	cleanPath, ok := cleanRequestPath(rewriteResult)
	if !ok {
		addVary(responseWriter.Header(), vary)
		reqMsg(responseWriter, 404)
		return chosenPath{}, false
	}
	return chosenPath{path: cleanPath, query: query, rewritten: true, match: matchedRewrite, requested: pathWithoutQuery, vary: vary}, true
}

// shortcutWords replaces the placeholders of a rewrite target, as stored ("N<path>", or "H"/"S" with the host for
// http:// and https://), for a request served by site. requestPath is the decoded, clean path that rewriteMatch, the
// matched rewrite key, was compared with. Each value is encoded for where it goes: in the path, segment by segment, keeping "/"; in the
// query, as one value; in the host, so that it can't change the shape of the URL. {REWRITE_COMPLEMENT} in the path
// takes the path alone, and in a redirection the request's query is added to the target's (an internal target
// already gets it). Unknown placeholders give nothing.
func shortcutWords(request *customNetHttp.Request, input string, site siteMatch, rewriteMatch string, requestPath string) string {
	writer := newTargetWriter(request, input != "" && (input[0] == 'H' || input[0] == 'S'))
	remaining := input
	for {
		// The first "}" after the "{", as the validator reads a target (unknownPlaceholder): with the first "}" of
		// all, one before the "{" ("/a}b/{DOMAIN}", accepted) left every placeholder of the target as it was written.
		openBraceIdx := strings.IndexByte(remaining, '{')
		if openBraceIdx == -1 {
			break
		}
		closeBraceIdx := strings.IndexByte(remaining[openBraceIdx:], '}')
		if closeBraceIdx == -1 {
			break
		}
		closeBraceIdx += openBraceIdx
		writer.text(remaining[:openBraceIdx])
		placeholder := remaining[openBraceIdx+1 : closeBraceIdx]
		remaining = remaining[closeBraceIdx+1:]
		replacer, placeholderExists := shortcutWordReplacers[placeholder]
		if !placeholderExists {
			continue
		}
		writer.value(placeholder, replacer(request, site, rewriteMatch, requestPath))
	}
	writer.text(remaining)
	return writer.finish()
}

// textTargetProblem says why a target written as a text (as it is kept: "N/…", or "H" or "S" and the host) can't be
// answered, or "". As in an expression (§6.3 of the API), the host of a redirection only gets keywords of the names of
// the site, of its wildcards and of the rewrite's key: a keyword of what the client sends ({FILE}, {FIRST_REQUEST}…)
// there chose where the visitors go. {SUBDOMAIN} and {FIRST_SUBDOMAIN}, which a wildcard subdomain lets the client
// choose ("evil.example" of evil.example.mysite.com), only start the host, with a "." and the rest of it after them.
// And {TURBO_CURRENT_DIR} is never in a target: it put a folder of the server in a URL. Unknown keywords are
// unknownPlaceholder's.
func textTargetProblem(target string) string {
	if target == "" {
		return ""
	}
	inHost := target[0] == 'H' || target[0] == 'S'
	labels := 0 // In the host: 1 right after labels that the client may choose, 2 after them and a "."
	text := func(literal string) bool {
		if !inHost {
			return true
		}
		var ok bool
		if labels, ok = hostAfterLabels(labels, literal); !ok {
			return false
		}
		inHost = !strings.ContainsAny(literal, "/?") // As targetWriter moves
		return true
	}
	remaining := target[1:]
	for { // As shortcutWords reads it
		open := strings.IndexByte(remaining, '{')
		if open == -1 {
			break
		}
		closing := strings.IndexByte(remaining[open:], '}')
		if closing == -1 {
			break
		}
		closing += open
		if !text(remaining[:open]) {
			return textTargetLabelsAtTheEnd
		}
		name := remaining[open+1 : closing]
		remaining = remaining[closing+1:]
		if name == currentDirPlaceholder {
			return "{" + currentDirPlaceholder + "} can't be in a rewrite: it would put a folder of the server in a URL"
		}
		if _, known := shortcutWordReplacers[name]; !known || !inHost {
			continue
		}
		switch class, _ := expr.ClassOf(name); class {
		case expr.Labels:
			labels = 1
		case expr.Config, expr.Host:
			if labels == 1 { // "{SUBDOMAIN}{DOMAIN}": the client's labels would start another name
				return textTargetLabelsAtTheEnd
			}
			labels = 0
		default:
			return "The host of a redirection can't have {" + name + "}: the client chooses it"
		}
	}
	if !text(remaining) || inHost && labels != 0 {
		return textTargetLabelsAtTheEnd
	}
	return ""
}

// labelsBeforeOneLabel reports whether the host of a redirection written as a text (as it is kept: "H" or "S" and the
// host) has {SUBDOMAIN} or {FIRST_SUBDOMAIN} followed by a "." and one label only, and nothing else: "{SUBDOMAIN}.com"
// passes textTargetProblem, but under a wildcard subdomain the visitor chooses that label, and so the whole domain
// (evil.yoursite.net to evil.com). Turbo warns of it (decision D6 of the review of v2.5): a site may want it, with a
// suffix of its own; the rest of the host is meant to be a domain of the site's.
func labelsBeforeOneLabel(target string) bool {
	if target == "" || target[0] != 'H' && target[0] != 'S' {
		return false
	}
	host := target[1:]
	if end := strings.IndexAny(host, "/?#"); end != -1 {
		host = host[:end]
	}
	for _, keyword := range []string{"{SUBDOMAIN}", "{FIRST_SUBDOMAIN}"} {
		at := strings.Index(host, keyword)
		if at == -1 {
			continue
		}
		rest, hasDot := strings.CutPrefix(host[at+len(keyword):], ".")
		rest, _, _ = strings.Cut(rest, ":")  // Without its port
		rest = strings.TrimSuffix(rest, ".") // Nor the dot that may end a host, which is no label more
		if hasDot && rest != "" && !strings.ContainsAny(rest, ".{") {
			return true
		}
	}
	return false
}

// textTargetLabelsAtTheEnd is why a host of a redirection can't end with the labels that the client may choose.
const textTargetLabelsAtTheEnd = "{SUBDOMAIN} and {FIRST_SUBDOMAIN}, which a wildcard lets the client choose, can't end the host of a redirection: write a \".\" and the rest of the host after them"

// targetPosition is where the next piece of a rewrite's target goes: the host of a redirection, the path or the
// query.
type targetPosition uint8

const (
	targetInHost targetPosition = iota
	targetInPath
	targetInQuery
)

// targetWriter writes the target of a rewrite for a request: the texts written in the target as they are, and the
// values placed in it, each encoded for where it goes, so that no value changes the shape of the URL. A "/" of a
// text goes from the host to the path, and a "?" to the query. The target starts with its mode ("N" for a path of
// the site, "H" or "S" for a redirection), which starts it in the path or in the host.
type targetWriter struct {
	request     *customNetHttp.Request
	result      strings.Builder
	position    targetPosition
	redirection bool
	addQuery    bool // The request's query goes at the end (REWRITE_COMPLEMENT in the path of a redirection)
}

func newTargetWriter(request *customNetHttp.Request, redirection bool) *targetWriter {
	writer := &targetWriter{request: request, position: targetInPath, redirection: redirection}
	if redirection {
		writer.position = targetInHost
	}
	return writer
}

// text writes a text of the target as it is.
func (writer *targetWriter) text(literal string) {
	for _, char := range literal {
		switch {
		case char == '/' && writer.position == targetInHost:
			writer.position = targetInPath
		case char == '?' && writer.position != targetInQuery:
			writer.position = targetInQuery
		}
		writer.result.WriteRune(char)
	}
}

// value writes the value of the placeholder name, encoded for where it goes: in the host, so that "/", "?" or "@"
// can't change the URL; in the path, each segment, keeping "/"; in the query, as one value.
func (writer *targetWriter) value(name string, value string) {
	switch writer.position {
	case targetInHost:
		writer.result.WriteString(url.QueryEscape(value)) // A host name is left as it is; "/", "?" or "@" can't change the URL
	case targetInPath:
		if name == "REWRITE_COMPLEMENT" { // The path here; a redirection adds the query to the target's
			// Without the query that the replacer adds: a "?" before it comes from the decoded path (%3F), and is
			// escaped with the segment. In any capitals: an expression may have changed them (lower, upper), and the
			// query goes on as the request sent it
			if queryStart := strings.IndexByte(writer.request.RequestURI, '?'); queryStart != -1 {
				if query := writer.request.RequestURI[queryStart:]; len(value) >= len(query) && strings.EqualFold(value[len(value)-len(query):], query) {
					value = value[:len(value)-len(query)]
				}
			}
			writer.addQuery = writer.redirection // An internal target already gets the request's query (CGI, QUERY_STRING)
		}
		segments := strings.Split(value, "/")
		for i, segment := range segments {
			segments[i] = url.PathEscape(segment)
		}
		writer.result.WriteString(strings.Join(segments, "/"))
	default:
		writer.result.WriteString(url.QueryEscape(value))
	}
}

// finish returns the target, with the request's query at its end when a REWRITE_COMPLEMENT in the path of a
// redirection asked for it.
func (writer *targetWriter) finish() string {
	if _, query, hasQuery := strings.Cut(writer.request.RequestURI, "?"); writer.addQuery && hasQuery && query != "" {
		if strings.IndexByte(writer.result.String(), '?') == -1 {
			writer.result.WriteByte('?')
		} else {
			writer.result.WriteByte('&')
		}
		for i := 0; i < len(query); i++ { // Control characters stay encoded, as in the rest of the target
			if c := query[i]; c < 0x20 || c == 0x7f {
				fmt.Fprintf(&writer.result, "%%%02X", c)
			} else {
				writer.result.WriteByte(c)
			}
		}
	}
	return writer.result.String()
}

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
