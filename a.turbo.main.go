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
	"crypto/tls"
	"errors"
	"log/slog"
	"maps"
	"net"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"turbo/customNetHttp"

	"encoding/json"
)

var (
	servers               = make([]*customNetHttp.Server, 2) // Current servers
	signedInTokens        = make(map[string]int64)           // Signed-in tokens
	persistentIPs         = make(map[string]int64)           // IPs marked by the global rate limiter (not saved)
	deniedIPs             atomic.Pointer[map[string]int64]   // IPs denied by the administrator until a UNIX date (saved as "@"; published copy, see setDeniedIPs)
	panelUser             atomicString                       // Panel username
	panelPasswordHash     atomicString                       // Panel password hash, saved as "PH" (see setPanelPassword)
	userFromEnv           bool                               // TURBO_USER set: it has priority over turbo.config
	passwordFromEnv       bool                               // TURBO_PASSWORD set: it has priority over turbo.config
	sitesDir              atomicString                       // Sites directory
	startDir              string                             // Directory where turbo.config is read first (working directory or TURBO_DIR)
	charReplacements      = make(map[string]string)          // Characters to encode
	fixedCharReplacements = make(map[string]bool)            // Fixed character replacements

	sitesMap      = make(map[string]map[string]map[string]string) // Sites map and rewrites
	siteSSLConfig = make(map[string]map[string]interface{})       // Sites with SSL
	mimeTypes     = make(map[string]map[string]string)            // MIME types
	customHeaders = make(map[string]map[string]string)            // Custom headers
	preprocessors = make(map[string]map[string]string)            // Preprocessors
	indexFiles    = make(map[string]map[string]int)               // Index files: name -> position (tried from the lowest)
	domainAliases = make(map[string]string)                       // Domain aliases

	serverTimeLimits    = &customNetHttp.TurboTimeLimits        // Server time limits (published copy, see setTimeLimits)
	serverRequestLimits = []int64{10000000000, 1000000000, 100} // Server request limits
	maxBodySize         = &customNetHttp.TurboMaxBodySize       // Server upload/body limit (MBB), read by the server on each request
	maxHeaderBytes      = &customNetHttp.TurboMaxHeaderBytes    // Maximum header bytes to read (MHB)
	maxURILength        = &customNetHttp.TurboMaxURILength      // Maximum URI length (MUB)

	lastRequestTimeNano  int64 // Reference time between requests
	requestCountInWindow int64 // Request count within the time window

	configCheckTicker = time.NewTicker(30 * time.Second)
	cleanupTicker     = time.NewTicker(60 * time.Second)

	tlsConfig = &tls.Config{NextProtos: []string{"h2", "http/1.1"}, Certificates: []tls.Certificate{}, MinVersion: tls.VersionTLS12}

	currentCertDomain string                    // Certificate domain currently being processed
	certRetryDelay    = 30 * time.Second        // Delay between certificate attempts, increasing by 100 ms per attempt
	configFileModTime int64                     // Config file modification time reference
	charEscapeLists   = make(map[rune][]string) // Character escape lists

	httpResponses      = &customNetHttp.TurboErrorTemplates // HTTP responses (published copy, see setHTTPResponses)
	fixedHTTPResponses = make(map[int]bool)                 // Fixed HTTP response codes

	visitsLogFile  *os.File // Visits log file pointer
	denialsLogFile *os.File // Denials log file pointer

	globalMutex          sync.RWMutex // Global mutex for shared state
	logMutex             sync.Mutex   // Guards the log file pointers, apart from globalMutex so logging never waits for it
	ipReferences         sync.Map     // References per IP
	maxHeaderKeyLength   = 48         // Maximum header key length
	maxHeaderValueLength = 512        // Maximum header value length
)

// Fixed names and texts (they were the keys of stringStore).
const (
	serverName          = customNetHttp.TurboServerName // Server header and default error template
	adminPathPrefix     = "admin"                       // Panel path: /admin:
	adminInsideName     = "inside"                      // Authenticated panel: /admin:inside:
	sessionHeaderName   = "ok"                          // Session header and login token prefix
	certificatesDirName = "turbo.certificates"          // Certbot's work directory
	publicDirName       = "@"                           // Public content of each site
	certFileName        = "fullchain.pem"               // Certificate of each site
	keyFileName         = "privkey.pem"                 // Private key of each site
	configFileName      = "turbo.config"                // Configuration
	denialsLogName      = "turbo.denials"               // Denials log
	visitsLogName       = "turbo.visits"                // Visits log
	panelPageName       = "#.html"                      // Panel page
	contentTypeHeader   = "Content-Type"                // Header name
	msgMissingData      = "Faltan datos"                // Generic API error
	devGUIDirName       = "turbo.dev"                   // GUI override directory
)

func main() {
	// Compile and compress with: go build -ldflags "-s -w"

	startTimeNano := time.Now().UnixNano()
	lastRequestTimeNano = startTimeNano

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil))) // Levels and timestamps; systemd keeps stdout in the journal
	slog.Info("Inicio", "servidor", serverName)

	// GUI access username & password
	panelUser.Set("Turbo")
	envValue, envExists := os.LookupEnv("TURBO_USER")
	if envExists {
		slog.Info("Usuario del panel tomado de TURBO_USER")
		panelUser.Set(envValue)
		userFromEnv = true
	}

	envValue, envExists = os.LookupEnv("TURBO_PASSWORD")
	if envExists {
		slog.Info("Contraseña del panel tomada de TURBO_PASSWORD")
		setPanelPassword(envValue)
		passwordFromEnv = true
	} else {
		setPanelPassword("Admin")
	}

	sitesDir.Set(currentDir())
	envValue, envExists = os.LookupEnv("TURBO_DIR")
	if envExists {
		slog.Info("Directorio de sitios tomado de TURBO_DIR", "directorio", envValue)
		sitesDir.Set(putSlash(envValue))
	}
	startDir = sitesDir.Get()

	var err error
	if httpAddr, err = listenAddress("TURBO_HTTP_ADDR", httpAddr); err != nil {
		slog.Error("TURBO_HTTP_ADDR no válida", "error", err)
		os.Exit(1)
	}
	if httpsAddr, err = listenAddress("TURBO_HTTPS_ADDR", httpsAddr); err != nil {
		slog.Error("TURBO_HTTPS_ADDR no válida", "error", err)
		os.Exit(1)
	}

	setHTTPResponses(func(responses map[int]string) { responses[0] = serverName + `\n{TURBO_RESPONSE_CODE}` })
	fixedHTTPResponses = map[int]bool{0: true}

	charReplacements[";"] = "-.-" // This group cannot be part of charEscapeLists because it must be transferred to the frontend
	charReplacements["#"] = "-,-"
	charReplacements["&"] = "-_-"
	fixedCharReplacements = map[string]bool{";": true, "#": true, "&": true}

	charEscapeLists['J'] = []string{
		"\\", "\"", "\t", "\r", "\n", "\f", "\b",
		`\\`, `\\"`, `\\t`, `\\r`, `\\n`, `\\f`, `\\b`,
	}

	updateSettings(false)
	servers[0] = createSafeServer(tlsConfig)
	servers[1] = createHttpServer()
	runRecovering("renewCertificates", renewCertificates)
	renewTicker := time.NewTicker(24 * time.Hour)
	for {
		select {
		case <-renewTicker.C:
			runRecovering("renewCertificates", renewCertificates)
		case <-configCheckTicker.C:
			runRecovering("updateSettings", func() { updateSettings(true) })
		case <-cleanupTicker.C:
			runRecovering("cleanOldValues", func() {
				cleanOldValues(&signedInTokens)
				cleanOldValues(&persistentIPs)
				withGlobalLock(cleanDeniedIPs)
				cleanIPReferences()
			})
		}
	}
}

// runRecovering runs a periodic task of main() and logs a panic instead of ending the process.
func runRecovering(taskName string, task func()) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("Panic en "+taskName, "error", p)
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

// setDeniedIPs publishes a modified copy of the denied IPs. Callers hold the global lock, so writes don't
// overlap, while the rate limiter reads the published list without it.
func setDeniedIPs(change func(map[string]int64)) {
	list := maps.Clone(deniedIPList())
	if list == nil {
		list = make(map[string]int64)
	}
	change(list)
	deniedIPs.Store(&list)
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

// withGlobalLock runs fn holding the global write lock, releasing it even if fn panics.
func withGlobalLock(fn func()) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	fn()
}

func createSafeServer(tlsConfig *tls.Config) *customNetHttp.Server {
	server := newHTTPSServer(tlsConfig)
	if len(siteCertificates) > 0 {
		return safeServerStart(server, tlsConfig)
	}

	return server
}

// newHTTPSServer builds the HTTPS server, without listening yet.
func newHTTPSServer(tlsConfig *tls.Config) *customNetHttp.Server {
	return &customNetHttp.Server{
		ReadHeaderTimeout: serverTimeLimits.Load().RHT,
		ReadTimeout:       serverTimeLimits.Load().RT,
		WriteTimeout:      serverTimeLimits.Load().WT,
		IdleTimeout:       serverTimeLimits.Load().IT,
		ConnState:         connHandler,
		Handler:           customNetHttp.HandlerFunc(serverHandlerFn("s")),
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn), // Connection errors (TLS, HTTP/2)
		TLSConfig:         tlsConfig,
		HTTP2:             &customNetHttp.HTTP2Config{MaxConcurrentStreams: http2MaxStreams},
	}
}

func safeServerStart(server *customNetHttp.Server, tlsConfig *tls.Config) *customNetHttp.Server {
	listener, err := tls.Listen("tcp", httpsAddr, tlsConfig) // #nosec G102 -- a web server listens on every interface by default; TURBO_HTTPS_ADDR narrows it
	if err != nil {
		slog.Error("No se puede abrir la dirección HTTPS", "dirección", httpsAddr, "error", err)
		return server
	}
	httpsListening = true

	go func() {
		if err = server.Serve(listener); err != nil {
			slog.Error("Servidor HTTPS detenido", "error", err)
			listener.Close()
			return
		}
	}()

	return server
}

func createHttpServer() *customNetHttp.Server {
	server := &customNetHttp.Server{
		ReadHeaderTimeout: serverTimeLimits.Load().RHT,
		ReadTimeout:       serverTimeLimits.Load().RT,
		WriteTimeout:      serverTimeLimits.Load().WT,
		IdleTimeout:       serverTimeLimits.Load().IT,
		ConnState:         connHandler,
		Handler:           customNetHttp.HandlerFunc(serverHandlerFn("")),
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn), // Connection errors
	}

	return httpServerStart(server)
}

// http2MaxStreams is the maximum of concurrent HTTP/2 streams per connection (Go's default is 250).
const http2MaxStreams = 50

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
		return "", errors.New("puerto no válido: " + port)
	}
	return net.JoinHostPort(host, port), nil
}

// httpServerStart serves on httpAddr (:80). Without it Turbo can't work, so it ends with an error instead of
// staying alive without serving (systemd and the like then see the failure and restart it).
func httpServerStart(server *customNetHttp.Server) *customNetHttp.Server {
	listener, err := net.Listen("tcp", httpAddr) // #nosec G102 -- a web server listens on every interface by default; TURBO_HTTP_ADDR narrows it
	if err != nil {
		slog.Error("No se puede abrir la dirección HTTP", "dirección", httpAddr, "error", err)
		os.Exit(1)
	}

	go func() {
		if err = server.Serve(listener); err != nil {
			slog.Error("Servidor HTTP detenido", "error", err)
			listener.Close()
			return
		}
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
			visitsLogFile.Close()
		}
		visitsLogFile = logFile
	case denialsLogName:
		if denialsLogFile == logFile {
			return
		}
		if denialsLogFile != nil {
			denialsLogFile.Close()
		}
		denialsLogFile = logFile
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

// refreshLogFiles opens or closes each log depending on whether its file exists in baseDir. It runs with the
// periodic settings check, so requests never stat the files.
func refreshLogFiles(baseDir string) {
	for _, logType := range []string{visitsLogName, denialsLogName} {
		_, statErr := os.Stat(baseDir + logType)
		isOpen := serverGetLogState(logType) != nil
		if statErr == nil && !isOpen {
			if logFile, openErr := os.OpenFile(baseDir+logType, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); openErr == nil { // #nosec G304 -- fixed log name in the sites directory
				serverSetLogState(logType, logFile)
			}
		} else if statErr != nil && isOpen {
			serverSetLogState(logType, nil)
		}
	}
}

func serverWriteLogs(logType string, request *customNetHttp.Request, timestamp int64, prefix string) {
	line := ""
	if request == nil {
		line = prefix + " " + "\n"
	} else {
		line = prefix + " " + request.RemoteAddr + " " + strconv.FormatInt(timestamp, 10) + " " + request.Method + " " + request.Host + " " + request.RequestURI + " " + "\n"
	}

	logMutex.Lock()
	defer logMutex.Unlock()
	logFile := visitsLogFile
	if logType == denialsLogName {
		logFile = denialsLogFile
	}
	if logFile != nil {
		logFile.WriteString(line)
	}
}

func serverHandlerFn(serverType string) func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
	return func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		currentTimestamp := time.Now().Unix()

		/* New deny method */
		clientIP := ipAddr(r.RemoteAddr)

		if limited, retryAfter := rateLimited(clientIP); limited {
			w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
			reqMsg(w, r, 429)
			return
		}
		/* End new deny method */

		serverWriteLogs(visitsLogName, r, currentTimestamp, "Visit")

		if console(w, r) {
			return
		}

		// The read lock covers only resolving the request: the file or CGI is served after releasing it,
		// so a slow response doesn't hold back the panel nor, through its pending Lock, other requests.
		globalMutex.RLock()
		plan := resolveRequest(serverType, w, r)
		globalMutex.RUnlock()
		if plan != nil {
			plan.serve(w, r)
		}
	}
}

// resolveRequest reads what the request needs from the shared settings. It writes redirects and errors
// itself and returns nil; otherwise it returns a plan that serves the response without the lock. Callers
// hold the global read lock.
func resolveRequest(serverType string, w customNetHttp.ResponseWriter, r *customNetHttp.Request) *servePlan {
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

	if _, siteFound = domainAliases[fullHost]; siteFound {
		validHost, wildcardDomain, subdomain, domain = host(domainAliases[fullHost])
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
		reqMsg(w, r, 404)
		return nil
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

	return serve(serverType, domain, effectiveDomain, subdomain, firstDomain, firstSubdomain, w, r)
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
	siteCertificates = make(map[string]*tls.Certificate)
	certificatesByName.Store(&map[string]*tls.Certificate{})
	logMutex.Lock()
	for _, logFile := range []*os.File{visitsLogFile, denialsLogFile} {
		if logFile != nil {
			logFile.Close()
		}
	}
	visitsLogFile = nil
	denialsLogFile = nil
	logMutex.Unlock()
}

func updateSettings(checkSitesFlag bool) {
	updateSettingsFollowing(checkSitesFlag, 0)
}

// updateSettingsFollowing is updateSettings counting how many times "M" moved it to another sites directory,
// to stop if two configs point at each other.
func updateSettingsFollowing(checkSitesFlag bool, redirects int) {
	if checkSitesFlag {
		checkSites()
	}

	globalMutex.RLock()
	baseDir := sitesDir.Get()
	configFileName := configFileName
	contentDirName := publicDirName
	lastConfigModTime := configFileModTime
	globalMutex.RUnlock()

	refreshLogFiles(baseDir)

	dirEntries, err := os.ReadDir(baseDir)
	if err != nil {
		slog.Error("No se puede leer el directorio de sitios", "directorio", baseDir, "error", err)
		return
	}

	configFileInfo, err := os.Stat(baseDir + configFileName)
	var configModTime int64
	if err != nil {
		configModTime = 1
	} else {
		configModTime = configFileInfo.ModTime().UnixNano()
	}

	if lastConfigModTime != configModTime {
		withGlobalLock(func() {
			configFileModTime = configModTime
			readSiteConfigFrom(baseDir + configFileName)
		})
		if configModTime == 1 {
			slog.Info("Sin turbo.config: configuración por defecto")
		} else {
			slog.Info("turbo.config leído y aplicado")
		}
		if newDir := sitesDir.Get(); newDir != baseDir && redirects < 2 { // "M" points elsewhere: read the config there
			slog.Info("Directorio de sitios", "directorio", newDir)
			resetSettings()
			withGlobalLock(func() { configFileModTime = 0 })
			updateSettingsFollowing(checkSitesFlag, redirects+1)
			return
		}
	}

	for _, entry := range dirEntries { // This is used when input is like: #.domain.com
		entryName := entry.Name()
		wildcardName := putWildcards(entryName)
		if hostValid, _ := hostOk(wildcardName, false); !hostValid {
			continue
		}

		_, err = os.ReadDir(baseDir + entryName + "/" + contentDirName)
		if err != nil {
			continue
		}

		subdirEntries, err := os.ReadDir(baseDir + entryName)
		if err != nil {
			continue
		}

		globalMutex.RLock()
		siteExistsResult := siteExists(wildcardName, "")
		globalMutex.RUnlock()

		if !siteExistsResult {
			constructSite(wildcardName, "")
			withGlobalLock(func() {
				subdomainContentCheckers["!"](false, siteSSLConfig[wildcardName], true, wildcardName, "") // Set first true to print errors
			})
			if checkSitesFlag {
				slog.Info("Sitio creado en disco y activado", "sitio", wildcardName)
			}
		}

		for _, entry = range subdirEntries {
			subEntryName := entry.Name()
			subWildcardName := putWildcards(subEntryName)
			if hostValid, _ := hostOk(subWildcardName+"."+changeWildcards(wildcardName, "x"), false); !hostValid {
				continue
			}

			contentDirInfo, err := os.Stat(baseDir + entryName + "/" + subEntryName + "/" + contentDirName)

			if err != nil {
				continue
			}

			globalMutex.RLock()
			siteExistsResult = siteExists(wildcardName, subWildcardName)
			globalMutex.RUnlock()

			if contentDirInfo.IsDir() && !siteExistsResult {
				constructSite(wildcardName, subWildcardName)
				withGlobalLock(func() {
					subdomainContentCheckers["!"](false, siteSSLConfig[subWildcardName+"."+wildcardName], true, wildcardName, subWildcardName)
				})
				if checkSitesFlag {
					slog.Info("Sitio creado en disco y activado", "sitio", subWildcardName+"."+wildcardName)
				}
			}
		}
	}
}

// connHandler closes new connections from an IP that is already blocked. Requests are counted, and
// answered with 429, in the handler (rateLimited).
func connHandler(conn net.Conn, connState customNetHttp.ConnState) {
	if connState != customNetHttp.StateNew {
		return
	}

	if blocked, _ := ipBlocked(ipAddr(conn.RemoteAddr().String())); blocked {
		conn.Close()
	}
}

// ipBlocked reports whether the IP is denied or blocked by the limiter, and the seconds left, without
// counting a request.
func ipBlocked(ip string) (bool, int64) {
	now := time.Now().Unix()
	if deniedUntil, isDenied := deniedIPList()[ip]; isDenied && deniedUntil > now {
		return true, deniedUntil - now
	}
	ipRef, found := ipReferences.Load(ip)
	if !found {
		return false, 0
	}
	ipData := ipRef.(*IPReference)
	ipData.mutex.Lock()
	defer ipData.mutex.Unlock()
	if ipData.blockedUntil > now {
		return true, ipData.blockedUntil - now
	}
	return false, 0
}

// rateLimited counts a request of the IP in the per-IP and global limiters. When the request must be
// rejected, it also returns the seconds to send in Retry-After.
func rateLimited(ip string) (bool, int64) {
	if perIpNotAvailable(ip, true) {
		if blocked, retryAfter := ipBlocked(ip); blocked {
			return true, retryAfter
		}
		return true, 1
	}
	if globalAndPerIpControl(ip) {
		windowSeconds := (atomic.LoadInt64(&serverRequestLimits[1]) + int64(time.Second) - 1) / int64(time.Second)
		return true, max(windowSeconds, 1)
	}
	return false, 0
}

// cleanIPReferences forgets the IPs whose counting window ended more than CIL ago and that aren't blocked:
// their next request would start from zero anyway.
func cleanIPReferences() {
	now := time.Now()
	intervalLimit := atomic.LoadInt64(&serverRequestLimits[0])
	ipReferences.Range(func(ip, ipRef any) bool {
		ipData := ipRef.(*IPReference)
		ipData.mutex.Lock()
		idle := now.UnixNano()-ipData.lastRequestNano > intervalLimit && ipData.blockedUntil <= now.Unix()
		ipData.mutex.Unlock()
		if idle {
			ipReferences.CompareAndDelete(ip, ipRef)
		}
		return true
	})
}

func perIpNotAvailable(ip string, incrementCounter bool) bool {
	deniedUntil, isDenied := deniedIPList()[ip] // Without the global lock, like the rest of the limiter
	if isDenied && deniedUntil > time.Now().Unix() {
		return true
	}

	ipRef, _ := ipReferences.LoadOrStore(ip, &IPReference{lastRequestNano: time.Now().UnixNano()})
	ipData := ipRef.(*IPReference)

	ipData.mutex.Lock()
	defer ipData.mutex.Unlock()

	if ipData.blockedUntil > time.Now().Unix() {
		return true
	}

	nowNano := time.Now().UnixNano()
	if incrementCounter {
		ipData.requestCount++
	}

	timeDiff := nowNano - ipData.lastRequestNano
	intervalLimit := atomic.LoadInt64(&serverRequestLimits[0])
	windowLimit := atomic.LoadInt64(&serverRequestLimits[1])
	maxRequests := atomic.LoadInt64(&serverRequestLimits[2])

	if timeDiff > intervalLimit {
		ipData.lastRequestNano = nowNano
		ipData.requestCount = 1
	}

	if (timeDiff > windowLimit && ipData.requestCount < maxRequests) || windowLimit == 0 || maxRequests == 0 {
		return false
	}

	requestRatio := ipData.requestCount / maxRequests
	timeRatio := timeDiff / windowLimit

	if requestRatio > timeRatio {
		globalMutex.RLock()
		_, persistent := persistentIPs[ip]
		globalMutex.RUnlock()

		ipData.blockedUntil = time.Now().Unix()
		denialMsg := ip + " conn denial"

		if persistent {
			ipData.blockedUntil += 10
			denialMsg += " persistent"
		} else {
			ipData.blockedUntil += 5
		}

		serverWriteLogs(denialsLogName, nil, 0, denialMsg)

		return true
	}

	return false
}

func globalAndPerIpControl(ip string) bool {
	var globalInterval int64 = atomic.LoadInt64(&serverRequestLimits[0])
	var globalWindow int64 = atomic.LoadInt64(&serverRequestLimits[1])
	var globalMaxReqs int64 = atomic.LoadInt64(&serverRequestLimits[2])

	lastGlobalTime := atomic.LoadInt64(&lastRequestTimeNano)
	globalReqCount := atomic.LoadInt64(&requestCountInWindow)
	atomic.AddInt64(&requestCountInWindow, 1)

	nowNano := time.Now().UnixNano()
	timeDiff := nowNano - lastGlobalTime
	globalReqCount++

	if (timeDiff > globalWindow && globalReqCount < globalMaxReqs) || globalWindow == 0 || globalMaxReqs == 0 { // Continue with unnecessary checking
		return false
	}

	globalReqRatio := (globalReqCount / globalMaxReqs)
	globalTimeRatio := (timeDiff / globalWindow)

	// Shows details

	exceeded := false

	if globalReqRatio > globalTimeRatio {
		persistUntil := time.Now().Unix() + 59 // Time to preserve during cleanOldValues
		globalMutex.Lock()
		persistentIPs[ip] = persistUntil
		globalMutex.Unlock()
		serverWriteLogs(denialsLogName, nil, 0, ip+" rate limit exceed at: "+strconv.FormatInt(persistUntil, 10))
		exceeded = true
	}

	if timeDiff > globalInterval {
		atomic.StoreInt64(&lastRequestTimeNano, nowNano)
		atomic.StoreInt64(&requestCountInWindow, 1)
	}

	return exceeded
}

func _constructSite(domain string, subdomain string) {
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

// constructSite adds a new site (from the panel or found in the sites directory), with index.html as its
// index. Sites read from turbo.config use _constructSite and keep the indexes saved there.
func constructSite(domain string, subdomain string) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	_constructSite(domain, subdomain)
	siteKey := domain
	if subdomain != "" {
		siteKey = subdomain + "." + domain
	}
	addIndex(siteKey, "index.html")
}

// addIndex appends an index to a site, after the existing ones (DP10). An index already there keeps its place.
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

func deleteSite(domain string, subdomain string) {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	var key string
	if subdomain != "" {
		delete(sitesMap[domain], subdomain)
		domain = subdomain + "." + domain
	} else {
		for key = range sitesMap[domain] {
			if key != "" {
				setSiteCertificate(key+"."+domain, nil)
			}
		}
		delete(sitesMap, domain)
	}
	setSiteCertificate(domain, nil)
	delete(preprocessors, domain)
	delete(indexFiles, domain)
	delete(siteSSLConfig, domain)
	delete(mimeTypes, domain)
	delete(customHeaders, domain)
	for key, subdomain = range domainAliases {
		if subdomain == domain {
			delete(domainAliases, key)
		}
	}
}

func checkSites() {
	type missingSite struct{ subdomain, domain string }
	var missing []missingSite

	globalMutex.RLock()
	for domain := range sitesMap {
		for subdomain := range sitesMap[domain] {
			if exists, _ := siteExistenceCheckers["/"](false, domain, subdomain); !exists { // siteExistenceCheckers["/"] is used when input is like: *.domain.com
				missing = append(missing, missingSite{subdomain, domain})
			}
		}
	}
	globalMutex.RUnlock()

	for _, site := range missing {
		deleteSite(site.domain, site.subdomain)

		name := site.domain
		if site.subdomain != "" {
			name = site.subdomain + "." + site.domain
		}
		slog.Info("Sitio borrado del disco y desactivado", "sitio", name)
	}
}

// httpsEnabled reports whether the site has HTTPS redirection on. A host that isn't a configured site has none.
func httpsEnabled(siteKey string) bool {
	certIndex, isSet := siteSSLConfig[siteKey]["S"].(int)
	return isSet && certIndex != 0
}

func redir(schemeSuffix string, host string, subdomain string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, statusCode int) {
	if subdomain != "" {
		subdomain += "."
	}
	customNetHttp.Redirect(responseWriter, request, "http"+schemeSuffix+"://"+subdomain+host+request.RequestURI, statusCode)
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

func serve(serverType string, host string, domain string, subdomain string, firstDomain string, firstSubdomain string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) *servePlan { //i, n, o
	wildcardMatch, _, _, wildcardDomain := detectWildcards(subdomain, domain)

	if !wildcardMatch {
		// Without 404 response: b = s
		reqMsg(responseWriter, request, 404)
		return nil
	}

	if serverType == "" && subdomain != "" && httpsRedirect(wildcardDomain+"."+domain, responseWriter, request) {
		return nil
	}

	var continueServe bool
	rewrittenPath, queryString, continueServe := choose(responseWriter, request, host, domain, wildcardDomain, subdomain, firstDomain, firstSubdomain)
	if !continueServe {
		return nil
	}
	if rewrittenPath == "" { // A rewrite whose placeholders expand to nothing
		rewrittenPath = "/"
	}
	request.RequestURI = rewrittenPath

	serverType = sitesDir.Get() + changeWildcards(domain) + "/"
	if subdomain != "" {
		if wildcardMatch {
			subdomain = changeWildcards(wildcardDomain)
		}
		serverType += subdomain + "/" + publicDirName
	} else {
		serverType += publicDirName
	}

	if subdomain != "" {
		subdomain = wildcardDomain + "." + domain
	} else {
		subdomain = domain
	}

	plan := &servePlan{
		root:          serverType,
		path:          rewrittenPath,
		queryString:   queryString,
		mimeTypes:     cloneOrNil(mimeTypes[subdomain]),
		preprocessors: cloneOrNil(preprocessors[subdomain]),
		headers:       cloneOrNil(customHeaders[subdomain]),
	}
	if len(indexFiles[subdomain]) > 0 {
		plan.indexes = orderedIndexes(subdomain)
	}

	return plan
}

// serve sends the file, or runs its preprocessor, without the global lock.
func (plan *servePlan) serve(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	rewrittenPath := plan.path
	fileInfo, err := os.Stat(plan.root + rewrittenPath)
	if err != nil {
		reqMsg(responseWriter, request, 404)
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
			preprocFileInfo, err := os.Stat(plan.root + rewrittenPath + indexFile)
			if err == nil && !preprocFileInfo.IsDir() { // Make sure this is the best error handling for Indexes, before: !os.IsNotExist(e)
				rewrittenPath += indexFile
				indexFile = ""
				break
			}
		}

		if indexFile != "" {
			reqMsg(responseWriter, request, 404)
			return
		}
	}

	extension := ext(rewrittenPath)
	responseHeaders := responseWriter.Header()
	for name, value := range plan.headers {
		responseHeaders.Set(name, value)
	} // Headers inclution, only for what is served

	if preprocessor := plan.preprocessors[extension]; preprocessor != "" { // Verify preprocessors
		preprocFileInfo, err := os.Stat(preprocessor)
		if err != nil || preprocFileInfo.IsDir() { // Fail closed: never serve the source of a preprocessed file
			slog.Error("Preprocesador no disponible", "extensión", extension, "preprocesador", preprocessor)
			reqMsg(responseWriter, request, 500)
			return
		}
		dynamic(plan.root, rewrittenPath, plan.queryString, preprocessor, responseWriter, request, &responseHeaders)
		return
	}

	if mimeType, found := plan.mimeTypes[extension]; found {
		responseHeaders.Set(contentTypeHeader, mimeType)
	}
	customNetHttp.ServeFile(responseWriter, request, plan.root+rewrittenPath)
}

func dynamic(basePath string, requestPath string, queryString string, scriptPath string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, headers *customNetHttp.Header) {
	handler := new(customNetHttp.CgiHandler) // Before: new(cgi.Handler)
	handler.Path = scriptPath
	handler.Root = basePath
	handler.Timeout = serverTimeLimits.Load().WT             // Zero (no write timeout) leaves the CGI without limit
	handler.Env = append(handler.Env, "REDIRECT_STATUS=CGI") // This is need for execution of scripts (it will not executed if isn't set). Also depends of 'cgi.force-redirect' on php.ini.
	if request.ContentLength > maxBodySize.Load() {
		reqMsg(responseWriter, request, 413)
		return
	}
	request.Body = customNetHttp.MaxBytesReader(responseWriter, request.Body, maxBodySize.Load()) // Bodies of unknown length
	withoutSessionCookie(request)
	if request.URL.RawQuery != "" && queryString != "" {
		queryString = request.URL.RawQuery + "&" + queryString
	} else if request.URL.RawQuery != "" {
		queryString = request.URL.RawQuery
	}
	handler.Env = append(handler.Env, "QUERY_STRING="+queryString) // If not set, not includes rewrite query string
	handler.Env = append(handler.Env, "DOCUMENT_ROOT="+basePath)
	handler.Env = append(handler.Env, "SCRIPT_FILENAME="+basePath+requestPath)
	handler.ServeHTTP(responseWriter, request)
}

// withoutSessionCookie removes the panel session cookie from the request, so a CGI never receives it. Only that
// pair is cut from the raw header: the other cookies reach the CGI exactly as the browser sent them.
func withoutSessionCookie(request *customNetHttp.Request) {
	var kept []string
	removed := false
	for _, value := range request.Header["Cookie"] {
		var pairs []string
		for _, pair := range strings.Split(value, ";") {
			if name, _, _ := strings.Cut(pair, "="); strings.TrimSpace(name) == sessionCookieName {
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

func rewrite(requestURI string, domain string, subdomain string) (string, string) {
	var found bool
	if _, found = sitesMap[domain][subdomain][requestURI]; found {
		return sitesMap[domain][subdomain][requestURI], requestURI
	}
	if requestURI == "/" {
		return "", ""
	} // To prevent passing through 'choose' unecessary functions. Before: return y, ""
	requestURI = requestURI[1:]
	for {
		slash := strings.LastIndexByte(requestURI, '/')
		if slash == -1 {
			break
		}
		slash++
		if _, found := sitesMap[domain][subdomain]["/"+requestURI[:slash]]; found {
			return sitesMap[domain][subdomain]["/"+requestURI[:slash]], "/" + requestURI[:slash]
		} else {
			requestURI = requestURI[:slash-1]
		}
	}
	if _, found = sitesMap[domain][subdomain]["/"]; found {
		return sitesMap[domain][subdomain]["/"], "/"
	} // At the end of large unmatched string is obligatory to check if match with a top level rewrite
	return "", ""
}

// rewriteRedirect answers a rewrite to "http(s)://" with a 302 (DP8): to the exact target when it has a path or
// a query, or to the target domain followed by the original URI when it is only a domain.
func rewriteRedirect(secure bool, target string, query string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	scheme := "http://"
	if secure {
		scheme = "https://"
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
	pathWithoutQuery := cutAt(request.RequestURI, '?')
	rewriteResult, matchedRewrite := rewrite(pathWithoutQuery, domain, subdomain) // domain is the site map key and subdomain is the site subdomain map key, both in sitesMap
	if rewriteResult == "" {
		return pathWithoutQuery, "", true
	} // This is for unmatched URIs for rewrite
	rewriteResult = shortcutWords(request, rewriteResult, domain, subdomain, host, currentSubdomain, firstDomain, firstSubdomain, matchedRewrite)
	queryIndex := strings.IndexByte(rewriteResult, '?')
	if queryIndex != -1 {
		pathWithoutQuery = rewriteResult[queryIndex+1:]
		rewriteResult = rewriteResult[:queryIndex]
	} else {
		pathWithoutQuery = ""
	}
	switch rewriteResult[0] {
	case 'H', 'S':
		rewriteRedirect(rewriteResult[0] == 'S', rewriteResult[1:], pathWithoutQuery, responseWriter, request)
		return "", "", false
	case 'N':
		rewriteResult = rewriteResult[1:]
	}
	if rewriteResult != "" { // Placeholders may have produced ".." or "\\": keep the path inside the content directory
		cleanPath := path.Clean(rewriteResult)
		if cleanPath[0] != '/' || strings.IndexByte(rewriteResult, '\\') != -1 {
			reqMsg(responseWriter, request, 400)
			return "", "", false
		}
		if rewriteResult[len(rewriteResult)-1] == '/' && cleanPath != "/" {
			cleanPath += "/"
		}
		rewriteResult = cleanPath
	}
	return rewriteResult, pathWithoutQuery, true
}

func shortcutWords(request *customNetHttp.Request, input string, domain string, subdomain string, host string, currentSubdomain string, firstDomain string, firstSubdomain string, rewriteMatch string) string {
	remaining := input
	placeholder := ""
	result := ""
	var placeholderExists bool
	for {
		openBraceIdx := strings.IndexByte(remaining, '{')
		closeBraceIdx := strings.IndexByte(remaining, '}')
		if remaining == "" || openBraceIdx == -1 || closeBraceIdx == -1 || closeBraceIdx < openBraceIdx {
			break
		}
		placeholder = remaining[openBraceIdx+1 : closeBraceIdx]
		if _, placeholderExists = shortcutWordReplacers[placeholder]; placeholderExists {
			result += remaining[:openBraceIdx] + shortcutWordReplacers[placeholder](request, domain, subdomain, host, currentSubdomain, firstDomain, firstSubdomain, rewriteMatch)
		} else {
			result += remaining[:openBraceIdx]
		}
		if closeBraceIdx < len(remaining) {
			remaining = remaining[closeBraceIdx+1:]
		} else {
			remaining = ""
		}
	}
	result += remaining
	return result
}

func readSiteConfigFrom(configPath string) {
	// Probably need to check file permissions, because can't read and generate an err.
	if fileExists(configPath) {
		configBytes, err := os.ReadFile(configPath) // #nosec G304 -- path under the sites directory chosen by the administrator (TURBO_DIR or M)
		if err != nil || !json.Valid([]byte(configBytes)) {
			slog.Error("turbo.config ilegible o no es JSON válido: se aplica la configuración por defecto", "archivo", configPath, "error", err)
			setDefaultSettings()
			return
		}
		json.Unmarshal(configBytes, &rawConfigMap)
		configSchemaRead = migrateConfig(rawConfigMap, configBytes)
		if configSchemaRead < configSchema {
			slog.Warn("Configuración en esquema " + strconv.Itoa(configSchemaRead) + ": se aplicará la migración al guardar")
		} else if configSchemaRead > configSchema {
			slog.Warn("Configuración en esquema " + strconv.Itoa(configSchemaRead) + ", posterior al de esta versión (" + strconv.Itoa(configSchema) + "): se carga lo que se entiende y no se guardará sin confirmación")
		}
		loadCredentials(rawConfigMap["."])
		var keyExists bool
		var stringValue string
		//var subKey string
		var configKey string
		for configKey = range adminAddHandlers {
			if _, keyExists = rawConfigMap[configKey]; keyExists { // This is for another kind of lists in config file
				for subKey, subValue := range rawConfigMap[configKey] {
					stringValue, keyExists = subValue.(string)
					if keyExists {
						adminAddHandlers[configKey](subKey, stringValue)
					}
				}
				continue
			}
		}
		if _, keyExists = rawConfigMap["@"]; keyExists {
			slog.Info("IPs denegadas activas", "total", len(deniedIPList()))
		}
		for configKey = range defaultSettingValidators { // Default settings check
			if _, keyExists = rawConfigMap[configKey]; keyExists {
				for _, subValue := range defaultSettingKeysGroup[configKey] {
					if _, keyExists = rawConfigMap[configKey][subValue]; keyExists {
						stringValue, keyExists = rawConfigMap[configKey][subValue].(string)
						var subKeyIter string
						if keyExists {
							if keyExists, subKeyIter = defaultSettingValidators[configKey][subValue](stringValue, internalAuth); keyExists {
								continue
							}
							if _, keyExists = defaultSettingErrorExceptions[configKey][subValue][subKeyIter]; keyExists { // ME (E, for exceptions) There are some exceptions on errors, some cause unnecessary resets
								continue
							}
						}
					}
					defaultSettingsResetFallbacks[configKey][subValue]()
				}
			} else {
				for subMap := range defaultSettingsResetFallbacks[configKey] {
					defaultSettingsResetFallbacks[configKey][subMap]()
				} // Reset specific defaults if doesn't exists
			}
		}
		for domain := range rawConfigMap { // Site & subdomains existence check
			if _, keyExists = defaultSettingValidators[domain]; keyExists {
				continue
			}
			if !siteExistenceCheck(domain, "") {
				continue
			}
			for subKey := range rawConfigMap[domain] {
				if _, keyExists = subdomainContentCheckers[subKey]; keyExists || (subKey != "" && !siteExistenceCheck(domain, subKey)) {
					continue
				}
				subdomainData, keyExists := rawConfigMap[domain][subKey].(map[string]interface{})
				if !keyExists {
					continue
				}
				for settingKey := range subdomainContentCheckers { // Subdomains content check
					if _, keyExists = subdomainData[settingKey]; keyExists {
						subdomainContentCheckers[settingKey](false, subdomainData[settingKey], true, domain, subKey) // Returns something like: a, _
					}
				}
			}
		}
		rawConfigMap = make(map[string]map[string]interface{})
		return
	}
	configSchemaRead = configSchema
	setDefaultSettings()
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
			siteExistenceResetFallbacks[checker](domain, subdomain)
			return false
		}
	}
	return true
}

type IPReference struct {
	mutex           sync.Mutex
	blockedUntil    int64
	lastRequestNano int64
	requestCount    int64
}
