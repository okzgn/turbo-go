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
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"turbo/customNetHttp"

	//"net/http/cgi" // If you want to deactivate custom cgi library, just turn this on and delete (or rename) server.net.cgi...go files
	//"runtime/debug"

	"encoding/json"
	"sync/atomic"
)

var (
	servers                = customNetHttp.N  // Current servers
	signedInTokens         = customNetHttp.I  // Signed-in tokens
	persistentIPs          = customNetHttp.J  // Persistent IPs
	stringStore             = customNetHttp.S_ // String store
	charReplacements        = customNetHttp.B_ // Characters to encode
	fixedCharReplacements   = customNetHttp.BF // Fixed character replacements

	sitesMap                = customNetHttp.O // Sites map and rewrites
	siteSSLConfig           = customNetHttp.W // Sites with SSL
	mimeTypes               = customNetHttp.T // MIME types
	customHeaders           = customNetHttp.Q // Custom headers
	preprocessors            = customNetHttp.D // Preprocessors
	indexFiles               = customNetHttp.H // Index files
	domainAliases            = customNetHttp.A // Domain aliases

	serverTimeLimits       = customNetHttp.V  // Server time limits
	serverRequestLimits    = customNetHttp.G  // Server request limits
	maxBodySize             = customNetHttp.L_ // Server upload/body limit
	maxHeaderBytes          = customNetHttp.YH // Maximum header bytes to read
	maxURILength            = customNetHttp.YU // Maximum URI length
	maxUploadFiles          = customNetHttp.YX // Maximum files in an upload
	maxHeaderCount          = customNetHttp.YY // Maximum number of headers

	lastRequestTimeNano     = customNetHttp.Za // Reference time between requests
	requestCountInWindow    = customNetHttp.Zb // Request count within the time window

	configCheckTicker       = customNetHttp.Pa
	cleanupTicker            = customNetHttp.Pb

	tlsConfig                = customNetHttp.U

	currentCertDomain        = customNetHttp.CC // Certificate domain currently being processed
	certRetryDelayMs         = customNetHttp.CD // Delay between certificate attempts, increasing by 100 ms per attempt
	httpResponses            = customNetHttp.Y  // HTTP responses
	fixedHTTPResponses       = customNetHttp.YF // Fixed HTTP response codes
	configFileModTime        = customNetHttp.A_ // Config file modification time reference
	charEscapeLists          = customNetHttp.C_ // Character escape lists

	visitsLogFile             = customNetHttp.LV // Visits log file pointer
	denialsLogFile            = customNetHttp.LD // Denials log file pointer

	globalMutex               sync.RWMutex        // Global mutex for logs and shared state
	ipReferences              sync.Map            // References per IP
	maxHeaderKeyLength        = customNetHttp.H1_ // Maximum header key length
	maxHeaderValueLength      = customNetHttp.H2_ // Maximum header value length
)

func main() {
	// Compile and compress with: go build -ldflags "-s -w"
	// debug.SetGCPercent(1000) // Change the garbage collection frequency

	startTimeNano := time.Now().UnixNano()
	lastRequestTimeNano = startTimeNano

	stringStore["T"] = "OKZGN Turbo"
	fmt.Println(stringStore["T"])

	stringStore["B"] = "admin"
	stringStore["H"] = "inside"

	// GUI access username & password
	stringStore["U"] = "Turbo"
	envValue, envExists := os.LookupEnv("TURBO_USER")
	if envExists {
		fmt.Println("Username env var set.")
		stringStore["U"] = envValue
	}

	stringStore["P"] = "Admin"
	envValue, envExists = os.LookupEnv("TURBO_PASSWORD")
	if envExists {
		fmt.Println("Password env var set.")
		stringStore["P"] = envValue
	}

	stringStore["A"] = currentDir()
	envValue, envExists = os.LookupEnv("TURBO_DIR")
	if envExists {
		fmt.Println("Start dir env var set.")
		stringStore["A"] = putSlash(envValue)
	}

	stringStore["M"] = "ok"
	stringStore["S"] = "turbo.certificates"
	stringStore["F"] = "@"
	stringStore["C"] = "fullchain.pem"
	stringStore["K"] = "privkey.pem"
	stringStore["N"] = "turbo.config"
	stringStore["X"] = "turbo.denials"
	stringStore["G"] = "turbo.visits"
	stringStore["J"] = "#.html"
	stringStore["D"] = "Content-Type"
	stringStore["Z"] = "Faltan datos"
	stringStore["Y"] = "turbo.dev"

	httpResponses[0] = stringStore["T"] + `\n{TURBO_RESPONSE_CODE}`
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
	for {
		select {
		case <-configCheckTicker.C:
			updateSettings(true)
		case <-cleanupTicker.C:
			cleanOldValues(&signedInTokens)
			cleanOldValues(&persistentIPs)
		}
	}
}

func createSafeServer(tlsConfig *tls.Config) *customNetHttp.Server {
	t := &customNetHttp.Server{
		ReadHeaderTimeout: serverTimeLimits["RHT"],
		ReadTimeout:       serverTimeLimits["RT"],
		WriteTimeout:      serverTimeLimits["WT"],
		IdleTimeout:       serverTimeLimits["IT"],
		MaxHeaderBytes:    maxHeaderBytes,
		ConnState:         connHandler,
		Handler:           customNetHttp.HandlerFunc(serverHandlerFn("s")),
		TLSConfig:         tlsConfig,
	}

	if len(tlsConfig.Certificates) > 0 {
		return safeServerStart(t, tlsConfig)
	}

	return t
}

func safeServerStart(server *customNetHttp.Server, tlsConfig *tls.Config) *customNetHttp.Server {
	l, e := tls.Listen("tcp", ":443", tlsConfig)
	if e != nil {
		fmt.Println(e)
		return server
	}

	go func() {
		if e = server.Serve(l); e != nil {
			fmt.Println(e)
			l.Close()
			return
		}
	}()

	return server
}

func createHttpServer() *customNetHttp.Server {
	s := &customNetHttp.Server{
		ReadHeaderTimeout: serverTimeLimits["RHT"],
		ReadTimeout:       serverTimeLimits["RT"],
		WriteTimeout:      serverTimeLimits["WT"],
		IdleTimeout:       serverTimeLimits["IT"],
		MaxHeaderBytes:    maxHeaderBytes,
		ConnState:         connHandler,
		Handler:           customNetHttp.HandlerFunc(serverHandlerFn("")),
	}

	return httpServerStart(s)
}

func httpServerStart(server *customNetHttp.Server) *customNetHttp.Server {
	l, e := net.Listen("tcp", ":80")
	if e != nil {
		fmt.Println(e)
		return server
	}

	go func() {
		if e = server.Serve(l); e != nil {
			fmt.Println(e)
			l.Close()
			return
		}
	}()

	return server
}

func serverSetLogState(logType string, logFile *os.File) {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	switch logType {
	case stringStore["G"]:
		if visitsLogFile == logFile {
			return
		}
		if visitsLogFile != nil {
			visitsLogFile.Close()
		}
		visitsLogFile = logFile
	case stringStore["X"]:
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
	globalMutex.RLock()
	defer globalMutex.RUnlock()

	switch logType {
	case stringStore["G"]:
		return visitsLogFile
	case stringStore["X"]:
		return denialsLogFile
	}
	return nil
}

func serverWriteLogs(logType string, request *customNetHttp.Request, timestamp int64, prefix string) {
	l := serverGetLogState(logType)

	if l != nil {
		c := ""
		if request == nil {
			c = prefix + " " + "\n"
		} else {
			c = prefix + " " + request.RemoteAddr + " " + strconv.FormatInt(timestamp, 10) + " " + request.Method + " " + request.Host + " " + request.RequestURI + " " + "\n"
		}
		_, e := l.WriteString(c)
		if e == nil {
			return
		}
	}

	if _, e := os.Stat(stringStore["A"] + logType); e == nil {
		p, _e := os.OpenFile(stringStore["A"]+logType, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if _e == nil {
			serverSetLogState(logType, p)
		}
	} else {
		serverSetLogState(logType, nil)
	}
}

func serverHandlerFn(serverType string) func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
	return func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		currentTimestamp := time.Now().Unix()

		/* New deny method */
		clientIP := ipAddr(r.RemoteAddr)

		if perIpNotAvailable(clientIP, true) == true {
			reqMsg(w, r, 429)
			return
		}
		/* End new deny method */

		serverWriteLogs(stringStore["G"], r, currentTimestamp, "Visit")

		if console(w, r) {
			return
		}

		globalMutex.RLock()
		defer globalMutex.RUnlock()

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
			return
		}

		if subdomain == "" && siteSSLConfig[effectiveDomain]["W"] == true {
			redir(serverType, domain, "www", w, r, 301)
			return
		}

		if subdomain == "www" && siteSSLConfig[effectiveDomain]["R"] == true {
			redir(serverType, domain, "", w, r, 301)
			return
		}

		if serverType == "" && siteSSLConfig[fullHost]["S"] != 0 {
			redir("s", domain, subdomain, w, r, 301)
		}

		serve(serverType, domain, effectiveDomain, subdomain, firstDomain, firstSubdomain, w, r)
	}
}

func resetSettings() {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	sitesMap = make(map[string]map[string]map[string]string) // Sites map & rewrites
	siteSSLConfig = make(map[string]map[string]interface{})  // Sites with SSL
	mimeTypes = make(map[string]map[string]string)            // MIME types
	customHeaders = make(map[string]map[string]string)       // Headers
	preprocessors = make(map[string]map[string]string)       // Preprocessors
	indexFiles = make(map[string]map[string]bool)             // Indexes
	domainAliases = make(map[string]string)                   // Domain aliases
	tlsConfig.Certificates = []tls.Certificate{}
	tlsConfig.NameToCertificate = nil
	visitsLogFile = nil
	denialsLogFile = nil
}

func updateSettings(checkSitesFlag bool) {
	if checkSitesFlag {
		checkSites()
	}

	globalMutex.RLock()
	baseDir := stringStore["A"]
	configFileName := stringStore["N"]
	contentDirName := stringStore["F"]
	lastConfigModTime := configFileModTime
	globalMutex.RUnlock()

	dirEntries, e := os.ReadDir(baseDir)
	if e != nil {
		fmt.Println("Start dir:", baseDir, e)
		return
	}

	configFileInfo, e := os.Stat(baseDir + configFileName)
	var configModTime int64
	if e != nil {
		configModTime = 1
	} else {
		configModTime = configFileInfo.ModTime().UnixNano()
	}

	if lastConfigModTime != configModTime {
		globalMutex.Lock()
		configFileModTime = configModTime
		readSiteConfigFrom(baseDir + configFileName)
		globalMutex.Unlock()
		if configModTime == 1 {
			fmt.Println("Default settings applied.")
		} else {
			fmt.Println("Config file updated, readed and settings applied.")
		}
	}

	for _, entry := range dirEntries { // This is used when input is like: #.domain.com
		entryName := entry.Name()
		wildcardName := putWildcards(entryName)
		if hostValid, _ := hostOk(wildcardName, false); !hostValid {
			continue
		}

		_, e = os.ReadDir(baseDir + entryName + "/" + contentDirName)
		if e != nil {
			continue
		}

		subdirEntries, e := os.ReadDir(baseDir + entryName)
		if e != nil {
			continue
		}

		globalMutex.RLock()
		siteExistsResult := siteExists(wildcardName, "")
		globalMutex.RUnlock()

		if !siteExistsResult {
			constructSite(wildcardName, "")
			globalMutex.Lock()
			subdomainContentCheckers["!"](false, siteSSLConfig[wildcardName], true, wildcardName, "") // Set first true to print errors
			globalMutex.Unlock()
			if checkSitesFlag {
				fmt.Println("Site \"" + wildcardName + "\" added to filesystem and enabled on server.")
			}
		}

		for _, entry = range subdirEntries {
			subEntryName := entry.Name()
			subWildcardName := putWildcards(subEntryName)
			if hostValid, _ := hostOk(subWildcardName+"."+changeWildcards(wildcardName, "x"), false); !hostValid {
				continue
			}

			contentDirInfo, e := os.Stat(baseDir + entryName + "/" + subEntryName + "/" + contentDirName)

			if e != nil {
				continue
			}

			globalMutex.RLock()
			siteExistsResult = siteExists(wildcardName, subWildcardName)
			globalMutex.RUnlock()

			if contentDirInfo.IsDir() && !siteExistsResult {
				constructSite(wildcardName, subWildcardName)
				globalMutex.Lock()
				subdomainContentCheckers["!"](false, siteSSLConfig[subWildcardName+"."+wildcardName], true, wildcardName, subWildcardName)
				globalMutex.Unlock()
				if checkSitesFlag {
					fmt.Println("Site \"" + subWildcardName + "." + wildcardName + "\" added to filesystem and enabled on server.")
				}
			}
		}
	}
}

func connHandler(conn net.Conn, connState customNetHttp.ConnState) {
	if !isConn(connState) {
		return
	}

	c := ipAddr(conn.RemoteAddr().String())

	if perIpNotAvailable(c, true) == true || globalAndPerIpControl(c) == true {
		conn.Close()
		return
	}
}

func perIpNotAvailable(ip string, incrementCounter bool) bool {
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
		_, z := persistentIPs[ip]
		globalMutex.RUnlock()

		ipData.blockedUntil = time.Now().Unix()
		denialMsg := ip + " conn denial"

		if z {
			ipData.blockedUntil += 10
			denialMsg += " persistent"
		} else {
			ipData.blockedUntil += 5
		}

		serverWriteLogs(stringStore["X"], nil, 0, denialMsg)

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
	// fmt.Println(_d, _l)

	exceeded := false

	if globalReqRatio > globalTimeRatio {
		globalMutex.Lock()
		persistentIPs[ip] = time.Now().Unix() + 59 // Time to preserve during cleanOldValues
		globalMutex.Unlock()
		serverWriteLogs(stringStore["X"], nil, 0, ip+" rate limit exceed at: "+strconv.FormatInt(persistentIPs[ip], 10))
		exceeded = true
	}

	if timeDiff > globalInterval {
		atomic.StoreInt64(&lastRequestTimeNano, nowNano)
		atomic.StoreInt64(&requestCountInWindow, 1)
	}

	return exceeded
}

func _constructSite(domain string, subdomain string) {
	if _, e := sitesMap[domain]; !e {
		sitesMap[domain] = make(map[string]map[string]string)
	}
	sitesMap[domain][subdomain] = make(map[string]string) // Rewrites
	if subdomain != "" {
		domain = subdomain + "." + domain
	}
	preprocessors[domain] = make(map[string]string)      // Preprocessors
	indexFiles[domain] = make(map[string]bool)           // Indexes
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

func constructSite(domain string, subdomain string) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	_constructSite(domain, subdomain)
}

func deleteSite(domain string, subdomain string) {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	var k string
	if subdomain != "" {
		delete(sitesMap[domain], subdomain)
		domain = subdomain + "." + domain
		deleteCertificate(domain)
	} else {
		for k, _ = range sitesMap[domain] {
			if k != "" {
				deleteCertificate(k + "." + domain)
			}
		}
		delete(sitesMap, domain)
	}
	delete(preprocessors, domain)
	delete(indexFiles, domain)
	delete(siteSSLConfig, domain)
	delete(mimeTypes, domain)
	delete(customHeaders, domain)
	for k, subdomain = range domainAliases {
		if subdomain == domain {
			delete(domainAliases, k)
		}
	}
}

func checkSites() {
	type _d struct{ s, d string }
	var _l []_d

	globalMutex.RLock()
	for d := range sitesMap {
		for s := range sitesMap[d] {
			if b, _ := siteExistenceCheckers["/"](false, d, s); !b { // siteExistenceCheckers["/"] is used when input is like: *.domain.com
				_l = append(_l, _d{s, d})
			}
		}
	}
	globalMutex.RUnlock()

	for _, i := range _l {
		deleteSite(i.d, i.s)

		s := i.s
		if s != "" {
			s += "."
		}
		fmt.Println("Site \"" + s + i.d + "\" deleted from filesystem and disabled on server.")
	}
}

func redir(schemeSuffix string, host string, subdomain string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, statusCode int) {
	if subdomain != "" {
		subdomain += "."
	}
	customNetHttp.Redirect(responseWriter, request, "http"+schemeSuffix+"://"+subdomain+host+request.RequestURI, statusCode)
}

func serve(serverType string, host string, domain string, subdomain string, firstDomain string, firstSubdomain string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) { //i, n, o
	wildcardMatch, _, _, wildcardDomain := detectWildcards(subdomain, domain)

	// fmt.Println("SUBDOMAIN", a, i, o, b)
	if !wildcardMatch {
		// Without 404 response: b = s
		reqMsg(responseWriter, request, 404)
		return
	}

	// fmt.Println("REQUEST", r.RequestURI)
	if serverType == "" && subdomain != "" && siteSSLConfig[wildcardDomain+"."+domain]["S"] != 0 {
		redir("s", host, subdomain, responseWriter, request, 301)
		return
	}

	var continueServe bool
	rewrittenPath, queryString, continueServe := choose(responseWriter, request, host, domain, wildcardDomain, subdomain, firstDomain, firstSubdomain)
	if !continueServe {
		return
	}
	request.RequestURI = rewrittenPath

	serverType = stringStore["A"] + changeWildcards(domain) + "/"
	if subdomain != "" {
		if wildcardMatch {
			subdomain = changeWildcards(wildcardDomain)
		}
		serverType += subdomain + "/" + stringStore["F"]
	} else {
		serverType += stringStore["F"]
	}

	fileInfo, err := os.Stat(serverType + rewrittenPath)
	if err != nil {
		reqMsg(responseWriter, request, 404)
		return
	}

	if subdomain != "" {
		subdomain = wildcardDomain + "." + domain
	} else {
		subdomain = domain
	}

	if fileInfo.IsDir() {
		trailingSlash := "/"
		if rewrittenPath == trailingSlash || rewrittenPath[len(rewrittenPath)-1] == '/' {
			trailingSlash = ""
		}
		indexFile := " " // Hide default indexes when indexFiles is empty

		for indexName := range indexFiles[subdomain] {
			indexFile = trailingSlash + indexName
			preprocFileInfo, err := os.Stat(serverType + rewrittenPath + indexFile)
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

	if _, continueServe = customHeaders[subdomain]; continueServe {
		for u := range customHeaders[subdomain] {
			responseHeaders.Set(u, customHeaders[subdomain][u])
		}
	} // Headers inclution

	if _, continueServe = preprocessors[subdomain][extension]; continueServe && preprocessors[subdomain][extension] != "" { // Verify preprocessors
		preprocFileInfo, err := os.Stat(preprocessors[subdomain][extension])
		if err == nil && !preprocFileInfo.IsDir() { // Before: !os.IsNotExist(e)
			dynamic(serverType, rewrittenPath, queryString, preprocessors[subdomain][extension], responseWriter, request, &responseHeaders)
			return
		}
	}

	if _, continueServe = mimeTypes[subdomain][extension]; continueServe {
		responseHeaders.Set(stringStore["D"], mimeTypes[subdomain][extension])
	}
	customNetHttp.ServeFile(responseWriter, request, serverType+rewrittenPath)
	// fmt.Println(j) Show headers
}

func dynamic(basePath string, requestPath string, queryString string, scriptPath string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, headers *customNetHttp.Header) {
	l := new(customNetHttp.CgiHandler) // Before: new(cgi.Handler)
	l.Path = scriptPath
	l.Root = basePath
	l.Env = append(l.Env, "REDIRECT_STATUS=CGI") // This is need for execution of scripts (it will not executed if isn't set). Also depends of 'cgi.force-redirect' on php.ini.
	if request.URL.RawQuery != "" {
		queryString = request.URL.RawQuery + "&" + queryString
	}
	l.Env = append(l.Env, "QUERY_STRING="+queryString) // If not set, not includes rewrite query string
	l.Env = append(l.Env, "DOCUMENT_ROOT="+basePath)
	l.Env = append(l.Env, "SCRIPT_FILENAME="+basePath+requestPath)
	l.ServeHTTP(responseWriter, request)
	// fmt.Println(j) Show headers
}

func rewrite(requestURI string, domain string, subdomain string) (string, string) {
	var c bool
	if _, c = sitesMap[domain][subdomain][requestURI]; c {
		return sitesMap[domain][subdomain][requestURI], requestURI
	}
	if requestURI == "/" {
		return "", ""
	} // To prevent passing through 'choose' unecessary functions. Before: return y, ""
	requestURI = requestURI[1:]
	for {
		d := strings.LastIndexByte(requestURI, '/')
		if d == -1 {
			break
		}
		d++
		if _, c := sitesMap[domain][subdomain]["/"+requestURI[:d]]; c {
			return sitesMap[domain][subdomain]["/"+requestURI[:d]], "/" + requestURI[:d]
		} else {
			requestURI = requestURI[:d-1]
		}
	}
	if _, c = sitesMap[domain][subdomain]["/"]; c {
		return sitesMap[domain][subdomain]["/"], "/"
	} // At the end of large unmatched string is obligatory to check if match with a top level rewrite
	return "", ""
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
	case 'H':
		redir("", rewriteResult[1:]+pathWithoutQuery, "", responseWriter, request, 302)
		return "", "", false
	case 'S':
		redir("s", rewriteResult[1:]+pathWithoutQuery, "", responseWriter, request, 302)
		return "", "", false
	case 'N':
		rewriteResult = rewriteResult[1:]
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
		configBytes, e := os.ReadFile(configPath)
		if e != nil || !json.Valid([]byte(configBytes)) {
			fmt.Println("Config file:", configPath, e)
			setDefaultSettings()
			return
		}
		json.Unmarshal(configBytes, &rawConfigMap)
		var keyExists bool
		var stringValue string
		//var subKey string
		var configKey string
		for configKey, _ = range adminAddHandlers {
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
		for configKey, _ = range defaultSettingValidators { // Default settings check
			if _, keyExists = rawConfigMap[configKey]; keyExists {
				for _, subValue := range defaultSettingKeysGroup[configKey] {
					if _, keyExists = rawConfigMap[configKey][subValue]; keyExists {
						stringValue, keyExists = rawConfigMap[configKey][subValue].(string)
						var subKeyIter string
						if keyExists {
							if keyExists, subKeyIter = defaultSettingValidators[configKey][subValue](stringValue, stringStore["P"]); keyExists {
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
				for subMap, _ := range defaultSettingsResetFallbacks[configKey] {
					defaultSettingsResetFallbacks[configKey][subMap]()
				} // Reset specific defaults if doesn't exists
			}
		}
		for domain, _ := range rawConfigMap { // Site & subdomains existence check
			if _, keyExists = defaultSettingValidators[domain]; keyExists {
				continue
			}
			if !siteExistenceCheck(domain, "") {
				continue
			}
			for subKey, _ := range rawConfigMap[domain] {
				if _, keyExists = subdomainContentCheckers[subKey]; keyExists || (subKey != "" && !siteExistenceCheck(domain, subKey)) {
					continue
				}
				subdomainData, keyExists := rawConfigMap[domain][subKey].(map[string]interface{})
				if !keyExists {
					continue
				}
				for settingKey, _ := range subdomainContentCheckers { // Subdomains content check
					if _, keyExists = subdomainData[settingKey]; keyExists {
						subdomainContentCheckers[settingKey](false, subdomainData[settingKey], true, domain, subKey) // Returns something like: a, _
					}
				}
			}
		}
		rawConfigMap = make(map[string]map[string]interface{})
		return
	}
	setDefaultSettings()
}

func setDefaultSettings() {
	for k, _ := range defaultSettingsResetFallbacks {
		for m, _ := range defaultSettingsResetFallbacks[k] {
			defaultSettingsResetFallbacks[k][m]()
		}
	}
}

func siteExistenceCheck(domain string, subdomain string) bool {
	var c bool
	var m string
	for m, _ = range siteExistenceCheckers {
		if c, _ = siteExistenceCheckers[m](true, domain, subdomain); !c {
			siteExistenceResetFallbacks[m](domain, subdomain)
			return false
		}
	}
	return true
}

type IPReference struct {
	mutex            sync.Mutex
	blockedUntil     int64
	lastRequestNano  int64
	requestCount     int64
}
