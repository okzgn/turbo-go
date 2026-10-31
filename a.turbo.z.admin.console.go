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
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"turbo/customNetHttp"
)

const passwordHashIterations = 600000 // PBKDF2-HMAC-SHA256 (DP12)

var (
	// internalAuth authorizes the validators that Turbo runs itself: while loading turbo.config, and in the
	// API once the request's password (b) has been checked. It is random and never leaves the process.
	internalAuth = newSessionToken()

	// verifiedPassword remembers the last password that matched panelPasswordHash, so checking it again
	// doesn't cost a PBKDF2; a wrong password always does.
	verifiedPassword atomic.Pointer[passwordCheck]

	// passwordHashSlots bounds the PBKDF2 checks running at once (half the CPUs): failed logins wait their turn
	// instead of taking every core.
	passwordHashSlots = make(chan struct{}, max(1, runtime.NumCPU()/2))

	// derivePasswordKey is the PBKDF2 of every password hash and check (a variable so that tests can count them).
	derivePasswordKey = func(password string, salt []byte, iterations int, keyLength int) ([]byte, error) {
		return pbkdf2.Key(sha256.New, password, salt, iterations, keyLength)
	}
)

type passwordCheck struct {
	hash string   // panelPasswordHash it was checked against
	sum  [32]byte // SHA-256 of hash and password
}

func console(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) bool {
	prefixLen := len(adminPathPrefix) + 2
	if len(request.RequestURI) < prefixLen || request.RequestURI[:prefixLen] != "/"+adminPathPrefix+":" {
		return false
	}

	// The panel can't be framed by another site and isn't cached (also its 404 outside PA).
	panelHeaders := responseWriter.Header()
	panelHeaders.Set("X-Frame-Options", "DENY")
	panelHeaders.Set("Content-Security-Policy", "frame-ancestors 'none'")
	panelHeaders.Set("Cache-Control", "no-store")

	if !panelAllowed(request) { // PA: the panel answers only on the listed hosts or networks (DP7)
		reqMsg(responseWriter, request, 404)
		return true
	}

	request.RequestURI = cutAt(request.RequestURI[prefixLen:], '?')

	if consoleActions(request.RequestURI, responseWriter, request) {
		return true
	}
	if request.RequestURI == "" {
		request.RequestURI = panelPageName
	}
	consoleFiles(adminPathPrefix, request.RequestURI, responseWriter, request)
	return true
}

func consoleFiles(panelName string, requestPath string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	// Turbo Dev: a file in turbo.dev/<panel>/ replaces the embedded one; what is missing there comes from the
	// embedded copy.
	devPath := sitesDir.Get() + putSlash(devGUIDirName) + putSlash(panelName) + filepath.Clean("/" + requestPath)[1:]
	if info, err := os.Stat(devPath); err == nil && !info.IsDir() {
		customNetHttp.ServeFile(responseWriter, request, devPath)
		return
	}
	// Turbo Dev end

	if content, err := fs.ReadFile(embeddedGUI, path.Join(devGUIDirName, panelName, path.Clean("/"+requestPath))); err == nil {
		customNetHttp.ServeContent(responseWriter, request, requestPath, time.Time{}, bytes.NewReader(content))
		return
	}

	reqMsg(responseWriter, request, 404)
}

// sessionCookieName holds the panel session. Its path is "/" because a cookie for "/admin:" would not be sent
// to "/admin:inside:..." (RFC 6265 path matching); dynamic removes it before running a CGI.
const sessionCookieName = "turbo_session"

// loginMaxBodyBytes bounds the body of a login, which is read before anything is checked (H46).
const loginMaxBodyBytes = 4096

// sessionCookie returns the Set-Cookie value for the panel session. It has no Max-Age, as the server renews
// the session on each request; deleteIt expires it at once.
func sessionCookie(token string, deleteIt bool, request *customNetHttp.Request) string {
	cookie := sessionCookieName + "=" + token + "; Path=/; HttpOnly; SameSite=Strict"
	if deleteIt {
		cookie += "; Max-Age=0"
	}
	if request.TLS != nil {
		cookie += "; Secure"
	}
	return cookie
}

// sessionKey is the key of a session in signedInTokens: the client's IP and the token, with a separator that
// neither has, so that no other IP and token make the same key (H22).
func sessionKey(clientIP string, token string) string {
	return clientIP + "|" + token
}

// sessionTokenOf returns the session token of a panel request: the cookie, or the "ok" header that API
// clients send. The token is never read from the URL.
func sessionTokenOf(request *customNetHttp.Request) (token string, fromCookie bool) {
	if cookie, err := request.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		return cookie.Value, true
	}
	return request.Header.Get(sessionHeaderName), false
}

// sameOriginRequest reports whether the browser says the request comes from the panel's own origin. The
// session cookie is sent by itself, and SameSite=Strict doesn't stop other origins of the same site (another
// subdomain served here), so actions authenticated with it need this (CSRF). It can't tell the panel from a
// page served on the same host: that needs a host of its own for the panel in PA (D3, warnPanelOrigin).
func sameOriginRequest(request *customNetHttp.Request) bool {
	if fetchSite := request.Header.Get("Sec-Fetch-Site"); fetchSite != "" {
		return fetchSite == "same-origin" || fetchSite == "none"
	}
	scheme := "http://"
	if request.TLS != nil {
		scheme = "https://"
	}
	return request.Header.Get("Origin") == scheme+request.Host
}

func consoleActions(actionPath string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) bool {
	colonIdx := strings.IndexByte(actionPath, ':')
	if colonIdx != -1 {
		request.RequestURI = request.RequestURI[colonIdx+1:]
		actionPath = actionPath[:colonIdx]
	}
	if request.RequestURI == "" {
		request.RequestURI = panelPageName
	}

	cleanOldValues(&signedInTokens)

	sessionToken, fromCookie := sessionTokenOf(request)
	clientIP := ipAddr(request.RemoteAddr)

	globalMutex.RLock()
	_, isSessionValid := signedInTokens[sessionKey(clientIP, sessionToken)]
	globalMutex.RUnlock()

	responseWriter.Header().Set("Access-Control-Allow-Origin", "default://home")
	responseWriter.Header().Set("Access-Control-Allow-Headers", "ok") // This is to accept ok header from default://home

	switch actionPath {
	case "signout":
		if request.Method != customNetHttp.MethodPost { // A link or an image of another page doesn't sign out
			return false
		}
		if isSessionValid {
			globalMutex.Lock()
			delete(signedInTokens, sessionKey(clientIP, sessionToken))
			globalMutex.Unlock()
		}
		responseWriter.Header().Add("Set-Cookie", sessionCookie("", true, request))

		consoleHtmlRedir("/"+adminPathPrefix+":", responseWriter, request)
		return true

	case adminInsideName:
		/*if len(I) != 0 && !a { // Only for logging from one IP at time
			w.Write([]byte("<p data-err>Inautorizado</p>"))
			return true
		}*/

		if isSessionValid {
			if fromCookie && request.Method == customNetHttp.MethodPost && !sameOriginRequest(request) {
				reqMsg(responseWriter, request, 403)
				return true
			}
			globalMutex.Lock()
			signedInTokens[sessionKey(clientIP, sessionToken)] = time.Now().Unix() + 600
			globalMutex.Unlock()

			if consoleActionsApi(request.RequestURI, responseWriter, request) {
				return true
			}

			consoleFiles(adminInsideName, request.RequestURI, responseWriter, request)
			return true
		}
		consoleHtmlRedir("/"+adminPathPrefix+":", responseWriter, request)
		return true
	case "":
		// Login: only POST /admin:, with the credentials in a small body (never in the URL, which turbo.visits
		// records), read before anything is checked.
		if request.Method != customNetHttp.MethodPost || colonIdx != -1 { // Not "/admin::..." (H60)
			return false
		}
		request.Body = customNetHttp.MaxBytesReader(responseWriter, request.Body, loginMaxBodyBytes)
		err := request.ParseForm() // ParseMultipartForm drops its error for a urlencoded body
		if err == nil {
			if err = request.ParseMultipartForm(loginMaxBodyBytes); err == customNetHttp.ErrNotMultipart {
				err = nil
			}
		}
		if err != nil {
			var tooLarge *customNetHttp.MaxBytesError
			if errors.As(err, &tooLarge) || errors.Is(err, customNetHttp.ErrMessageTooLarge) {
				reqMsg(responseWriter, request, 413)
			} else {
				reqMsg(responseWriter, request, 400)
			}
			return true
		}
		_, hasUser := request.PostForm["u"]
		_, hasPassword := request.PostForm["p"]
		if hasUser && hasPassword {
			if retryAfter := startLoginAttempt(clientIP); retryAfter > 0 { // H7: no PBKDF2 for a blocked IP
				responseWriter.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
				reqMsg(responseWriter, request, 429)
				return true
			}
			userMatches := subtle.ConstantTimeCompare([]byte(request.PostForm["u"][0]), []byte(panelUser.Get())) == 1
			passwordOK, busy := checkPassword(request.PostForm["p"][0], passwordSlotWait)
			if busy {
				finishLoginAttempt(clientIP, false)
				responseWriter.Header().Set("Retry-After", "2")
				reqMsg(responseWriter, request, 503)
				return true
			}
			if passwordOK && userMatches {
				finishLoginAttempt(clientIP, false)
				forgetLoginFailures(clientIP)
				now := time.Now().Unix()
				token := newSessionToken()

				globalMutex.Lock()
				signedInTokens[sessionKey(clientIP, token)] = now + 600
				globalMutex.Unlock()
				// The browser panel uses the cookie; API clients send the token in the "ok" header.
				responseWriter.Header().Add("Set-Cookie", sessionCookie(token, false, request))
				respond(responseWriter, sessionHeaderName+token)
			} else {
				finishLoginAttempt(clientIP, true)
				responseWriter.WriteHeader(403)
			}
			return true
		}
	}
	return false
}

// Failed logins per IP (H7): after loginMaxFailures within loginFailureWindow, the IP gets 429 without any
// PBKDF2 for a while that doubles with each block (1, 2, 4... minutes, up to 15). A correct login forgets them.
// The attempts still being checked count too, so that concurrent ones can't add up to more (H57).
const (
	loginMaxFailures   = 5
	loginFailureWindow = 10 * time.Minute
	loginFirstBlock    = time.Minute
	loginLongestBlock  = 15 * time.Minute
)

type loginFailures struct {
	count        int       // Failures in the current window
	inFlight     int       // Attempts started and not finished
	windowEnd    time.Time // End of the window, which starts at its first failure
	blocks       int       // Blocks so far, for the next one's length
	blockedUntil time.Time
}

var (
	loginFailuresMutex sync.Mutex // Guards loginFailuresByIP, apart from globalMutex
	loginFailuresByIP  = make(map[string]*loginFailures)
)

// startLoginAttempt starts a login attempt of ip, which finishLoginAttempt must end, and returns 0; or, without
// starting it, the seconds to wait: what is left of its block, or passwordSlotWait while the failures and the
// attempts being checked already reach loginMaxFailures.
func startLoginAttempt(ip string) int64 {
	loginFailuresMutex.Lock()
	defer loginFailuresMutex.Unlock()
	now := time.Now()
	failures, found := loginFailuresByIP[ip]
	if !found {
		failures = &loginFailures{}
		loginFailuresByIP[ip] = failures
	}
	if left := failures.blockedUntil.Sub(now); left > 0 {
		return int64((left + time.Second - 1) / time.Second)
	}
	if now.After(failures.windowEnd) {
		failures.count = 0 // The next failure opens a new window
	}
	if failures.count+failures.inFlight >= loginMaxFailures {
		return int64(passwordSlotWait / time.Second)
	}
	failures.inFlight++
	return 0
}

// finishLoginAttempt ends an attempt of ip started by startLoginAttempt and, if it failed, counts the failure and
// blocks ip when it reaches loginMaxFailures.
func finishLoginAttempt(ip string, failed bool) {
	loginFailuresMutex.Lock()
	defer loginFailuresMutex.Unlock()
	failures, found := loginFailuresByIP[ip]
	if !found {
		return
	}
	failures.inFlight = max(failures.inFlight-1, 0)
	if !failed {
		return
	}
	now := time.Now()
	if now.After(failures.windowEnd) {
		failures.count, failures.windowEnd = 0, now.Add(loginFailureWindow)
	}
	if failures.count++; failures.count < loginMaxFailures {
		return
	}
	block := min(loginFirstBlock<<min(failures.blocks, 4), loginLongestBlock)
	failures.blocks++
	failures.count, failures.windowEnd, failures.blockedUntil = 0, now, now.Add(block)
	serverWriteLogs(denialsLogName, nil, 0, ip+" login denial "+block.String())
}

// forgetLoginFailures clears the failed logins of ip after a correct one.
func forgetLoginFailures(ip string) {
	loginFailuresMutex.Lock()
	delete(loginFailuresByIP, ip)
	loginFailuresMutex.Unlock()
}

// cleanLoginFailures forgets the IPs whose window and block ended more than loginLongestBlock ago (main's
// periodic cleanup): their next block starts again from the first length.
func cleanLoginFailures() {
	loginFailuresMutex.Lock()
	defer loginFailuresMutex.Unlock()
	forgetBefore := time.Now().Add(-loginLongestBlock)
	for ip, failures := range loginFailuresByIP {
		if failures.inFlight == 0 && failures.windowEnd.Before(forgetBefore) && failures.blockedUntil.Before(forgetBefore) {
			delete(loginFailuresByIP, ip)
		}
	}
}

// warnDefaultCredentials logs when the panel still has the default username and password (D2).
func warnDefaultCredentials() {
	if panelUser.Get() == "Turbo" && passwordMatches("Admin") {
		slog.Warn("Se usan las credenciales por defecto (Turbo/Admin): cámbielas desde el panel o con TURBO_USER y TURBO_PASSWORD.")
	}
}

func consoleHtmlRedir(redirectURL string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	responseWriter.Header().Set(contentTypeHeader, "text/html; charset=UTF-8")
	respond(responseWriter, "<meta http-equiv='refresh' content='0; URL="+redirectURL+"'/>")
}

// panelAccessList is the parsed "PA" setting: host names the panel answers on, and client networks it answers
// to. An empty list means no restriction.
type panelAccessList struct {
	setting  string
	hosts    map[string]bool
	networks []*net.IPNet
}

var panelAccess atomic.Pointer[panelAccessList]

func init() {
	panelAccess.Store(&panelAccessList{})
}

// parsePanelAccess reads "PA": comma-separated host names (matched with the request's Host) and CIDR networks
// (matched with the client's IP). "" or "*" means no restriction. With both kinds, a request needs both. The
// Host header is chosen by the client: a host name gives the panel an origin of its own, apart from the sites,
// while networks are what limits who can reach it.
func parsePanelAccess(setting string) (*panelAccessList, string) {
	list := &panelAccessList{hosts: make(map[string]bool)}
	setting = strings.TrimSpace(setting)
	if setting == "" || setting == "*" {
		return list, ""
	}
	if len(setting) > 1024 {
		return nil, "Lista demasiado larga"
	}
	var entries []string
	for _, entry := range strings.Split(setting, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if strings.IndexByte(entry, '/') != -1 {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, "Red incorrecta: " + entry
			}
			list.networks = append(list.networks, network)
		} else {
			if valid, _ := hostOk(entry, false); !valid && net.ParseIP(entry) == nil {
				return nil, "Host incorrecto: " + entry
			}
			list.hosts[entry] = true
		}
		entries = append(entries, entry)
	}
	if len(entries) > 32 {
		return nil, "Más de 32 hosts o redes"
	}
	list.setting = strings.Join(entries, ",")
	return list, ""
}

// isClientIP reports whether ip is the address the request comes from.
func isClientIP(ip string, request *customNetHttp.Request) bool {
	denied := net.ParseIP(strings.TrimSpace(ip))
	return denied != nil && denied.Equal(net.ParseIP(ipAddr(request.RemoteAddr)))
}

// panelAllowed reports whether the panel answers this request under "PA": on one of its hosts, if it has any,
// and from one of its networks, if it has any.
func panelAllowed(request *customNetHttp.Request) bool {
	list := panelAccess.Load()
	if len(list.hosts) > 0 && !list.hosts[strings.ToLower(requestHostname(request))] {
		return false
	}
	if len(list.networks) == 0 {
		return true
	}
	clientIP := net.ParseIP(ipAddr(request.RemoteAddr))
	for _, network := range list.networks {
		if clientIP != nil && network.Contains(clientIP) {
			return true
		}
	}
	return false
}

// panelHostConflict says which host of the list serves a site, which would put the panel in the same origin as
// that site's pages (D3), or "" if none does. Callers hold the global lock.
func panelHostConflict(list *panelAccessList) string {
	hosts := make([]string, 0, len(list.hosts))
	for hostName := range list.hosts {
		hosts = append(hosts, hostName)
	}
	sort.Strings(hosts)
	for _, hostName := range hosts {
		if site := servingSite(hostName); site != "" {
			return "El host del panel " + hostName + " sirve el sitio " + site + ": use un host que no sirva contenido"
		}
	}
	return ""
}

// panelHostServedBy returns the host of PA that siteKey serves, or "" if it serves none. Callers hold the global
// lock.
func panelHostServedBy(siteKey string) string {
	for hostName := range panelAccess.Load().hosts {
		if servingSite(hostName) == siteKey {
			return hostName
		}
	}
	return ""
}

// warnPanelOrigin logs when the panel shares an origin with the sites (D3): PA has no host, or one of its hosts
// serves a site (accepted from turbo.config, so as not to break it). Callers hold the global read lock.
func warnPanelOrigin() {
	list := panelAccess.Load()
	if len(list.hosts) == 0 {
		slog.Warn("El panel responde en los mismos hosts que los sitios: una página servida por Turbo podría usar su sesión. Configure en PA un host dedicado al panel.")
	} else if conflict := panelHostConflict(list); conflict != "" {
		slog.Warn(conflict + " (PA de turbo.config: se mantiene, pero el panel comparte origen con ese sitio)")
	}
}

// newSessionToken returns 32 random bytes in hex, unrelated to the credentials and unique per login.
func newSessionToken() string {
	random := make([]byte, 32)
	rand.Read(random) // Never fails (crypto/rand)
	return hex.EncodeToString(random)
}

// hashPassword returns "pbkdf2-sha256$<iterations>$<salt>$<key>" (standard base64), the "PH" format of
// turbo.config, with a random 16-byte salt and a 32-byte key.
func hashPassword(password string) string {
	salt := make([]byte, 16)
	rand.Read(salt) // Never fails (crypto/rand)
	key, _ := derivePasswordKey(password, salt, passwordHashIterations, 32)
	return "pbkdf2-sha256$" + strconv.Itoa(passwordHashIterations) + "$" + base64.StdEncoding.EncodeToString(salt) + "$" + base64.StdEncoding.EncodeToString(key)
}

// parsePasswordHash splits a hash made by hashPassword.
func parsePasswordHash(hash string) (iterations int, salt []byte, key []byte, ok bool) {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return 0, nil, nil, false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 || iterations > 10000000 {
		return 0, nil, nil, false
	}
	salt, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < 8 {
		return 0, nil, nil, false
	}
	key, err = base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(key) < 16 {
		return 0, nil, nil, false
	}
	return iterations, salt, key, true
}

// setPanelPassword replaces the panel password; only its hash is kept.
func setPanelPassword(password string) {
	applyPasswordHash(hashPassword(password), password)
}

// applyPasswordHash makes hash, made by hashPassword from password, the panel's password.
func applyPasswordHash(hash string, password string) {
	panelPasswordHash.Set(hash)
	verifiedPassword.Store(&passwordCheck{hash, sha256.Sum256([]byte(hash + "\x00" + password))})
}

// newPasswordHash checks a new panel password and returns its hash, or why it can't be used. It costs two
// PBKDF2, so setP runs it before taking the global lock (H16).
func newPasswordHash(password string) (hash string, problem string) {
	if length := len(password); length < 1 || length > 24 {
		return "", "Contraseña muy larga o corta"
	}
	if passwordMatches(password) {
		return "", "Contraseña sin cambios"
	}
	return hashPassword(password), ""
}

// passwordSlotWait is how long a password check from a request waits for a PBKDF2 slot before giving up with 503
// (H7): a flood of logins can't keep the administrator waiting without limit.
const passwordSlotWait = 2 * time.Second

// passwordMatches reports whether password is the panel's (or internalAuth), comparing in constant time. It
// waits for a PBKDF2 slot as long as needed.
func passwordMatches(password string) bool {
	matches, _ := checkPassword(password, 0)
	return matches
}

// checkPassword is passwordMatches waiting at most wait for a PBKDF2 slot (0: as long as needed). busy reports
// that there was none in time, and then matches is false.
func checkPassword(password string, wait time.Duration) (matches bool, busy bool) {
	if subtle.ConstantTimeCompare([]byte(password), []byte(internalAuth)) == 1 {
		return true, false
	}
	// PBKDF2 uses the password as an HMAC key, padded with zeros: "x" and "x\x00" would match the same hash. No
	// password can have a NUL (the panel rejects control characters, and an environment variable can't hold one).
	if strings.IndexByte(password, 0) != -1 {
		return false, false
	}
	hash := panelPasswordHash.Get()
	sum := sha256.Sum256([]byte(hash + "\x00" + password))
	if last := verifiedPassword.Load(); last != nil && last.hash == hash && subtle.ConstantTimeCompare(last.sum[:], sum[:]) == 1 {
		return true, false
	}
	iterations, salt, key, ok := parsePasswordHash(hash)
	if !ok {
		return false, false
	}
	if wait == 0 {
		passwordHashSlots <- struct{}{}
	} else {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case passwordHashSlots <- struct{}{}:
		case <-timer.C:
			return false, true
		}
	}
	derived, err := derivePasswordKey(password, salt, iterations, len(key))
	<-passwordHashSlots
	if err != nil || subtle.ConstantTimeCompare(derived, key) != 1 {
		return false, false
	}
	verifiedPassword.Store(&passwordCheck{hash, sum})
	return true, false
}

// loadCredentials applies "U" and "PH" from the global settings of turbo.config, unless TURBO_USER or
// TURBO_PASSWORD are set. A plain "P" (schema 1, or written by hand) is hashed and never saved again.
// Callers hold the global lock.
func loadCredentials(settings map[string]interface{}) {
	if user, isString := settings["U"].(string); isString && !userFromEnv && len(user) >= 1 && len(user) <= 24 {
		panelUser.Set(user)
	}
	if passwordFromEnv {
		return
	}
	if hash, isString := settings["PH"].(string); isString {
		if _, _, _, ok := parsePasswordHash(hash); ok {
			panelPasswordHash.Set(hash)
			return
		}
		slog.Warn("PH incorrecto en turbo.config: se ignora")
	}
	if password, isString := settings["P"].(string); isString && len(password) >= 1 && len(password) <= 24 {
		slog.Warn("Contraseña en texto plano en turbo.config: se guardará solo su hash")
		setPanelPassword(password)
	}
}

// uploadedFilePath returns where an uploaded file goes inside @. The browser sends the chosen folder as the
// first segment of each name, so it is dropped ("site/css/a.css" -> "css/a.css"). Names that would leave @
// ("..", absolute or with a volume) are rejected.
func uploadedFilePath(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	if _, rest, found := strings.Cut(name, "/"); found {
		name = rest
	}
	if name == "" || strings.HasPrefix(name, "/") || filepath.VolumeName(name) != "" || strings.IndexByte(name, ':') != -1 {
		return "", false
	}
	for _, segment := range strings.Split(name, "/") {
		// Names that Windows treats specially are refused on every system, so the site can be moved (H47).
		if segment == "" || segment == "." || segment == ".." || !pathSegmentAllowed(segment, true) {
			return "", false
		}
	}
	return name, true
}

// charsDecodedByValidator lists, per action, the parameters whose character replacements its validator undoes
// itself; undoCharReplacements undoes them in all the others.
var charsDecodedByValidator = map[string]map[string]bool{
	"addRewrite": {"a": true, "b": true}, "addMIME": {"b": true}, "addHeader": {"b": true}, "addPreprocessor": {"b": true},
	"addIndex": {"a": true}, "addCharsReplace": {"s": true, "d": true}, "delRewrite": {"a": true}, "delIndex": {"a": true},
	"delCharsReplace": {"s": true},
}

// undoCharReplacements turns the character replacements of §2.1 of the API ("-.-" for ";" and the rest) back
// into their characters in every parameter of a panel action, once, before the action reads them (H21).
func undoCharReplacements(request *customNetHttp.Request, apiPath string) {
	globalMutex.RLock() // charReplacements
	defer globalMutex.RUnlock()
	for name, values := range request.Form {
		if charsDecodedByValidator[apiPath][name] {
			continue
		}
		for i := range values {
			values[i] = replaceURIChars(values[i])
		}
	}
}

// formRejected answers a request whose parameters couldn't be read: 413 if they are larger than allowed (MBB,
// and at most 10 MiB in a urlencoded body), 400 otherwise.
func formRejected(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, err error) {
	var tooLarge *customNetHttp.MaxBytesError
	if errors.As(err, &tooLarge) || errors.Is(err, customNetHttp.ErrMessageTooLarge) || strings.Contains(err.Error(), "too large") {
		responseWriter.WriteHeader(413)
		respond(responseWriter, "Longitud máxima de contenidos excedida")
		return
	}
	badReq(responseWriter, request, "Parámetros incorrectos")
}

// formTextProblem checks every parameter of a panel request with textProblem and returns the first problem.
func formTextProblem(request *customNetHttp.Request, whitespace bool) string {
	for name, values := range request.Form {
		if problem := textProblem(name, false); problem != "" {
			return problem
		}
		for _, value := range values {
			if problem := textProblem(value, whitespace); problem != "" {
				return problem
			}
		}
	}
	return ""
}

// addSite creates a site from the panel: its folder with @ and its settings. Callers hold the global lock.
func addSite(domain string) (bool, string) {
	if siteExists(domain, "") {
		return false, "Sitio existente."
	}
	if valid, message := hostOk(domain, false); !valid {
		return false, message
	}
	// Subdomains map keys coincidence detection
	if matched, matchedSite, _, subdomain := detectWildcards(domain, ""); matched {
		if matched, _, _, matchedSite = detectWildcards(matchedSite, subdomain); matched {
			return false, "Coincidencia con sitio: " + matchedSite + "." + subdomain
		}
	}
	constructSiteLocked(domain, "")
	if panelHost := panelHostServedBy(domain); panelHost != "" { // D3: undone before anything reaches the disk
		deleteSiteLocked(domain, "")
		return false, "El sitio serviría el host del panel " + panelHost + ": use otro host para el panel o para el sitio"
	}
	if os.MkdirAll(sitesDir.Get()+changeWildcards(domain)+"/"+publicDirName+"/", 0755) != nil { // #nosec G301 -- public web content of a site, served by Turbo
		deleteSiteLocked(domain, "")
		return false, "Error al crear"
	}
	return true, "Sitio agregado"
}

// addSubdomain creates a subdomain of an existing site from the panel. Callers hold the global lock.
func addSubdomain(domain string, subdomain string) (bool, string) {
	if _, exists := sitesMap[domain]; !exists {
		return false, "Sitio inexistente"
	}
	if valid, message := hostOk(subdomain+"."+changeWildcards(domain, "x"), false); !valid { // A wildcard is only accepted at the beginning
		return false, message
	}
	if siteExists(domain, subdomain) {
		return false, "Subdominio existente"
	}
	// Domains map keys coincidence detection
	if matched, _, _, matchedSite := detectWildcards(subdomain+"."+domain, ""); matched && matchedSite != domain {
		return false, "Coincidencia con sitio: " + matchedSite
	}
	constructSiteLocked(domain, subdomain)
	if panelHost := panelHostServedBy(subdomain + "." + domain); panelHost != "" { // D3: undone before anything reaches the disk
		deleteSiteLocked(domain, subdomain)
		return false, "El subdominio serviría el host del panel " + panelHost + ": use otro host para el panel o para el subdominio"
	}
	if os.MkdirAll(sitesDir.Get()+changeWildcards(domain)+"/"+changeWildcards(subdomain)+"/"+publicDirName+"/", 0755) != nil { // #nosec G301 -- public web content of a site, served by Turbo
		deleteSiteLocked(domain, subdomain)
		return false, "Error al crear"
	}
	return true, "Subdominio agregado"
}

// lockedCheck runs a validator holding the global write lock, releasing it even if the validator panics.
func lockedCheck(check func() (bool, string)) (bool, string) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	return check()
}

func consoleActionsApi(apiPath string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) (handled bool) {
	if request.Method != customNetHttp.MethodPost {
		return false
	}

	defer func() { // A panic in a validator must not take down the panel
		if p := recover(); p != nil {
			slog.Error("Panic en la API del panel", "acción", apiPath, "error", p)
			reqMsg(responseWriter, request, 500)
			handled = true
		}
	}()

	if len(apiPath) < 4 {
		return false
	}
	// No saved value may have control characters (H4); a response template may span lines. hardUpload reads
	// its multipart body itself.
	if apiPath != "hardUpload" {
		if err := request.ParseForm(); err != nil { // Every action reads its parameters from here on
			formRejected(responseWriter, request, err)
			return true
		}
		if problem := formTextProblem(request, apiPath == "addHttpCodeResponse"); problem != "" {
			badReq(responseWriter, request, problem)
			return true
		}
		undoCharReplacements(request, apiPath)
	}
	switch apiPath[:3] {
	case "set":
		apiPath = apiPath[3:]
		if _, handlerExists := defaultSettingValidators["."][apiPath]; handlerExists {
			if _, paramExists := request.Form["a"]; paramExists {
				argumentList := []string{request.Form["a"][0]}
				currentPassword := ""
				if _, paramExists = request.Form["b"]; paramExists {
					currentPassword = request.Form["b"][0]
				}
				if apiPath == "M" { // D11: the sites directory changes only to one whose turbo.config can be read
					if err := configFileProblem(sitesDirSetting(argumentList[0])); err != nil {
						badReq(responseWriter, request, "El turbo.config de ese directorio no es JSON válido o no se puede leer; corríjalo antes:\n"+err.Error())
						return true
					}
				}
				// Every setting needs the current password (b). It is checked here, before taking the lock,
				// as a wrong one costs a PBKDF2; the validator then gets internalAuth.
				if _, paramExists = request.Form["b"]; !paramExists {
					badReq(responseWriter, request, msgMissingData)
					return true
				}
				if matches, busy := checkPassword(currentPassword, passwordSlotWait); busy {
					responseWriter.Header().Set("Retry-After", "2")
					reqMsg(responseWriter, request, 503)
					return true
				} else if !matches {
					badReq(responseWriter, request, "Contraseña actual incorrecta")
					return true
				}
				argumentList = append(argumentList, internalAuth)
				if apiPath == "P" { // PBKDF2 without the global lock (H16)
					hash, problem := newPasswordHash(argumentList[0])
					if problem != "" {
						badReq(responseWriter, request, problem)
						return true
					}
					argumentList = append(argumentList, hash)
				}

				var resultMsg string
				resultBool, resultMsg := lockedCheck(func() (bool, string) {
					if apiPath == "PA" { // D3: the panel's host can't be a site's
						if list, _ := parsePanelAccess(argumentList[0]); list != nil {
							if conflict := panelHostConflict(list); conflict != "" {
								return false, conflict
							}
						}
					}
					return defaultSettingValidators["."][apiPath](argumentList...)
				})
				if !resultBool {
					badReq(responseWriter, request, resultMsg)
				} else {
					if _, handlerExists = serverRestartRequiredSettings[apiPath]; handlerExists { // serverRestartRequiredSettings: List of settings that use restartServers
						respond(responseWriter, resultMsg)
						//time.AfterFunc(50*time.Millisecond, func() {
						resetSettings()
						logConfigError(updateSettings(true))
						//})
					} else {
						respond(responseWriter, resultMsg)
					}
				}
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true
		}
		return false

	case "add":
		apiPath = apiPath[3:]
		switch apiPath {
		case "Rewrite", "MIME", "Header", "Preprocessor":
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			_, argumentParamExists := request.Form["a"]
			_, valueParamExists := request.Form["b"]
			if sourceParamExists && destinationParamExists && argumentParamExists && valueParamExists {
				resultMsg := "="
				entries := make(map[string]interface{})
				entries[request.Form["a"][0]] = request.Form["b"][0]
				if apiPath[0] == 'M' {
					resultMsg = "$"
				} else if apiPath[0] == 'H' {
					resultMsg = "."
				} else if apiPath[0] == 'P' {
					resultMsg = "?"
				}
				resultBool, resultMsg := lockedCheck(func() (bool, string) {
					return subdomainContentCheckers[resultMsg](true, entries, false, request.Form["s"][0], request.Form["d"][0])
				})
				if !resultBool {
					badReq(responseWriter, request, resultMsg)
				} else {
					respond(responseWriter, resultMsg)
				}
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "Index", "Alias":
			_, destinationParamExists := request.Form["d"]
			_, sourceParamExists := request.Form["s"]
			_, argumentParamExists := request.Form["a"]
			if destinationParamExists && sourceParamExists && argumentParamExists {
				argumentValues := make(map[string]interface{})
				argumentValues[request.Form["a"][0]] = false
				resultMsg := "-"
				if apiPath[0] == 'A' {
					resultMsg = "&"
				}
				resultBool, resultMsg := lockedCheck(func() (bool, string) {
					if resultMsg == "&" && panelAccess.Load().hosts[strings.ToLower(request.Form["a"][0])] { // D3
						return false, "El alias " + request.Form["a"][0] + " es un host del panel: use otro host para el panel o para el alias"
					}
					return subdomainContentCheckers[resultMsg](true, argumentValues, false, request.Form["s"][0], request.Form["d"][0])
				})
				if !resultBool {
					badReq(responseWriter, request, resultMsg)
				} else {
					respond(responseWriter, resultMsg)
				}
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "Subdomain":
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			if !sourceParamExists || !destinationParamExists {
				badReq(responseWriter, request, msgMissingData)
				return true
			}
			// Checks and creation in one locked section: no map is read without the lock, and nothing changes
			// between checking and creating (H10).
			resultBool, resultMsg := lockedCheck(func() (bool, string) { return addSubdomain(request.Form["s"][0], request.Form["d"][0]) })
			if !resultBool {
				badReq(responseWriter, request, resultMsg)
				return true
			}
			respond(responseWriter, resultMsg)
			return true

		case "Site":
			if _, sourceParamExists := request.Form["s"]; !sourceParamExists {
				badReq(responseWriter, request, msgMissingData)
				return true
			}
			resultBool, resultMsg := lockedCheck(func() (bool, string) { return addSite(request.Form["s"][0]) })
			if !resultBool {
				badReq(responseWriter, request, resultMsg)
				return true
			}
			respond(responseWriter, resultMsg)
			return true

		case "Denied", "HttpCodeResponse", "CharsReplace":
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			if sourceParamExists && destinationParamExists {
				resultMsg := "#"
				switch apiPath[0] {
				case 'C':
					resultMsg = "_"
				case 'D':
					resultMsg = "@"
					if isClientIP(request.Form["s"][0], request) { // The panel would lock itself out
						badReq(responseWriter, request, "IP actual")
						return true
					}
				}

				resultBool, resultMsg := lockedCheck(func() (bool, string) { return adminAddHandlers[resultMsg](request.Form["s"][0], request.Form["d"][0]) })

				if !resultBool {
					badReq(responseWriter, request, resultMsg)
					return true
				}
				respond(responseWriter, resultMsg)
				return true
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true
		}
		return false

	case "del":
		apiPath = apiPath[3:]
		switch apiPath {
		case "Index", "Alias", "Preprocessor", "Header", "MIME", "Rewrite":
			_, destinationParamExists := request.Form["d"]
			_, sourceParamExists := request.Form["s"]
			_, argumentParamExists := request.Form["a"]
			if destinationParamExists && sourceParamExists && argumentParamExists {
				argumentValues := make(map[string]interface{})
				argumentValues[request.Form["a"][0]] = false
				resultMsg := "="
				if apiPath[0] == 'A' {
					resultMsg = "&"
				} else if apiPath[0] == 'I' {
					resultMsg = "-"
				} else if apiPath[0] == 'P' {
					resultMsg = "?"
				} else if apiPath[0] == 'H' {
					resultMsg = "."
				} else if apiPath[0] == 'M' {
					resultMsg = "$"
				}

				resultBool, resultMsg := lockedCheck(func() (bool, string) {
					return subdomainContentDeleters[resultMsg](true, argumentValues, request.Form["s"][0], request.Form["d"][0])
				})

				if !resultBool {
					badReq(responseWriter, request, resultMsg)
				} else {
					respond(responseWriter, resultMsg)
				}
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "Site":
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			if sourceParamExists && destinationParamExists {
				resultMsg := "Sitio"
				resultBool := request.Form["d"][0] != ""
				if resultBool {
					resultMsg = "Subdominio"
				}

				globalMutex.RLock()
				_e := siteExists(request.Form["s"][0], request.Form["d"][0])
				globalMutex.RUnlock()

				if !_e {
					badReq(responseWriter, request, resultMsg+" inexistente")
					return true
				}

				siteDir := sitesDir.Get() + changeWildcards(request.Form["s"][0])
				if resultBool {
					siteDir += "/" + changeWildcards(request.Form["d"][0])
				}
				siteDir += "/"
				if os.RemoveAll(siteDir) != nil {
					badReq(responseWriter, request, "Error al borrar")
					return true
				}

				deleteSite(request.Form["s"][0], request.Form["d"][0])
				respond(responseWriter, resultMsg+" borrado")
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "Denied", "HttpCodeResponse", "CharsReplace":
			_, sourceParamExists := request.Form["s"]
			if sourceParamExists {
				resultMsg := "#"
				switch apiPath[0] {
				case 'C':
					resultMsg = "_"
				case 'D':
					resultMsg = "@"
				}

				resultBool, resultMsg := lockedCheck(func() (bool, string) { return adminDeleteHandlers[resultMsg](request.Form["s"][0]) })

				if !resultBool {
					badReq(responseWriter, request, resultMsg)
					return true
				}
				respond(responseWriter, resultMsg)
				return true
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true
		}
		return false

	case "cfg":
		apiPath = apiPath[3:]
		if _, handlerExists := siteSSLSettingCheckers[apiPath]; handlerExists {
			_, argumentParamExists := request.Form["a"]
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			_, zParamExists := request.Form["z"]
			_, yParamExists := request.Form["y"]
			email := ""
			adapter := ""
			if zParamExists {
				email = request.Form["z"][0]
			}
			if yParamExists {
				adapter = request.Form["y"][0]
			}
			if argumentParamExists && sourceParamExists && destinationParamExists {
				var resultMsg string
				resultBool, resultMsg := lockedCheck(func() (bool, string) {
					return siteSSLSettingCheckers[apiPath](false, request.Form["a"][0], request.Form["s"][0], request.Form["d"][0], email, adapter)
				})

				if !resultBool && strings.Contains(resultMsg, `"status":"WAIT"`) { // In progress, not an error (D8)
					responseWriter.WriteHeader(202)
					respond(responseWriter, resultMsg)
					return true
				}
				if !resultBool {
					badReq(responseWriter, request, resultMsg)
					return true
				}
				respond(responseWriter, resultMsg)
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true
		}
		return false

	default:
		switch apiPath {
		case "hardUpload":
			// s and d may come in the URL or in the multipart body, which is read only into memory and up to MBB.
			// A whole site is uploaded at once: up to 10 000 files (D10), each with two headers.
			request = customNetHttp.TurboWithFormLimits(request, 10000, 20000)
			if readErr := request.ParseMultipartForm(maxBodySize.Load()); readErr != nil && readErr != customNetHttp.ErrNotMultipart {
				badReq(responseWriter, request, "Longitud máxima de contenidos excedida")
				return true
			}
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			if !sourceParamExists || !destinationParamExists {
				badReq(responseWriter, request, msgMissingData)
				return true
			}
			if problem := formTextProblem(request, false); problem != "" {
				badReq(responseWriter, request, problem)
				return true
			}
			globalMutex.RLock()
			_e := siteExists(request.Form["s"][0], request.Form["d"][0])
			globalMutex.RUnlock()

			if !_e {
				if request.Form["d"][0] != "" {
					badReq(responseWriter, request, "Subdominio inexistente")
				} else {
					badReq(responseWriter, request, "Sitio inexistente")
				}
				return true
			}

			if request.MultipartForm == nil || len(request.MultipartForm.File["f"]) == 0 {
				badReq(responseWriter, request, "No hay datos")
				return true
			}
			defer request.MultipartForm.RemoveAll()

			contentDir := sitesDir.Get() + changeWildcards(request.Form["s"][0])
			if request.Form["d"][0] != "" {
				contentDir += "/" + changeWildcards(request.Form["d"][0])
			}
			contentDir += "/" + publicDirName + "/"

			dirEntries, readErr := os.ReadDir(contentDir)
			if readErr != nil {
				badReq(responseWriter, request, "Directorio inaccesible")
				return true
			}
			var undeleted []string
			for _, entry := range dirEntries { // The upload replaces all of @, folders included (DP13)
				if os.RemoveAll(contentDir+entry.Name()) != nil {
					undeleted = append(undeleted, entry.Name())
				}
			}
			if len(undeleted) > 0 { // Don't mix new files with old ones that are still there
				slog.Error("hardUpload: no se pudo vaciar el directorio público", "directorio", contentDir, "restos", undeleted)
				badReq(responseWriter, request, "No se pudo vaciar el directorio; no se ha subido nada. Sin borrar: "+strings.Join(undeleted, ", "))
				return true
			}

			var discarded []string
			for _, uploadedFile := range request.MultipartForm.File["f"] {
				_, fileMetadata, readErr := mime.ParseMediaType(uploadedFile.Header.Get("Content-Disposition"))
				if readErr != nil {
					continue
				}
				name := fileMetadata["filename"]
				relativePath, ok := uploadedFilePath(name)
				if !ok {
					discarded = append(discarded, name)
					continue
				}
				srcFile, readErr := uploadedFile.Open()
				if readErr != nil {
					discarded = append(discarded, name)
					continue
				}
				targetPath := contentDir + relativePath
				if readErr = os.MkdirAll(filepath.Dir(targetPath), 0755); readErr == nil { // #nosec G301 -- public web content of a site, served by Turbo
					var dstFile *os.File
					if dstFile, readErr = os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); readErr == nil { // #nosec G302 G304 -- public web content; uploadedFilePath rejects .. and absolute paths, so it stays under @
						_, readErr = io.Copy(dstFile, srcFile)
						if closeErr := dstFile.Close(); readErr == nil { // A failed close can mean an incomplete file
							readErr = closeErr
						}
					}
				}
				_ = srcFile.Close() // In memory (P10): closing it can't fail
				if readErr != nil {
					discarded = append(discarded, name)
				}
			}
			if len(discarded) > 0 {
				respond(responseWriter, "Datos volcados. Descartados: "+strings.Join(discarded, ", "))
			} else {
				respond(responseWriter, "Datos volcados")
			}
			return true

		case "sites":
			// The response is built with the read lock and written without it (H12): a client that reads slowly
			// doesn't hold back a pending Lock, and through it, every other request.
			globalMutex.RLock()
			response := createDefaultConfig(false, true, false)
			globalMutex.RUnlock()
			respond(responseWriter, response)
			return true

		case "subdomains":

			_, paramExists := request.Form["s"]
			if paramExists {
				globalMutex.RLock()
				_e := siteExists(request.Form["s"][0], "")
				response := ""
				if _e {
					response = createSubdomainsList(false, request.Form["s"][0])
				}
				globalMutex.RUnlock()

				if !_e {
					badReq(responseWriter, request, "Sitio inexistente")
					return true
				}
				respond(responseWriter, response)
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "subdomainData":
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			if sourceParamExists && destinationParamExists {
				globalMutex.RLock()
				_e := siteExists(request.Form["s"][0], request.Form["d"][0])
				response := ""
				if _e {
					response = createSubdomainData(request.Form["s"][0], request.Form["d"][0])
				}
				globalMutex.RUnlock()

				if !_e {
					badReq(responseWriter, request, "Subdominio inexistente")
					return true
				}
				respond(responseWriter, response)
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true
		}
	}
	return false
}
