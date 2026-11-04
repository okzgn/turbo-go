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
	"net/netip"
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

const passwordHashIterations = 600000 // PBKDF2-HMAC-SHA256

var (
	// internalAuth authorizes the validators that Turbo runs itself: while loading turbo.config, and in the
	// API once the request's password (b) has been checked. It is random and never leaves the process.
	internalAuth = newSessionToken()

	// verifiedPassword remembers the last password that matched panelPasswordHash, so checking it again
	// doesn't cost a PBKDF2; a wrong password always does.
	verifiedPassword atomic.Pointer[passwordCheck]

	// verifiedLogin is verifiedPassword for logins, together with the username: a login with the right password
	// and a wrong username costs a PBKDF2, like any other failed login, so its timing doesn't tell whether the
	// password alone is right.
	verifiedLogin atomic.Pointer[passwordCheck]

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

	// The panel can't be framed by another site and isn't cached (also its 404 outside PA), no browser guesses
	// another type for its answers than the one they say, and only its own pages run scripts (panelCSP).
	panelHeaders := responseWriter.Header()
	panelHeaders.Set("X-Frame-Options", "DENY")
	panelHeaders.Set("Content-Security-Policy", panelCSP)
	panelHeaders.Set("Cache-Control", "no-store")
	panelHeaders.Set("X-Content-Type-Options", "nosniff")

	if !panelAllowed(request) { // PA: the panel answers only on the listed hosts or networks
		reqMsg(responseWriter, 404)
		return true
	}
	if request.TLS == nil && panelHTTPSRedirect(responseWriter, request) {
		return true
	}
	// Its own host, while a certificate covers it: always HTTPS. Without one (cfgPC a=0 sent max-age=0), a request on a
	// connection still open, or a TLS session resumed, would set it again for a year, with no HTTPS to come back to.
	if hostName := requestHostName(request.Host); request.TLS != nil && panelAccess.Load().hosts[hostName] && certificateFor(hostName) != nil {
		panelHeaders.Set("Strict-Transport-Security", "max-age=31536000")
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

// panelHTTPSRedirect sends a panel request that came over HTTP to HTTPS, on the host it asked for, when a
// certificate covers that host (the panel's own or a site's) and HTTPS is open: 301 for GET and HEAD, 308 for the
// rest, which keeps the method and the body.
func panelHTTPSRedirect(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) bool {
	hostname := hostWithoutPort(request)
	if certificateFor(hostname) == nil || !httpsListening.Load() {
		return false
	}
	code := customNetHttp.StatusPermanentRedirect
	if request.Method == customNetHttp.MethodGet || request.Method == customNetHttp.MethodHead {
		code = customNetHttp.StatusMovedPermanently
	}
	customNetHttp.Redirect(responseWriter, request, "https://"+hostname+httpsPortSuffix()+request.RequestURI, code)
	return true
}

// panelCSP is the Content-Security-Policy of the answers on the panel's origin that are not its pages: its
// errors, its API answers and, on its own host, everything else. An error template is HTML that the panel's
// session can set without the password; on the panel's origin, a script in it could read the panel. Without
// scripts, frames, forms or plugins, a template keeps its styles and data: images.
const panelCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// panelPageCSP is the Content-Security-Policy of the panel's own pages, which run their scripts.
const panelPageCSP = "frame-ancestors 'none'"

// panelPageWriter gives a page of the panel panelPageCSP only when it is served: an error written in its place
// (the error template) keeps panelCSP.
type panelPageWriter struct {
	customNetHttp.ResponseWriter
	wroteHeader bool
}

func (w *panelPageWriter) WriteHeader(code int) {
	if !w.wroteHeader && code < 300 {
		w.Header().Set("Content-Security-Policy", panelPageCSP)
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *panelPageWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(customNetHttp.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

// Unwrap lets ResponseController reach the connection's writer.
func (w *panelPageWriter) Unwrap() customNetHttp.ResponseWriter { return w.ResponseWriter }

func consoleFiles(panelName string, requestPath string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	responseWriter = &panelPageWriter{ResponseWriter: responseWriter}
	// The path follows the rules of a site's files: decoded, without "..", "\\" or control characters and, on
	// Windows, without ":" nor device names. Cleaned by itself, a path that started with "/" was taken on Windows
	// for a network path and could leave turbo.dev/<panel>/, and a device name was opened as a file.
	cleanPath, ok := cleanRequestPath("/" + requestPath)
	if !ok {
		reqMsg(responseWriter, 404)
		return
	}
	// Turbo Dev: a file in turbo.dev/<panel>/ replaces the embedded one; what is missing there comes from the
	// embedded copy.
	devPath := sitesDir.Get() + putSlash(devGUIDirName) + putSlash(panelName) + cleanPath[1:]
	if info, err := os.Stat(devPath); err == nil && info.Mode().IsRegular() {
		customNetHttp.ServeFile(responseWriter, request, devPath)
		return
	}
	// Turbo Dev end

	if content, err := fs.ReadFile(embeddedGUI, path.Join(devGUIDirName, panelName, cleanPath)); err == nil {
		customNetHttp.ServeContent(responseWriter, request, requestPath, time.Time{}, bytes.NewReader(content))
		return
	}

	reqMsg(responseWriter, 404)
}

// The panel session cookie: sessionCookieName over HTTP, and sessionCookieNameTLS over TLS, a "__Host-" cookie
// that browsers only take from the host itself (Secure, Path=/ and no Domain), so another subdomain can't set
// one in its place. Its path is "/" because a cookie for "/admin:" would not be sent to "/admin:inside:..." (RFC
// 6265 path matching); dynamic removes it before running a CGI.
const (
	sessionCookieName    = "turbo_session"
	sessionCookieNameTLS = "__Host-turbo_session"
)

// sessionLifetime is how long a session lasts without requests, and sessionMaxLifetime how long it lasts at most,
// however it is used: a copy of a token (a cookie stolen from the same IP) isn't kept alive forever by requesting
// something every few minutes.
const (
	sessionLifetime    = 600
	sessionMaxLifetime = 12 * 3600
)

// loginMaxBodyBytes bounds the body of a login, which is read before anything is checked.
const loginMaxBodyBytes = 4096

// sessionCookie returns the Set-Cookie value for the panel session. It has no Max-Age, as the server renews
// the session on each request; deleteIt expires it at once.
func sessionCookie(token string, deleteIt bool, request *customNetHttp.Request) string {
	name := sessionCookieName
	if request.TLS != nil {
		name = sessionCookieNameTLS
	}
	cookie := name + "=" + token + "; Path=/; HttpOnly; SameSite=Strict"
	if deleteIt {
		cookie += "; Max-Age=0"
	}
	if request.TLS != nil {
		cookie += "; Secure"
	}
	return cookie
}

// sessionKey is the key of a session in signedInTokens: the client's IP and the token, with a separator that
// neither has, so that no other IP and token make the same key.
func sessionKey(clientIP string, token string) string {
	return clientIP + "|" + token
}

// panelSession finds the session of a panel request: the first session cookie, of either name, or else the "ok"
// header that API clients send, whose token is an unexpired session of the client's IP. Every session cookie is
// tried, as a cookie with the same name set by another subdomain may come first. key is "" without a session;
// viaCookie says the session came in a cookie, and hasCookie that the request had a session cookie, valid or not.
// The token is never read from the URL.
func panelSession(request *customNetHttp.Request, clientIP string) (key string, viaCookie bool, hasCookie bool) {
	now := time.Now().Unix()
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	valid := func(token string) bool {
		expiry, found := signedInTokens[sessionKey(clientIP, token)]
		return token != "" && found && expiry > now
	}
	for _, cookie := range request.Cookies() {
		if cookie.Name != sessionCookieName && cookie.Name != sessionCookieNameTLS {
			continue
		}
		hasCookie = true
		if valid(cookie.Value) {
			return sessionKey(clientIP, cookie.Value), true, true
		}
	}
	if token := request.Header.Get(sessionHeaderName); valid(token) {
		return sessionKey(clientIP, token), false, hasCookie
	}
	return "", false, hasCookie
}

// renewSession extends a session by sessionLifetime from now, if it is still open: a request that found it
// valid doesn't bring back a session closed meanwhile. Only requests of the panel's own origin renew it (or
// those without Sec-Fetch-Site, from API clients): a resource of the panel loaded by another page doesn't.
func renewSession(key string, request *customNetHttp.Request) {
	if fetchSite := request.Header.Get("Sec-Fetch-Site"); fetchSite != "" && fetchSite != "same-origin" && fetchSite != "none" {
		return
	}
	beforeSessionRenewal()
	now := time.Now().Unix()
	withGlobalLock(func() {
		if expiry, found := signedInTokens[key]; found && expiry > now {
			renewed := now + sessionLifetime
			if deadline, bounded := sessionDeadlines[key]; bounded && renewed > deadline {
				renewed = deadline // Never past sessionMaxLifetime from the login
			}
			signedInTokens[key] = renewed
		}
	})
}

// closeOtherSessions closes every session but keep (all with ""), after the credentials change. Callers hold the
// global lock.
func closeOtherSessions(keep string) {
	for key := range signedInTokens {
		if key != keep {
			delete(signedInTokens, key)
			delete(sessionDeadlines, key)
		}
	}
}

// openSessionLocked opens a session for clientIP and returns its token. Callers hold the global lock.
func openSessionLocked(clientIP string) string {
	token := newSessionToken()
	now := time.Now().Unix()
	key := sessionKey(clientIP, token)
	signedInTokens[key] = now + sessionLifetime
	sessionDeadlines[key] = now + sessionMaxLifetime
	return token
}

// renewCredentialsSessionLocked closes every session, the one of request too, after the panel's credentials change,
// and opens a new one for its client, whose token goes in the answer: in the cookie, which the browser replaces, and
// in the "ok" header, for API clients. A copy of the old token (a cookie stolen from the same IP, which the session
// of setU or setP kept until now) is then worth nothing. Callers hold the global lock.
func renewCredentialsSessionLocked(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	closeOtherSessions("")
	token := openSessionLocked(ipAddr(request.RemoteAddr))
	responseWriter.Header().Add("Set-Cookie", sessionCookie(token, false, request))
	responseWriter.Header().Set(sessionHeaderName, token)
}

// sameOriginRequest reports whether the browser says the request comes from the panel's own origin. The
// session cookie is sent by itself, and SameSite=Strict doesn't stop other origins of the same site (another
// subdomain served here), so actions authenticated with it need this (CSRF). It can't tell the panel from a
// page served on the same host: that needs a host of its own for the panel in PA (warnPanelOrigin).
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

	// Expired sessions are no longer valid; main's periodic task removes them, so a panel request takes no lock
	// for that.
	clientIP := ipAddr(request.RemoteAddr)
	currentSession, fromCookie, hasSessionCookie := panelSession(request, clientIP)
	isSessionValid := currentSession != ""

	switch actionPath {
	case "signout":
		if request.Method != customNetHttp.MethodPost { // A link or an image of another page doesn't sign out
			return false
		}
		if hasSessionCookie && !sameOriginRequest(request) { // Another page can't close the session
			reqMsg(responseWriter, 403)
			return true
		}
		if isSessionValid {
			withGlobalLock(func() { delete(signedInTokens, currentSession); delete(sessionDeadlines, currentSession) })
		}
		responseWriter.Header().Add("Set-Cookie", sessionCookie("", true, request))

		consoleHTMLRedir("/"+adminPathPrefix+":", responseWriter, request)
		return true

	case adminInsideName:
		if isSessionValid {
			if fromCookie && request.Method == customNetHttp.MethodPost && !sameOriginRequest(request) {
				reqMsg(responseWriter, 403)
				return true
			}
			renewSession(currentSession, request)

			if consoleActionsAPI(request.RequestURI, currentSession, responseWriter, request) {
				return true
			}

			consoleFiles(adminInsideName, request.RequestURI, responseWriter, request)
			return true
		}
		// The same body as always, for the pages that look for it; the GUI looks for the header.
		responseWriter.Header().Set("X-Turbo-Login", "required")
		consoleHTMLRedir("/"+adminPathPrefix+":", responseWriter, request)
		return true
	case "":
		// Login: only POST /admin:, with the credentials in a small body (never in the URL, which turbo.visits
		// records), read before anything is checked.
		if request.Method != customNetHttp.MethodPost || colonIdx != -1 { // Not "/admin::..."
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
				reqMsg(responseWriter, 413)
			} else {
				reqMsg(responseWriter, 400)
			}
			return true
		}
		_, hasUser := request.PostForm["u"]
		_, hasPassword := request.PostForm["p"]
		if hasUser && hasPassword {
			if retryAfter := startLoginAttempt(clientIP); retryAfter > 0 { // no PBKDF2 for a blocked IP
				responseWriter.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
				reqMsg(responseWriter, 429)
				return true
			}
			loginOK, busy := checkLogin(request.PostForm["u"][0], request.PostForm["p"][0], passwordSlotWait, inPanelNetworks(clientIP))
			if busy {
				finishLoginAttempt(clientIP, false)
				responseWriter.Header().Set("Retry-After", "2")
				reqMsg(responseWriter, 503)
				return true
			}
			if loginOK {
				finishLoginAttempt(clientIP, false)
				forgetLoginFailures(clientIP)
				var token string
				withGlobalLock(func() { token = openSessionLocked(clientIP) })
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

// Failed logins per IP: after loginMaxFailures within loginFailureWindow, the IP gets 429 without any
// PBKDF2 for a while that doubles with each block (1, 2, 4... minutes, up to 15). A correct login forgets them.
// The attempts still being checked count too, so that concurrent ones can't add up to more.
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

// loginMaxNetworkFailures is how many failed logins the /64s of an IPv6 /48 may make together within
// loginFailureWindow: a /48, which a tunnel broker gives away, is 65 536 /64s, each with its own loginMaxFailures.
const loginMaxNetworkFailures = 20

// loginLimit is a count of failed logins and its limit: that of the client (an IPv4 address or an IPv6 /64), or
// that of its IPv6 /48.
type loginLimit struct {
	key string
	max int
}

// loginLimits are the counts a login attempt of ip goes into.
func loginLimits(ip string) []loginLimit {
	limits := []loginLimit{{limiterKey(ip), loginMaxFailures}}
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		limits = append(limits, loginLimit{parsed.Mask(net.CIDRMask(48, 128)).String() + "/48", loginMaxNetworkFailures})
	}
	return limits
}

// startLoginAttempt starts a login attempt of ip, which finishLoginAttempt must end, and returns 0; or, without
// starting it, the seconds to wait: what is left of a block of its client or of its /48, or passwordSlotWait while
// the failures and the attempts being checked already reach their limit.
func startLoginAttempt(ip string) int64 {
	limits := loginLimits(ip)
	loginFailuresMutex.Lock()
	defer loginFailuresMutex.Unlock()
	now := time.Now()
	for _, limit := range limits {
		failures, found := loginFailuresByIP[limit.key]
		if !found {
			failures = &loginFailures{}
			loginFailuresByIP[limit.key] = failures
		}
		if left := failures.blockedUntil.Sub(now); left > 0 {
			return int64((left + time.Second - 1) / time.Second)
		}
		if now.After(failures.windowEnd) {
			failures.count = 0 // The next failure opens a new window
		}
		if failures.count+failures.inFlight >= limit.max {
			return int64(passwordSlotWait / time.Second)
		}
	}
	for _, limit := range limits {
		loginFailuresByIP[limit.key].inFlight++
	}
	return 0
}

// finishLoginAttempt ends an attempt of ip started by startLoginAttempt and, if it failed, counts the failure and
// blocks its client, or its /48, when it reaches the limit.
func finishLoginAttempt(ip string, failed bool) {
	loginFailuresMutex.Lock()
	defer loginFailuresMutex.Unlock()
	now := time.Now()
	for _, limit := range loginLimits(ip) {
		failures, found := loginFailuresByIP[limit.key]
		if !found {
			continue
		}
		failures.inFlight = max(failures.inFlight-1, 0)
		if !failed {
			continue
		}
		if now.After(failures.windowEnd) {
			failures.count, failures.windowEnd = 0, now.Add(loginFailureWindow)
		}
		if failures.count++; failures.count < limit.max {
			continue
		}
		block := min(loginFirstBlock<<min(failures.blocks, 4), loginLongestBlock)
		failures.blocks++
		failures.count, failures.windowEnd, failures.blockedUntil = 0, now, now.Add(block)
		serverWriteLogs(denialsLogName, nil, 0, limit.key+" login denial "+block.String())
	}
}

// forgetLoginFailures clears the failed logins of the client of ip after a correct one (not those of its /48,
// which other clients may share).
func forgetLoginFailures(ip string) {
	ip = limiterKey(ip)
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

// warnDefaultCredentials logs when the panel still has the default password, with the default username or another
// one (TURBO_USER alone leaves the password Admin).
func warnDefaultCredentials() {
	switch {
	case !passwordMatches("Admin"):
	case panelUser.Get() == "Turbo":
		slog.Warn("The default credentials (Turbo/Admin) are in use: change them from the panel or with TURBO_USER and TURBO_PASSWORD.")
	default:
		slog.Warn("The default password (Admin) is in use: change it from the panel or with TURBO_PASSWORD.")
	}
}

// panelUserValid says whether a panel username can be used and saved as "U": 1 to 24 characters, without control
// characters, as setU and turbo.config take it.
func panelUserValid(user string) bool {
	return len(user) >= 1 && len(user) <= 24 && textAllowed(user, false)
}

func consoleHTMLRedir(redirectURL string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	responseWriter.Header().Set(contentTypeHeader, "text/html; charset=UTF-8")
	respond(responseWriter, "<meta http-equiv='refresh' content='0; URL="+redirectURL+"'/>")
}

// panelAccessList is the parsed "PA" setting: host names the panel answers on, and client networks it answers
// to. An empty list means no restriction.
type panelAccessList struct {
	setting  string
	hosts    map[string]bool
	networks []*net.IPNet
	ipHosts  []string // Hosts that are IP addresses, compared with Host as any host (not with the client's IP)
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
		return nil, "List too long"
	}
	var entries []string
	for _, entry := range strings.Split(setting, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		switch {
		case entry == "*": // Alone it means no restriction; in a list it would match nothing
			return nil, "The * wildcard is only valid as the only value (no restriction)"
		case strings.IndexByte(entry, '*') != -1: // The Host is compared exactly: a wildcard would never match
			return nil, "Wildcards not allowed in panel hosts: " + entry
		case strings.IndexByte(entry, '/') != -1:
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, "Invalid network: " + entry
			}
			list.networks = append(list.networks, network)
		default:
			if address, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(entry, "["), "]")); err == nil {
				entry = address.Unmap().String() // As panelAllowed compares it: "[::1]" and "::1" are the same host
				list.ipHosts = append(list.ipHosts, entry)
			} else if valid, _ := hostOk(entry, false); !valid {
				return nil, "Invalid host: " + entry
			}
			list.hosts[entry] = true
		}
		entries = append(entries, entry)
	}
	if len(entries) > 32 {
		return nil, "More than 32 hosts or networks"
	}
	list.setting = strings.Join(entries, ",")
	return list, ""
}

// isClientIP reports whether denying ip would deny the address the request comes from: it is that address, or an
// IPv6 address of its /64, which a denial covers (deniedUntil).
func isClientIP(ip string, request *customNetHttp.Request) bool {
	denied := net.ParseIP(strings.TrimSpace(ip))
	return denied != nil && limiterKey(ipAddr(denied.String())) == limiterKey(ipAddr(request.RemoteAddr))
}

// panelAllowed reports whether the panel answers this request under "PA": on one of its hosts, if it has any,
// and from one of its networks, if it has any.
func panelAllowed(request *customNetHttp.Request) bool {
	return panelAccessProblem(panelAccess.Load(), request) == ""
}

// panelAccessProblem says why list leaves the request out (its host, or its IP), or "" if it lets it in.
func panelAccessProblem(list *panelAccessList, request *customNetHttp.Request) string {
	hostName := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(hostWithoutPort(request), "["), "]"))
	if address, err := netip.ParseAddr(hostName); err == nil {
		hostName = address.Unmap().String()
	}
	if len(list.hosts) > 0 && !list.hosts[hostName] {
		return "the host " + hostName + " is not in the list"
	}
	if len(list.networks) == 0 {
		return ""
	}
	// With networks and no host, the panel answers on an IP address or localhost, which no other page can take: a
	// page of any name that the browser of someone in those networks loads, and whose name then resolves to Turbo
	// (DNS rebinding), would otherwise reach the panel from them, on its own origin.
	if _, notAddress := netip.ParseAddr(hostName); len(list.hosts) == 0 && notAddress != nil && hostName != "localhost" {
		return "the host " + hostName + " is a name, and PA only has networks: use an IP address, or add the host to PA"
	}
	clientIP := net.ParseIP(ipAddr(request.RemoteAddr))
	for _, network := range list.networks {
		if clientIP != nil && network.Contains(clientIP) {
			return ""
		}
	}
	return "the IP " + ipAddr(request.RemoteAddr) + " is not in any network of the list"
}

// panelHostConflict says which host of the list serves a site, which would put the panel in the same origin as
// that site's pages, or "" if none does. Callers hold the global lock.
func panelHostConflict(list *panelAccessList) string {
	hosts := make([]string, 0, len(list.hosts))
	for hostName := range list.hosts {
		hosts = append(hosts, hostName)
	}
	sort.Strings(hosts)
	for _, hostName := range hosts {
		if site := servingSite(hostName); site != "" {
			return "The panel host " + hostName + " serves the site " + site + ": use a host that serves no content"
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

// warnPanelOrigin logs when the panel shares an origin with the sites: PA has no host, or one of its hosts
// serves a site (accepted from turbo.config, so as not to break it). Callers hold the global read lock.
func warnPanelOrigin() {
	list := panelAccess.Load()
	if len(list.hosts) == 0 && len(list.networks) > 0 {
		slog.Warn("PA only has networks: the panel answers on IP addresses and localhost, not on host names. Set a host dedicated to the panel in PA to reach it by name.")
	} else if len(list.hosts) == 0 {
		slog.Warn("The panel answers on the same hosts as the sites: a page served by Turbo could use its session. Set a host dedicated to the panel in PA.")
	} else if conflict := panelHostConflict(list); conflict != "" {
		slog.Warn(conflict + " (PA of turbo.config: kept, but the panel shares its origin with that site)")
	}
}

// newSessionToken returns 32 random bytes in hex, unrelated to the credentials and unique per login.
func newSessionToken() string {
	random := make([]byte, 32)
	rand.Read(random) // Never fails (crypto/rand)
	return hex.EncodeToString(random)
}

// hashPassword returns "pbkdf2-sha256$<iterations>$<salt>$<key>" (standard base64), the "PH" format of
// turbo.config, with a random 16-byte salt and a 32-byte key. PBKDF2 can fail (in FIPS 140 mode, for one), and
// then there is no hash to use.
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt) // Never fails (crypto/rand)
	key, err := derivePasswordKey(password, salt, passwordHashIterations, 32)
	if err != nil {
		return "", err
	}
	return "pbkdf2-sha256$" + strconv.Itoa(passwordHashIterations) + "$" + base64.StdEncoding.EncodeToString(salt) + "$" + base64.StdEncoding.EncodeToString(key), nil
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
	// Bounded: each login derives a key of this length (a PBKDF2 per 32 bytes), so a "PH" with a huge key would make
	// every failed login cost minutes. hashPassword writes 16 bytes of salt and 32 of key.
	salt, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return 0, nil, nil, false
	}
	key, err = base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return 0, nil, nil, false
	}
	return iterations, salt, key, true
}

// setPanelPassword replaces the panel password; only its hash is kept. If it can't be hashed, the password in
// use stays and the error is returned.
func setPanelPassword(password string) error {
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	applyPasswordHash(hash, password)
	return nil
}

// applyPasswordHash makes hash, made by hashPassword from password, the panel's password.
// The current username and the new password are a pair that matches: a login with them needs no PBKDF2.
func applyPasswordHash(hash string, password string) {
	panelPasswordHash.Set(hash)
	verifiedPassword.Store(&passwordCheck{hash, sha256.Sum256([]byte(hash + "\x00" + password))})
	verifiedLogin.Store(&passwordCheck{hash, sha256.Sum256([]byte(hash + "\x00" + panelUser.Get() + "\x00" + password))})
}

// newPasswordHash checks a new panel password and returns its hash, or why it can't be used (problem), or the
// error that kept it from being hashed. It costs two PBKDF2, so setP runs it before taking the global lock.
func newPasswordHash(password string) (hash string, problem string, err error) {
	if length := len(password); length < minNewPasswordBytes || length > maxPasswordBytes {
		return "", "The password must have " + strconv.Itoa(minNewPasswordBytes) + " to " + strconv.Itoa(maxPasswordBytes) + " bytes", nil
	}
	if passwordMatches(password) {
		return "", "Password unchanged", nil
	}
	hash, err = hashPassword(password)
	return hash, "", err
}

// passwordSlotWait is how long a password check from a request waits for a PBKDF2 slot before giving up with 503:
// a flood of logins can't keep the administrator waiting without limit.
const passwordSlotWait = 2 * time.Second

// minNewPasswordBytes and maxPasswordBytes bound the length of a password: a new one (setP) needs at least
// minNewPasswordBytes, as the failed-login limits only slow down guessing a short one; one already in use
// (turbo.config, TURBO_PASSWORD) keeps working, with a warning at startup if it is shorter.
const (
	minNewPasswordBytes = 12
	maxPasswordBytes    = 64
)

// passwordReservedSlot is a PBKDF2 slot kept for the password checks of the requests with a panel session (the
// current password of an action) and of the logins from the networks of PA: a flood of logins from elsewhere, which
// takes the other slots, doesn't keep the administrator out (503).
var passwordReservedSlot = make(chan struct{}, 1)

// acquirePasswordSlot takes a PBKDF2 slot, waiting at most wait (0: as long as needed); priority callers may also
// take passwordReservedSlot. It returns how to give it back, or false if there was none in time.
func acquirePasswordSlot(wait time.Duration, priority bool) (release func(), acquired bool) {
	slots, reserved := passwordHashSlots, passwordReservedSlot
	normal := func() { <-slots }
	if wait == 0 {
		slots <- struct{}{}
		return normal, true
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	if priority {
		select {
		case slots <- struct{}{}:
			return normal, true
		case reserved <- struct{}{}:
			return func() { <-reserved }, true
		case <-timer.C:
			return nil, false
		}
	}
	select {
	case slots <- struct{}{}:
		return normal, true
	case <-timer.C:
		return nil, false
	}
}

// inPanelNetworks reports whether ip is in one of the networks of PA (false without networks).
func inPanelNetworks(ip string) bool {
	parsed := net.ParseIP(ip)
	for _, network := range panelAccess.Load().networks {
		if parsed != nil && network.Contains(parsed) {
			return true
		}
	}
	return false
}

// passwordMatches reports whether password is the panel's (or internalAuth), comparing in constant time. It
// waits for a PBKDF2 slot as long as needed.
func passwordMatches(password string) bool {
	matches, _ := checkPassword(password, 0, false)
	return matches
}

// checkPassword is passwordMatches waiting at most wait for a PBKDF2 slot (0: as long as needed), the reserved one
// too with priority. busy reports that there was none in time, and then matches is false.
func checkPassword(password string, wait time.Duration, priority bool) (matches bool, busy bool) {
	if subtle.ConstantTimeCompare([]byte(password), []byte(internalAuth)) == 1 {
		return true, false
	}
	return derivePasswordCheck(password, wait, true, priority)
}

// checkLogin is checkPassword for a login: both the username and the password must match. Only a pair that
// already matched skips the PBKDF2, so a wrong username costs the same as a wrong password.
func checkLogin(user string, password string, wait time.Duration, priority bool) (matches bool, busy bool) {
	userMatches := subtle.ConstantTimeCompare([]byte(user), []byte(panelUser.Get())) == 1
	hash := panelPasswordHash.Get()
	sum := sha256.Sum256([]byte(hash + "\x00" + user + "\x00" + password))
	if last := verifiedLogin.Load(); userMatches && last != nil && last.hash == hash && subtle.ConstantTimeCompare(last.sum[:], sum[:]) == 1 {
		return true, false
	}
	passwordOK, busy := derivePasswordCheck(password, wait, false, priority)
	if passwordOK && userMatches {
		verifiedLogin.Store(&passwordCheck{hash, sum})
	}
	return passwordOK && userMatches, busy
}

// derivePasswordCheck compares password with panelPasswordHash. With useCache, the last password that matched is
// accepted without a PBKDF2; with priority, the reserved PBKDF2 slot may be used.
func derivePasswordCheck(password string, wait time.Duration, useCache bool, priority bool) (matches bool, busy bool) {
	// PBKDF2 uses the password as an HMAC key, padded with zeros: "x" and "x\x00" would match the same hash. No
	// password can have a NUL (the panel rejects control characters, and an environment variable can't hold one).
	if strings.IndexByte(password, 0) != -1 {
		return false, false
	}
	hash := panelPasswordHash.Get()
	sum := sha256.Sum256([]byte(hash + "\x00" + password))
	if last := verifiedPassword.Load(); useCache && last != nil && last.hash == hash && subtle.ConstantTimeCompare(last.sum[:], sum[:]) == 1 {
		return true, false
	}
	iterations, salt, key, ok := parsePasswordHash(hash)
	if !ok {
		return false, false
	}
	release, acquired := acquirePasswordSlot(wait, priority)
	if !acquired {
		return false, true
	}
	derived, err := derivePasswordKey(password, salt, iterations, len(key))
	release()
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
		slog.Warn("Invalid PH in turbo.config: ignored")
	}
	if password, isString := settings["P"].(string); isString && len(password) >= 1 && len(password) <= 24 {
		slog.Warn("Plain-text password in turbo.config: only its hash will be saved")
		if err := setPanelPassword(password); err != nil {
			slog.Error("Can't hash the password of turbo.config: the previous one is kept", "error", err)
		}
	}
}

// uploadedFilePath returns where an uploaded file goes inside @. The browser sends the chosen folder as the
// first segment of each name, so it is dropped ("site/css/a.css" -> "css/a.css"). Names that would leave @
// ("..", absolute or with a volume) are rejected, and so are those the file systems can't hold: a segment
// longer than maxUploadNameSegment bytes or a path longer than maxUploadPath.
func uploadedFilePath(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	if _, rest, found := strings.Cut(name, "/"); found {
		name = rest
	}
	if name == "" || len(name) > maxUploadPath || strings.HasPrefix(name, "/") || filepath.VolumeName(name) != "" || strings.IndexByte(name, ':') != -1 {
		return "", false
	}
	for _, segment := range strings.Split(name, "/") {
		// Names that Windows treats specially are refused on every system, so the site can be moved.
		if segment == "" || segment == "." || segment == ".." || len(segment) > maxUploadNameSegment || !pathSegmentAllowed(segment, true) {
			return "", false
		}
	}
	return name, true
}

const (
	maxUploadNameSegment = 255  // Bytes of a file or folder name: what ext4 allows (NTFS, 255 UTF-16 units)
	maxUploadPath        = 1024 // Bytes of a path inside @, well below what Linux allows with the sites directory
)

// charsDecodedByValidator lists, per action, the parameters whose character replacements its validator undoes
// itself; undoCharReplacements undoes them in all the others.
var charsDecodedByValidator = map[string]map[string]bool{
	"addRewrite": {"a": true, "b": true}, "addMIME": {"b": true}, "addHeader": {"b": true},
	"addIndex": {"a": true}, "delRewrite": {"a": true}, "delIndex": {"a": true},
}

// literalActions are the panel actions whose parameters are all used exactly as sent, without undoing the
// character replacements: those that need the current password (with set<KEY> and cfg<KEY>, which all take theirs
// as sent), and those that change the replacements or the error templates. A replacement whose token is a site's or
// an extension's name, or part of a path, would otherwise change what a password confirms: delSite deleted another
// site, delPreprocessor another extension's preprocessor (its files then served as text), and addPreprocessor saved
// another program. hardUpload doesn't come here: none of its parameters are replaced.
var literalActions = map[string]bool{
	"addPreprocessor": true, "delPreprocessor": true, "delSite": true,
	"addCharsReplace": true, "delCharsReplace": true, "addHttpCodeResponse": true, "delHttpCodeResponse": true,
	"closeSessions": true,
}

// undoCharReplacements turns the character replacements of §2.1 of the API ("-.-" for ";" and the rest) back
// into their characters in the parameters of a panel action, once, before the action reads them. The actions of
// literalActions, set<KEY> and cfg<KEY> are left as they come, and so are the site and the subdomain (s, d) of
// every action: a host name has no character that needs a replacement, and a token can't be told from a name typed
// on purpose.
func undoCharReplacements(request *customNetHttp.Request, apiPath string) {
	if literalActions[apiPath] || strings.HasPrefix(apiPath, "set") || strings.HasPrefix(apiPath, "cfg") {
		return
	}
	globalMutex.RLock() // charReplacements
	defer globalMutex.RUnlock()
	for name, values := range request.Form {
		if name == "s" || name == "d" || charsDecodedByValidator[apiPath][name] {
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
		respond(responseWriter, "Maximum body size exceeded")
		return
	}
	badReq(responseWriter, request, "Invalid parameters")
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
		return false, "Site already exists."
	}
	if valid, message := hostOk(domain, false); !valid {
		return false, message
	}
	if problem := newSiteProblem(domain, ""); problem != "" {
		return false, problem
	}
	// Subdomains map keys coincidence detection
	if matched, matchedSite, _, subdomain := detectWildcards(domain, ""); matched {
		if matched, _, _, matchedSite = detectWildcards(matchedSite, subdomain); matched {
			return false, "Matches site: " + matchedSite + "." + subdomain
		}
	}
	constructSiteLocked(domain, "")
	if panelHost := panelHostServedBy(domain); panelHost != "" { // undone before anything reaches the disk
		deleteSiteLocked(domain, "")
		return false, "The site would serve the panel host " + panelHost + ": use another host for the panel or for the site"
	}
	if os.MkdirAll(sitesDir.Get()+changeWildcards(domain)+"/"+publicDirName+"/", 0755) != nil { // #nosec G301 -- public web content of a site, served by Turbo
		deleteSiteLocked(domain, "")
		return false, "Error creating"
	}
	forgetDormantLocked(domain, "") // A site created from the panel starts anew, its subdomains too
	return true, "Site added"
}

// addSubdomain creates a subdomain of an existing site from the panel. Callers hold the global lock.
func addSubdomain(domain string, subdomain string) (bool, string) {
	if _, exists := sitesMap[domain]; !exists {
		return false, "Site not found"
	}
	if valid, message := hostOk(subdomain+"."+changeWildcards(domain, "x"), false); !valid { // A wildcard is only accepted at the beginning
		return false, message
	}
	if siteExists(domain, subdomain) {
		return false, "Subdomain already exists"
	}
	if problem := newSiteProblem(domain, subdomain); problem != "" {
		return false, problem
	}
	// Domains map keys coincidence detection
	if matched, _, _, matchedSite := detectWildcards(subdomain+"."+domain, ""); matched && matchedSite != domain {
		return false, "Matches site: " + matchedSite
	}
	constructSiteLocked(domain, subdomain)
	if panelHost := panelHostServedBy(subdomain + "." + domain); panelHost != "" { // undone before anything reaches the disk
		deleteSiteLocked(domain, subdomain)
		return false, "The subdomain would serve the panel host " + panelHost + ": use another host for the panel or for the subdomain"
	}
	if os.MkdirAll(sitesDir.Get()+changeWildcards(domain)+"/"+changeWildcards(subdomain)+"/"+publicDirName+"/", 0755) != nil { // #nosec G301 -- public web content of a site, served by Turbo
		deleteSiteLocked(domain, subdomain)
		return false, "Error creating"
	}
	forgetDormantLocked(domain, subdomain) // A subdomain created from the panel starts anew
	return true, "Subdomain added"
}

// currentPasswordOK checks the current password (b) of a panel action as a login does: it counts for the
// failed-login limit of the client's IP, which gets 429 without any PBKDF2 while it is blocked. When the password
// isn't accepted, it answers the request itself and reports false.
func currentPasswordOK(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, password string) bool {
	clientIP := ipAddr(request.RemoteAddr)
	if retryAfter := startLoginAttempt(clientIP); retryAfter > 0 {
		responseWriter.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
		reqMsg(responseWriter, 429)
		return false
	}
	matches, busy := checkPassword(password, passwordSlotWait, true) // The request has a session: the reserved slot too
	finishLoginAttempt(clientIP, !matches && !busy)
	if busy {
		responseWriter.Header().Set("Retry-After", "2")
		reqMsg(responseWriter, 503)
		return false
	}
	if !matches {
		badReq(responseWriter, request, "Wrong current password")
		return false
	}
	return true
}

// hardUpload replaces the public folder (@) of a site with the uploaded files, all at once: every name is
// checked first, the files are written to a folder of their own next to @, and that folder takes the place of @
// with a rename, holding the global lock and only if the site still exists, so a site deleted meanwhile doesn't
// come back. Until then, @ is left as it was. It returns the status and the message of the response.
func hardUpload(domain string, subdomain string, siteDir string, files []*customNetHttp.FileHeader) (int, string) {
	type upload struct {
		file *customNetHttp.FileHeader
		path string
	}
	var uploads []upload
	var discarded []string
	// A file and a folder can't have the same name: the later one is discarded. Where the file system ignores
	// case, names are compared that way.
	foldCase := runtime.GOOS == "windows" || runtime.GOOS == "darwin"
	filePaths, folderPaths := map[string]bool{}, map[string]bool{}
	for _, uploadedFile := range files {
		name := uploadedFile.Filename
		if _, fileMetadata, err := mime.ParseMediaType(uploadedFile.Header.Get("Content-Disposition")); err == nil {
			name = fileMetadata["filename"] // As sent: Filename drops the folders
		}
		relativePath, ok := uploadedFilePath(name)
		key := relativePath
		if foldCase {
			key = strings.ToLower(key)
		}
		var folders []string // The folders the file goes in, none of which may be an uploaded file
		for i := 0; i < len(key); i++ {
			if key[i] == '/' {
				folders = append(folders, key[:i])
				ok = ok && !filePaths[key[:i]]
			}
		}
		if !ok || folderPaths[key] {
			discarded = append(discarded, name)
			continue
		}
		filePaths[key] = true
		for _, folder := range folders {
			folderPaths[folder] = true
		}
		uploads = append(uploads, upload{uploadedFile, relativePath})
	}
	if len(uploads) == 0 {
		return 400, "No valid file; nothing was changed. Discarded: " + strings.Join(discarded, ", ")
	}

	stagingDir, err := os.MkdirTemp(siteDir, publicDirName+".upload-")
	if err != nil {
		return 400, "Directory inaccessible"
	}
	stagingDir += "/"
	defer os.RemoveAll(stagingDir) // #nosec G104 -- after the swap it no longer exists; otherwise, best effort
	for _, file := range uploads {
		if err = writeUploadedFile(file.file, stagingDir+file.path); err != nil {
			slog.Error("hardUpload: can't write the file", "file", file.path, "error", err)
			return 500, "Error writing " + file.path + "; nothing was changed"
		}
	}

	beforeUploadSwap()
	contentDir := siteDir + publicDirName
	previousDir := contentDir + ".previous-" + newSessionToken()[:16]
	siteGone := false
	withGlobalLock(func() {
		if siteGone = !siteExists(domain, subdomain); siteGone {
			return
		}
		if err = os.Rename(contentDir, previousDir); err != nil {
			return
		}
		if err = os.Rename(stagingDir, contentDir); err != nil {
			if os.Rename(previousDir, contentDir) != nil {
				slog.Error("hardUpload: can't restore the public directory", "directory", contentDir, "backup", previousDir)
			}
		}
	})
	if siteGone {
		return 400, "Site not found"
	}
	if err != nil { // On Windows, for one, a file of @ that is open
		slog.Error("hardUpload: can't replace the public directory", "directory", contentDir, "error", err)
		return 400, "The public directory could not be replaced (open files?); nothing was changed"
	}
	if err = os.RemoveAll(previousDir); err != nil {
		slog.Warn("hardUpload: can't delete the previous content", "directory", previousDir, "error", err)
	}
	if len(discarded) > 0 {
		return 200, "Data uploaded. Discarded: " + strings.Join(discarded, ", ")
	}
	return 200, "Data uploaded"
}

// writeUploadedFile writes an uploaded file to targetPath, creating its folders.
func writeUploadedFile(uploadedFile *customNetHttp.FileHeader, targetPath string) error {
	srcFile, err := uploadedFile.Open()
	if err != nil {
		return err
	}
	defer srcFile.Close() // #nosec G307 -- in memory (P10): closing it can't fail

	if err = os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil { // #nosec G301 -- public web content of a site, served by Turbo
		return err
	}
	dstFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644) // #nosec G302 G304 -- public web content; uploadedFilePath rejects .. and absolute paths, so it stays under the upload folder
	if err != nil {
		return err
	}
	_, err = io.Copy(dstFile, srcFile)
	if closeErr := dstFile.Close(); err == nil { // A failed close can mean an incomplete file
		err = closeErr
	}
	return err
}

// beforeSessionRenewal runs right before a panel request renews its session (a hook for tests).
var beforeSessionRenewal = func() {}

// beforeUploadSwap runs right before hardUpload puts the uploaded files in place of @ (a hook for tests).
var beforeUploadSwap = func() {}

// lockedCheck runs a validator holding the global write lock, releasing it even if the validator panics.
func lockedCheck(check func() (bool, string)) (bool, string) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	return check()
}

// lockedCheckLooking is lockedCheck with what look saw of the disk for the validator (diskLook).
func lockedCheckLooking(look *diskLook, check func() (bool, string)) (bool, string) {
	return lockedCheck(func() (bool, string) {
		lookedDisk = look
		defer func() { lookedDisk = nil }()
		return check()
	})
}

// setSitesDir is setM once the current password matched. The new directory is checked before taking any lock;
// the change and the reload that follows hold settingsUpdateMutex, so the periodic reload can't mix the two
// directories. Its turbo.config is always read, also with the same date as the one in use. Without one there,
// the global settings, the credentials and the lists in use stay, to be written there with the next save; a
// pointer in the start directory counts as none, so going back there stays there. With one, it applies whole and
// the answer says what it changed of where the panel answers and of its credentials.
func setSitesDir(value string, currentSession string) (bool, string) {
	resolved, err := resolveSitesDir(value)
	if err != nil {
		return false, "Sites directory not found"
	}
	if info, err := os.Stat(resolved); err != nil || !info.IsDir() {
		return false, "Sites directory not found"
	}
	// Listed before anything changes: one whose sites can't be listed (permissions that only let it be crossed)
	// would leave the server without sites until "M" is set back.
	if _, err := os.ReadDir(resolved); err != nil {
		return false, "Sites directory can't be read"
	}
	if sameDir(resolved, sitesDir.Get()) {
		return false, "Sites directory unchanged"
	}
	// The turbo.config there and every directory it leads to, before anything changes: resetSettings below empties
	// the configuration in use, and a chain that can't be followed left the sites with the defaults.
	if err := configFileProblem(resolved, sameDir(resolved, startDir)); err != nil {
		return false, "The sites directory is not changed. " + configErrorMessage(err, false)
	}
	settingsUpdateMutex.Lock()
	defer settingsUpdateMutex.Unlock()
	type panelSettings struct{ access, user, hash string }
	current := func() panelSettings {
		return panelSettings{panelAccess.Load().setting, panelUser.Get(), panelPasswordHash.Get()}
	}
	before := current()
	look := newDiskLook() // What the validator of M looks at, looked at before the lock
	look.stat(resolved)
	if inUse, err := resolveSitesDir(sitesDir.Get()); err == nil {
		look.stat(inUse)
	}
	applied, message := lockedCheckLooking(look, func() (bool, string) { return defaultSettingValidators["."]["M"](value, internalAuth) })
	if !applied {
		return false, message
	}
	options := reloadOptions{keepWithoutConfig: true, ignorePointer: sameDir(resolved, startDir), keepSession: currentSession}
	configBytes, readErr := os.ReadFile(resolved + configFileName) // #nosec G304 -- turbo.config of the sites directory chosen by the administrator
	kept := readErr != nil || options.ignorePointer && isSitesDirPointer(configBytes)
	resetSettings()
	withGlobalLock(func() { configFileModTime = 0 }) // Read even with the same date as the one in use
	if err = updateSettingsFollowing(true, 0, options); err != nil {
		slog.Error(configErrorMessage(err, false))
		return true, message + ", but its configuration could not be applied:\n" + err.Error()
	}
	if kept {
		return true, message + ". No turbo.config there: the global settings, the credentials and the lists in use are kept, and they will be written there when saving"
	}
	shown := func(access string) string {
		if access == "" {
			return "any host and network"
		}
		return access
	}
	after := current()
	var changes []string
	if after.access != before.access {
		changes = append(changes, "where the panel answers (PA): \""+shown(before.access)+"\" → \""+shown(after.access)+"\"")
	}
	if after.user != before.user || after.hash != before.hash {
		changes = append(changes, "the panel's user or password: those of that directory apply")
	}
	if len(changes) > 0 {
		message += ". Its turbo.config changes " + strings.Join(changes, "; ")
	}
	return true, message
}

// dangerousActionPasswordOK checks the current password that an action able to run programs on the server, to
// serve the source of a site's scripts, to delete a site's files or a certificate, to change what every site
// serves or what the panel's actions read, or to close every session needs besides the session (addPreprocessor,
// delPreprocessor, hardUpload, delSite, cfgC and cfgPC with a=0, add/del of HttpCodeResponse and CharsReplace, and
// closeSessions), sent in param of values: missing, 400; wrong, it counts as a failed login, as in set<KEY>. A
// stolen session alone can do none of these. It reports whether to go on.
func dangerousActionPasswordOK(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, values map[string][]string, param string) bool {
	password, sent := values[param]
	if !sent || len(password) == 0 {
		badReq(responseWriter, request, msgMissingData+": the current password ("+param+")")
		return false
	}
	return currentPasswordOK(responseWriter, request, password[0])
}

// consoleActionsAPI runs a panel action of the session currentSession.
func consoleActionsAPI(apiPath string, currentSession string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) (handled bool) {
	if request.Method != customNetHttp.MethodPost {
		return false
	}

	defer func() { // A panic in a validator must not take down the panel
		if p := recover(); p != nil {
			slog.Error("Panic in the panel API", "action", apiPath, "error", p)
			reqMsg(responseWriter, 500)
			handled = true
		}
	}()

	if len(apiPath) < 4 {
		return false
	}
	// No saved value may have control characters; a response template may span lines. hardUpload reads
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
				// Every setting needs the current password (b). It is checked here, before taking the lock,
				// as a wrong one costs a PBKDF2; the validator then gets internalAuth.
				if _, paramExists = request.Form["b"]; !paramExists {
					badReq(responseWriter, request, msgMissingData)
					return true
				}
				if !currentPasswordOK(responseWriter, request, currentPassword) {
					return true
				}
				if apiPath == "M" { // Nothing of the new directory is read before the password matched
					credentials := panelUser.Get() + "\x00" + panelPasswordHash.Get()
					if applied, message := setSitesDir(argumentList[0], currentSession); applied {
						if panelUser.Get()+"\x00"+panelPasswordHash.Get() != credentials { // Those of the new directory: as with setU and setP
							withGlobalLock(func() { renewCredentialsSessionLocked(responseWriter, request) })
						}
						respond(responseWriter, message)
					} else {
						badReq(responseWriter, request, message)
					}
					return true
				}
				argumentList = append(argumentList, internalAuth)
				if apiPath == "P" { // PBKDF2 without the global lock
					hash, problem, err := newPasswordHash(argumentList[0])
					if err != nil {
						slog.Error("Can't hash the new password", "error", err)
						reqMsg(responseWriter, 500)
						return true
					}
					if problem != "" {
						badReq(responseWriter, request, problem)
						return true
					}
					argumentList = append(argumentList, hash)
				}

				if apiPath == "C" { // Saving writes files: it takes the locks itself, without holding the global one meanwhile
					if applied, message := defaultSettingValidators["."]["C"](argumentList...); applied {
						respond(responseWriter, message)
					} else {
						badReq(responseWriter, request, message)
					}
					return true
				}
				applied, message := lockedCheck(func() (bool, string) {
					if apiPath == "PA" { // the panel's host can't be a site's
						if list, _ := parsePanelAccess(argumentList[0]); list != nil {
							if conflict := panelHostConflict(list); conflict != "" {
								return false, conflict
							}
							if problem := panelAccessProblem(list, request); problem != "" { // The administrator would lock themselves out
								return false, "The panel would stop answering this very request: " + problem
							}
						}
					}
					ok, msg := defaultSettingValidators["."][apiPath](argumentList...)
					if ok && (apiPath == "U" || apiPath == "P") { // New credentials: every session ends, and this client gets a new one
						renewCredentialsSessionLocked(responseWriter, request)
					}
					return ok, msg
				})
				if !applied {
					badReq(responseWriter, request, message)
				} else {
					respond(responseWriter, message)
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
				if apiPath == "Preprocessor" && !dangerousActionPasswordOK(responseWriter, request, request.Form, "c") { // b is the executable
					return true
				}
				look := newDiskLook()
				if apiPath == "Preprocessor" { // The disk is looked at before taking the lock; the path is used as sent (literalActions)
					if executable, problem := preprocessorCommand(request.Form["b"][0]); problem == "" {
						look.stat(executable)
						if looked := look.stats[executable]; looked.err != nil {
							badReq(responseWriter, request, "Preprocessor not found")
							return true
						} else if looked.info.IsDir() {
							badReq(responseWriter, request, "Invalid preprocessor")
							return true
						}
					}
				}
				kind := "=" // The key of the validator: rewrites
				switch apiPath[0] {
				case 'M':
					kind = "$"
				case 'H':
					kind = "."
				case 'P':
					kind = "?"
				}
				entries := map[string]interface{}{request.Form["a"][0]: request.Form["b"][0]}
				applied, message := lockedCheckLooking(look, func() (bool, string) {
					return subdomainContentCheckers[kind](true, entries, false, request.Form["s"][0], request.Form["d"][0])
				})
				if !applied {
					badReq(responseWriter, request, message)
				} else {
					respond(responseWriter, message)
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
				kind := "-" // The key of the validator: indexes
				if apiPath[0] == 'A' {
					kind = "&"
				}
				argumentValues := map[string]interface{}{request.Form["a"][0]: false}
				applied, message := lockedCheck(func() (bool, string) {
					if kind == "&" && panelAccess.Load().hosts[strings.ToLower(request.Form["a"][0])] { // The panel's host is never a site's
						return false, "The alias " + request.Form["a"][0] + " is a panel host: use another host for the panel or for the alias"
					}
					return subdomainContentCheckers[kind](true, argumentValues, false, request.Form["s"][0], request.Form["d"][0])
				})
				if !applied {
					badReq(responseWriter, request, message)
				} else {
					respond(responseWriter, message)
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
			// between checking and creating.
			applied, message := lockedCheck(func() (bool, string) { return addSubdomain(request.Form["s"][0], request.Form["d"][0]) })
			if !applied {
				badReq(responseWriter, request, message)
				return true
			}
			respond(responseWriter, message)
			return true

		case "Site":
			if _, sourceParamExists := request.Form["s"]; !sourceParamExists {
				badReq(responseWriter, request, msgMissingData)
				return true
			}
			applied, message := lockedCheck(func() (bool, string) { return addSite(request.Form["s"][0]) })
			if !applied {
				badReq(responseWriter, request, message)
				return true
			}
			respond(responseWriter, message)
			return true

		case "Denied", "HttpCodeResponse", "CharsReplace":
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			if sourceParamExists && destinationParamExists {
				if apiPath != "Denied" && !dangerousActionPasswordOK(responseWriter, request, request.Form, "b") {
					return true
				}
				kind := "#" // The key of the handler: responses
				switch apiPath[0] {
				case 'C':
					kind = "_"
				case 'D':
					kind = "@"
					if isClientIP(request.Form["s"][0], request) { // The panel would lock itself out
						badReq(responseWriter, request, "Current IP")
						return true
					}
				}
				applied, message := lockedCheck(func() (bool, string) { return adminAddHandlers[kind](request.Form["s"][0], request.Form["d"][0]) })
				if !applied {
					badReq(responseWriter, request, message)
					return true
				}
				respond(responseWriter, message)
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
				// Without its preprocessor, the extension's files would be served as text, their source included
				if apiPath == "Preprocessor" && !dangerousActionPasswordOK(responseWriter, request, request.Form, "b") {
					return true
				}
				kind := "=" // The key of the deleter: rewrites
				switch apiPath[0] {
				case 'A':
					kind = "&"
				case 'I':
					kind = "-"
				case 'P':
					kind = "?"
				case 'H':
					kind = "."
				case 'M':
					kind = "$"
				}
				argumentValues := map[string]interface{}{request.Form["a"][0]: false}
				applied, message := lockedCheck(func() (bool, string) {
					return subdomainContentDeleters[kind](true, argumentValues, request.Form["s"][0], request.Form["d"][0])
				})
				if !applied {
					badReq(responseWriter, request, message)
				} else {
					respond(responseWriter, message)
				}
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "Site":
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			if sourceParamExists && destinationParamExists {
				if !dangerousActionPasswordOK(responseWriter, request, request.Form, "b") {
					return true
				}
				what := "Site"
				isSubdomain := request.Form["d"][0] != ""
				if isSubdomain {
					what = "Subdomain"
				}
				var exists, kept bool
				withReadLock(func() {
					exists = siteExists(request.Form["s"][0], request.Form["d"][0])
					_, kept = dormantSites[request.Form["s"][0]][request.Form["d"][0]] // Its folder isn't there: what is kept of it
				})
				if !exists && !kept {
					badReq(responseWriter, request, what+" not found")
					return true
				}
				siteDir := sitesDir.Get() + changeWildcards(request.Form["s"][0])
				if isSubdomain {
					siteDir += "/" + changeWildcards(request.Form["d"][0])
				}
				siteDir += "/"
				if os.RemoveAll(siteDir) != nil {
					badReq(responseWriter, request, "Error deleting")
					return true
				}
				deleteSite(request.Form["s"][0], request.Form["d"][0])
				respond(responseWriter, what+" deleted")
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "Denied", "HttpCodeResponse", "CharsReplace":
			_, sourceParamExists := request.Form["s"]
			if sourceParamExists {
				if apiPath != "Denied" && !dangerousActionPasswordOK(responseWriter, request, request.Form, "b") {
					return true
				}
				kind := "#" // The key of the handler: responses
				switch apiPath[0] {
				case 'C':
					kind = "_"
				case 'D':
					kind = "@"
				}
				applied, message := lockedCheck(func() (bool, string) { return adminDeleteHandlers[kind](request.Form["s"][0]) })
				if !applied {
					badReq(responseWriter, request, message)
					return true
				}
				respond(responseWriter, message)
				return true
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true
		}
		return false

	case "cfg":
		apiPath = apiPath[3:]
		if _, handlerExists := siteSSLSettingCheckers[apiPath]; handlerExists || apiPath == "PC" { // PC: the panel's certificate, of no site
			_, argumentParamExists := request.Form["a"]
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			if apiPath == "PC" {
				sourceParamExists, destinationParamExists = true, true
			}
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
				if (apiPath == "C" || apiPath == "PC") && request.Form["a"][0] == "0" && !dangerousActionPasswordOK(responseWriter, request, request.Form, "b") { // Deleting a certificate
					return true
				}
				look := newDiskLook() // The certificate files C and S look at, looked at before the lock
				known := false        // Only the folders of existing sites (PC has no site)
				if apiPath == "C" || apiPath == "S" {
					withReadLock(func() { known = siteExists(request.Form["s"][0], request.Form["d"][0]) })
				}
				if known {
					folder := sitesDir.Get() + siteFolder(request.Form["s"][0], request.Form["d"][0])
					look.siteFiles(folder, apiPath == "S" && request.Form["a"][0] != "0")
					look.stat(sitesDir.Get() + putSlash(certificatesDirName))
				}
				applied, message := lockedCheckLooking(look, func() (bool, string) {
					if apiPath == "PC" {
						return panelCertificateAction(request.Form["a"][0], email, adapter, yParamExists)
					}
					return siteSSLSettingCheckers[apiPath](false, request.Form["a"][0], request.Form["s"][0], request.Form["d"][0], email, adapter)
				})
				if !applied && strings.Contains(message, `"status":"WAIT"`) { // In progress, not an error
					responseWriter.Header().Set(contentTypeHeader, jsonContentType)
					responseWriter.WriteHeader(202)
					respond(responseWriter, message)
					return true
				}
				if !applied {
					badReq(responseWriter, request, message)
					return true
				}
				if apiPath == "PC" && request.Form["a"][0] == "0" && request.TLS != nil {
					// Without its certificate the panel's host has no HTTPS: the browser has to be able to come back by HTTP
					responseWriter.Header().Set("Strict-Transport-Security", "max-age=0")
				}
				respond(responseWriter, message)
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
			// A whole site is uploaded at once: up to 10 000 files, each with two headers.
			request = customNetHttp.TurboWithFormLimits(request, 10000, 20000)
			if readErr := request.ParseMultipartForm(maxBodySize.Load()); readErr != nil && readErr != customNetHttp.ErrNotMultipart {
				formRejected(responseWriter, request, readErr) // 413 if too large, 400 if malformed
				return true
			}
			if request.MultipartForm != nil {
				defer request.MultipartForm.RemoveAll()
			}
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			if !sourceParamExists || !destinationParamExists {
				badReq(responseWriter, request, msgMissingData)
				return true
			}
			if !dangerousActionPasswordOK(responseWriter, request, request.PostForm, "b") { // Only in the body: the URL is logged
				return true
			}
			if problem := formTextProblem(request, false); problem != "" {
				badReq(responseWriter, request, problem)
				return true
			}
			var exists bool
			withReadLock(func() { exists = siteExists(request.Form["s"][0], request.Form["d"][0]) })

			if !exists {
				if request.Form["d"][0] != "" {
					badReq(responseWriter, request, "Subdomain not found")
				} else {
					badReq(responseWriter, request, "Site not found")
				}
				return true
			}

			if request.MultipartForm == nil || len(request.MultipartForm.File["f"]) == 0 {
				badReq(responseWriter, request, "No data")
				return true
			}

			siteDir := sitesDir.Get() + changeWildcards(request.Form["s"][0]) + "/"
			if request.Form["d"][0] != "" {
				siteDir += changeWildcards(request.Form["d"][0]) + "/"
			}
			status, message := hardUpload(request.Form["s"][0], request.Form["d"][0], siteDir, request.MultipartForm.File["f"])
			if status != 200 {
				responseWriter.WriteHeader(status)
			}
			respond(responseWriter, message)
			return true

		case "closeSessions":
			// Every session ends, the request's own too, and its client gets a new one, as when the credentials
			// change: a copy of a token (a cookie taken from the same IP) is then worth nothing. It needs the
			// password, so that a stolen session can't close the administrator's.
			if !dangerousActionPasswordOK(responseWriter, request, request.Form, "b") {
				return true
			}
			withGlobalLock(func() { renewCredentialsSessionLocked(responseWriter, request) })
			slog.Info("Every session of the panel closed from the panel", "ip", ipAddr(request.RemoteAddr))
			respond(responseWriter, "Every session closed: this one goes on with a new token")
			return true

		case "sites":
			// The response is built with the read lock and written without it: a client that reads slowly
			// doesn't hold back a pending Lock, and through it, every other request.
			var response string
			withReadLock(func() { response = createDefaultConfig(false, true, false) })
			respondJSON(responseWriter, response)
			return true

		case "subdomains":
			_, paramExists := request.Form["s"]
			if paramExists {
				var exists bool
				response := ""
				withReadLock(func() {
					if exists = siteExists(request.Form["s"][0], ""); exists {
						response = createSubdomainsList(false, request.Form["s"][0])
					}
				})

				if !exists {
					badReq(responseWriter, request, "Site not found")
					return true
				}
				respondJSON(responseWriter, response)
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "subdomainData":
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			if sourceParamExists && destinationParamExists {
				var exists bool
				response := ""
				withReadLock(func() {
					if exists = siteExists(request.Form["s"][0], request.Form["d"][0]); exists {
						response = createSubdomainData(request.Form["s"][0], request.Form["d"][0])
					}
				})

				if !exists {
					badReq(responseWriter, request, "Subdomain not found")
					return true
				}
				respondJSON(responseWriter, response)
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true
		}
	}
	return false
}
