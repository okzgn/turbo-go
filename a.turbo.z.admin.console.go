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
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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
// subdomain served here, an uploaded page), so actions authenticated with it need this (CSRF).
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
	_, isSessionValid := signedInTokens[clientIP+sessionToken]
	globalMutex.RUnlock()

	responseWriter.Header().Set("Access-Control-Allow-Origin", "default://home")
	responseWriter.Header().Set("Access-Control-Allow-Headers", "ok") // This is to accept ok header from default://home

	switch actionPath {
	case "signout":
		if isSessionValid {
			globalMutex.Lock()
			delete(signedInTokens, clientIP+sessionToken)
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
			signedInTokens[clientIP+sessionToken] = time.Now().Unix() + 600
			globalMutex.Unlock()

			if consoleActionsApi(request.RequestURI, responseWriter, request) {
				return true
			}

			consoleFiles(adminInsideName, request.RequestURI, responseWriter, request)
			return true
		}
		consoleHtmlRedir("/"+adminPathPrefix+":", responseWriter, request)
		return true
	default:
		request.ParseMultipartForm(1024)
		_, isSessionValid := request.Form["u"]
		_, hasPassword := request.Form["p"]
		if isSessionValid && hasPassword {
			userMatches := subtle.ConstantTimeCompare([]byte(request.Form["u"][0]), []byte(panelUser.Get())) == 1
			if passwordMatches(request.Form["p"][0]) && userMatches {
				now := time.Now().Unix()
				token := newSessionToken()

				globalMutex.Lock()
				signedInTokens[clientIP+token] = now + 600
				globalMutex.Unlock()
				// The browser panel uses the cookie; API clients send the token in the "ok" header.
				responseWriter.Header().Add("Set-Cookie", sessionCookie(token, false, request))
				responseWriter.Write([]byte(sessionHeaderName + token))
			} else {
				responseWriter.WriteHeader(403)
			}
			return true
		}
	}
	return false
}

func consoleHtmlRedir(redirectURL string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	responseWriter.Header().Set(contentTypeHeader, "text/html; charset=UTF-8")
	responseWriter.Write([]byte("<meta http-equiv='refresh' content='0; URL=" + redirectURL + "'/>"))
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
// (matched with the client's IP). "" or "*" means no restriction. Either kind of entry is enough, and the Host
// header is chosen by the client: host names only keep the panel off other domains, while networks are what
// limits who can reach it.
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

// panelAllowed reports whether the panel answers this request under "PA".
func panelAllowed(request *customNetHttp.Request) bool {
	list := panelAccess.Load()
	if list.setting == "" {
		return true
	}
	if list.hosts[strings.ToLower(requestHostname(request))] {
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
	key, _ := pbkdf2.Key(sha256.New, password, salt, passwordHashIterations, 32)
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
	hash := hashPassword(password)
	panelPasswordHash.Set(hash)
	verifiedPassword.Store(&passwordCheck{hash, sha256.Sum256([]byte(hash + "\x00" + password))})
}

// passwordMatches reports whether password is the panel's (or internalAuth), comparing in constant time.
func passwordMatches(password string) bool {
	if subtle.ConstantTimeCompare([]byte(password), []byte(internalAuth)) == 1 {
		return true
	}
	hash := panelPasswordHash.Get()
	sum := sha256.Sum256([]byte(hash + "\x00" + password))
	if last := verifiedPassword.Load(); last != nil && last.hash == hash && subtle.ConstantTimeCompare(last.sum[:], sum[:]) == 1 {
		return true
	}
	iterations, salt, key, ok := parsePasswordHash(hash)
	if !ok {
		return false
	}
	passwordHashSlots <- struct{}{}
	derived, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(key))
	<-passwordHashSlots
	if err != nil || subtle.ConstantTimeCompare(derived, key) != 1 {
		return false
	}
	verifiedPassword.Store(&passwordCheck{hash, sum})
	return true
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
		if segment == "" || segment == "." || segment == ".." {
			return "", false
		}
	}
	return name, true
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
	switch apiPath[:3] {
	case "set":
		apiPath = apiPath[3:]
		if _, handlerExists := defaultSettingValidators["."][apiPath]; handlerExists {
			request.ParseForm()
			if _, paramExists := request.Form["a"]; paramExists {
				var argumentList []string
				argumentList = append(argumentList, replaceURIChars(request.Form["a"][0]))
				// Every setting needs the current password (b). It is checked here, before taking the lock,
				// as a wrong one costs a PBKDF2; the validator then gets internalAuth.
				if _, paramExists = request.Form["b"]; !paramExists {
					badReq(responseWriter, request, msgMissingData)
					return true
				}
				if !passwordMatches(replaceURIChars(request.Form["b"][0])) {
					badReq(responseWriter, request, "Contraseña actual incorrecta")
					return true
				}
				argumentList = append(argumentList, internalAuth)

				var resultMsg string
				resultBool, resultMsg := lockedCheck(func() (bool, string) { return defaultSettingValidators["."][apiPath](argumentList...) })
				if !resultBool {
					badReq(responseWriter, request, resultMsg)
				} else {
					if _, handlerExists = serverRestartRequiredSettings[apiPath]; handlerExists { // serverRestartRequiredSettings: List of settings that use restartServers
						responseWriter.Write([]byte(resultMsg))
						//time.AfterFunc(50*time.Millisecond, func() {
						resetSettings()
						updateSettings(true)
						//})
					} else {
						responseWriter.Write([]byte(resultMsg))
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
			request.ParseForm()
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
					responseWriter.Write([]byte(resultMsg))
				}
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "Index", "Alias":
			request.ParseForm()
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
					return subdomainContentCheckers[resultMsg](true, argumentValues, false, request.Form["s"][0], request.Form["d"][0])
				})
				if !resultBool {
					badReq(responseWriter, request, resultMsg)
				} else {
					responseWriter.Write([]byte(resultMsg))
				}
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "Subdomain":
			request.ParseForm()
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			if sourceParamExists && destinationParamExists {
				if _, handlerExists := sitesMap[request.Form["s"][0]]; handlerExists {
					resultBool, resultMsg := hostOk(request.Form["d"][0]+"."+changeWildcards(request.Form["s"][0], "x"), false) // Because wildcard is only accepted on begining
					if resultBool {
						globalMutex.RLock()
						_e := siteExists(request.Form["s"][0], request.Form["d"][0])
						globalMutex.RUnlock()
						if _e {
							badReq(responseWriter, request, "Subdominio existente")
							return true
						}

						/* Domains map keys coincidence detection */
						resultBool, _, _, resultMsg = detectWildcards(request.Form["d"][0]+"."+request.Form["s"][0], "")
						if resultBool && resultMsg != request.Form["s"][0] {
							badReq(responseWriter, request, "Coincidencia con sitio: "+resultMsg)
							return true
						}

						resultMsg = sitesDir.Get() + changeWildcards(request.Form["s"][0]) + "/" + changeWildcards(request.Form["d"][0]) + "/" + publicDirName + "/"
						if os.MkdirAll(resultMsg, 0755) != nil { // #nosec G301 -- public web content of a site, served by Turbo
							badReq(responseWriter, request, "Error al crear")
							return true
						}
						constructSite(request.Form["s"][0], request.Form["d"][0])
						responseWriter.Write([]byte("Subdominio agregado"))
					} else {
						badReq(responseWriter, request, resultMsg)
					}
				} else {
					badReq(responseWriter, request, "Sitio inexistente")
				}
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "Site":
			request.ParseForm()
			_, sourceParamExists := request.Form["s"]
			if sourceParamExists {
				globalMutex.RLock()
				_e := siteExists(request.Form["s"][0], "")
				globalMutex.RUnlock()
				if _e {
					badReq(responseWriter, request, "Sitio existente.")
					return true
				}
				var resultBool bool
				var resultMsg string
				if resultBool, resultMsg = hostOk(request.Form["s"][0], false); !resultBool {
					badReq(responseWriter, request, resultMsg)
					return true
				}

				/* Subdomains map keys coincidence detection */
				var matchedSite string
				resultBool, matchedSite, _, resultMsg = detectWildcards(request.Form["s"][0], "")
				if resultBool {
					resultBool, _, _, matchedSite = detectWildcards(matchedSite, resultMsg)
					if resultBool {
						badReq(responseWriter, request, "Coincidencia con sitio: "+matchedSite+"."+resultMsg)
						return true
					}
				}

				resultMsg = sitesDir.Get() + changeWildcards(request.Form["s"][0]) + "/" + publicDirName + "/"
				if os.MkdirAll(resultMsg, 0755) != nil { // #nosec G301 -- public web content of a site, served by Turbo
					badReq(responseWriter, request, "Error al crear")
					return true
				}
				constructSite(request.Form["s"][0], "")
				responseWriter.Write([]byte("Sitio agregado"))
				return true
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "Denied", "HttpCodeResponse", "CharsReplace":
			request.ParseForm()
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
				responseWriter.Write([]byte(resultMsg))
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
			request.ParseForm()
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
					responseWriter.Write([]byte(resultMsg))
				}
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "Site":
			request.ParseForm()
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
				responseWriter.Write([]byte(resultMsg + " borrado"))
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "Denied", "HttpCodeResponse", "CharsReplace":
			request.ParseForm()
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
				responseWriter.Write([]byte(resultMsg))
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
			request.ParseForm()
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

				if !resultBool {
					badReq(responseWriter, request, resultMsg)
					return true
				}
				responseWriter.Write([]byte(resultMsg))
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
				srcFile.Close()
				if readErr != nil {
					discarded = append(discarded, name)
				}
			}
			if len(discarded) > 0 {
				responseWriter.Write([]byte("Datos volcados. Descartados: " + strings.Join(discarded, ", ")))
			} else {
				responseWriter.Write([]byte("Datos volcados"))
			}
			return true

		case "sites":
			globalMutex.RLock()
			responseWriter.Write([]byte(createDefaultConfig(false, true, false)))
			globalMutex.RUnlock()
			return true

		case "subdomains":

			request.ParseForm()
			_, paramExists := request.Form["s"]
			if paramExists {
				globalMutex.RLock()
				_e := siteExists(request.Form["s"][0], "")
				globalMutex.RUnlock()

				if !_e {
					badReq(responseWriter, request, "Sitio inexistente")
					return true
				}

				globalMutex.RLock()
				responseWriter.Write([]byte(createSubdomainsList(false, request.Form["s"][0])))
				globalMutex.RUnlock()
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true

		case "subdomainData":
			request.ParseForm()
			_, sourceParamExists := request.Form["s"]
			_, destinationParamExists := request.Form["d"]
			if sourceParamExists && destinationParamExists {
				globalMutex.RLock()
				_e := siteExists(request.Form["s"][0], request.Form["d"][0])
				globalMutex.RUnlock()

				if !_e {
					badReq(responseWriter, request, "Subdominio inexistente")
					return true
				}

				globalMutex.RLock()
				responseWriter.Write([]byte(createSubdomainData(request.Form["s"][0], request.Form["d"][0])))
				globalMutex.RUnlock()
			} else {
				badReq(responseWriter, request, msgMissingData)
			}
			return true
		}
	}
	return false
}
