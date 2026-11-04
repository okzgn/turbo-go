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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	pathpkg "path"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"turbo/customNetHttp"
)

// ipAddr returns the IP of a "host:port" address, or of an IP alone, in its canonical form: an IPv4 also when
// it comes inside IPv6 (::ffff:1.2.3.4), and an IPv6 compressed, in lower case and without zone. A client has
// the same key in the limiter, the denied IPs and the sessions however its address is written. Anything
// else is returned without the port.
func ipAddr(address string) string {
	if addrPort, err := netip.ParseAddrPort(address); err == nil {
		return addrPort.Addr().Unmap().WithZone("").String()
	}
	if addr, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(address, "["), "]")); err == nil {
		return addr.Unmap().WithZone("").String()
	}
	if hostName, _, err := net.SplitHostPort(address); err == nil {
		return hostName
	}
	return address
}

func cutAt(input string, delimiter byte) string {
	index := strings.IndexByte(input, delimiter)
	if index != -1 {
		return input[:index]
	}
	return input
}

// cleanOldValues deletes expired entries; it takes the global lock, so callers must not hold it.
func cleanOldValues(store *map[string]int64) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	now := time.Now().Unix()
	for key, expiry := range *store {
		if now > expiry {
			delete(*store, key)
		}
	}
}

// host resolves the Host of a request against the sites: whether a site matches, the wildcard pattern that
// matched, and the subdomain and domain parts. The name is taken without its port (also "[::1]:80"), in lower
// case and without a final dot; anything but labels of 1 to 63 characters of [a-z0-9-] (not starting or ending
// with "-") is no site, so nothing else reaches the sites or the placeholders of the rewrites. An IP address is a
// single name: only the site "*" serves it, if there is one.
func host(hostHeader string) (bool, string, string, string) {
	name := requestHostName(hostHeader)
	if mayBeIPAddress(name) {
		if address, err := netip.ParseAddr(name); err == nil {
			if existWildcards("*", "") {
				return true, "*", "", address.String()
			}
			return false, "", "", ""
		}
	}
	if !hostNameValid(name) {
		return false, "", "", ""
	}
	return hostExist(name)
}

// mayBeIPAddress says whether a name could be an IP address, which is worth parsing: an IPv6 has ":" and an IPv4
// ends in a digit. Most hosts end in a letter, and parsing them on every request costs.
func mayBeIPAddress(name string) bool {
	return strings.IndexByte(name, ':') != -1 || name != "" && name[len(name)-1] >= '0' && name[len(name)-1] <= '9'
}

// requestHostName is the name of a Host header: without its port (also "[::1]:80" or "[::1]"), in lower case and
// without a final dot.
func requestHostName(hostHeader string) string {
	name := hostHeader
	if strings.HasPrefix(name, "[") {
		if end := strings.IndexByte(name, ']'); end != -1 {
			name = name[1:end]
		}
	} else if colon := strings.IndexByte(name, ':'); colon != -1 && strings.Count(name, ":") == 1 {
		name = name[:colon]
	}
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// hostNameValid reports whether a lower case name is a host name: up to 220 bytes, of labels of 1 to 63
// characters of [a-z0-9-] that don't start or end with "-" ("--" inside one, as in "xn--", is allowed).
func hostNameValid(name string) bool {
	if name == "" || len(name) > 220 {
		return false
	}
	labelStart := 0
	for i := 0; i <= len(name); i++ {
		if i < len(name) && name[i] != '.' {
			if c := name[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
			continue
		}
		label := name[labelStart:i]
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		labelStart = i + 1
	}
	return true
}

// hostExist resolves a host against the configured sites. It returns whether a site matches, the wildcard
// pattern that matched (empty without wildcard), the subdomain part and the domain part.
func hostExist(hostHeader string) (bool, string, string, string) {
	matched, prefix, wildcardHost, site := detectWildcards(hostHeader, "")

	if !matched {
		upperSubdomains, subdomain, domainName, tld := hostParts(hostHeader)
		if upperSubdomains != "" {
			upperSubdomains += "."
		}
		if domainName != "" {
			domainName += "."
		}
		return false, "", upperSubdomains + subdomain, domainName + tld
	}

	if wildcardHost != "" { // Filled when a wildcard is detected; site is then the pattern
		return true, site, prefix, wildcardHost
	}
	return true, "", prefix, site
}

func hostParts(hostHeader string) (string, string, string, string) {
	if hostHeader == "" {
		return "", "", "", ""
	}
	var part1 string
	var part2 string
	var part3 string
	var subdomainsCombined string
	dotIdx := len(hostHeader) - 1
	if hostHeader[dotIdx] == '.' { // Dot chars on the right side causes an empty string on domain name
		for {
			hostHeader = hostHeader[:dotIdx]
			dotIdx -= 1
			if dotIdx < 0 || hostHeader[dotIdx] != '.' {
				break
			}
		}
	}
	for {
		dotIdx = strings.IndexByte(hostHeader, '.')
		if dotIdx == -1 {
			break
		}
		part3 = part2
		part2 = part1
		part1 = hostHeader[:dotIdx]
		hostHeader = hostHeader[dotIdx+1:]
		if part1 == "" {
			part1 = part2
			part2 = part3
			part3 = ""
			continue
		}
		if part3 != "" {
			if subdomainsCombined != "" {
				subdomainsCombined += "."
			}
			subdomainsCombined += part3
		}
	}
	return subdomainsCombined, part2, part1, hostHeader
}

func hostDisposition(hostHeader string) bool {
	length := len(hostHeader)
	lastWildcard := strings.LastIndexByte(hostHeader, '*')
	if length < 1 || length > 220 ||
		hostHeader[0] == '.' || hostHeader[length-1] == '.' ||
		hostHeader[0] == '-' || hostHeader[length-1] == '-' ||
		strings.Contains(hostHeader, "..") ||
		strings.Contains(hostHeader, ".-") ||
		strings.Contains(hostHeader, "-.") ||
		((lastWildcard != -1) && length > 1 && ((lastWildcard != 0) || (hostHeader[lastWildcard+1] != '.'))) {
		return true
	}
	return false
}

func hostOk(hostHeader string, checkExists bool) (bool, string) {
	if hostDisposition(hostHeader) {
		return false, "Invalid address"
	}
	if !hostChars(hostHeader) {
		return false, "Invalid characters"
	}
	if checkExists {
		exists, _, _, _ := hostExist(hostHeader)
		if exists {
			return false, "Site already exists"
		}
	}
	upperSubdomains, subdomain, domainName, tld := hostParts(hostHeader)
	if len(tld) > 31 {
		return false, "Invalid TLD"
	}
	if len(domainName) > 63 {
		return false, "Invalid domain"
	}
	if len(subdomain) > 63 {
		return false, "Too long"
	}
	if len(upperSubdomains) > 63 {
		return false, "Too long"
	}
	return true, ""
}

// hostChars reports whether a host name, as the panel and turbo.config write it, has only lower case letters,
// digits, "-", "." and "*".
func hostChars(hostHeader string) bool {
	for i := 0; i < len(hostHeader); i++ {
		if c := hostHeader[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '*') {
			return false
		}
	}
	return true
}

func extChars(extension string) bool {
	if extension != "" && extension[0] == '.' {
		extension = extension[1:]
	}
	if extension == "" { // "." alone isn't an extension
		return false
	}
	if extension[0] == '-' || extension[len(extension)-1] == '.' || extension[len(extension)-1] == '-' || strings.Contains(extension, "..") || strings.Contains(extension, "--") {
		return false
	}
	for i := 0; i < len(extension); i++ {
		if !nameByte(extension[i]) {
			return false
		}
	}
	return true
}

// nameByte reports whether a byte can be in an extension or a header name: a letter, a digit, "-" or ".".
func nameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.'
}

// headerChars reports whether a header name has only letters, digits, "-" and ".".
func headerChars(headerName string) bool {
	for i := 0; i < len(headerName); i++ {
		if !nameByte(headerName[i]) {
			return false
		}
	}
	return true
}

// replaceURIChars undoes the character replacements of §2.1 of the API ("-.-" back to ";" and the rest) in one
// pass, the longest tokens first (then in alphabetical order), so the result never depends on the order of a map.
// Callers hold the global lock (charReplacements).
func replaceURIChars(uri string) string {
	tokens := make([]string, 0, len(charReplacements))
	chars := make(map[string]string, len(charReplacements))
	for char, token := range charReplacements {
		tokens = append(tokens, token)
		chars[token] = char
	}
	sort.Slice(tokens, func(i, j int) bool {
		if len(tokens[i]) != len(tokens[j]) {
			return len(tokens[i]) > len(tokens[j])
		}
		return tokens[i] < tokens[j]
	})
	pairs := make([]string, 0, 2*len(tokens))
	for _, token := range tokens {
		pairs = append(pairs, token, chars[token])
	}
	return strings.NewReplacer(pairs...).Replace(uri)
}
func changeWildcards(input ...string) string {
	replacement := "#"
	if len(input) == 2 {
		replacement = input[1]
	}
	return strings.ReplaceAll(input[0], "*", replacement)
}
func putWildcards(input ...string) string {
	replacement := "#"
	if len(input) == 2 {
		replacement = input[1]
	}
	return strings.ReplaceAll(input[0], replacement, "*")
}

// detectWildcards finds what serves hostInput: a site (subdomain empty) or, in the site named by subdomain, one of
// its subdomains. It returns whether one matched, the labels left before it (the prefix), the host a wildcard
// matched and the key that matched. A site serves the labels before it as its subdomains; a subdomain serves
// only its own name, and deeper levels only through a wildcard ("*.api", "*"): "api" doesn't serve x.api.
func detectWildcards(hostInput string, subdomain string) (bool, string, string, string) {
	if hostInput == "" && subdomain == "" {
		return false, "", "", ""
	}
	var currentSegment string
	var prefixSegments string
	for {
		dotIdx := strings.IndexByte(hostInput, '.')
		if dotIdx == -1 {
			currentSegment = hostInput
			break
		}
		currentSegment = hostInput[:dotIdx]
		hostInput = hostInput[dotIdx+1:]

		if (subdomain == "" || prefixSegments == "") && existWildcards(currentSegment+"."+hostInput, subdomain) {
			return true, prefixSegments, "", currentSegment + "." + hostInput
		}
		if existWildcards("*."+hostInput, subdomain) {
			return true, prefixSegments, currentSegment + "." + hostInput, "*." + hostInput
		}
		if prefixSegments != "" {
			prefixSegments += "." + currentSegment
		} else {
			prefixSegments += currentSegment
		}
	}

	if (subdomain == "" || prefixSegments == "") && existWildcards(hostInput, subdomain) {
		return true, prefixSegments, "", hostInput
	}
	if existWildcards("*", subdomain) {
		return true, prefixSegments, currentSegment, "*"
	}
	return false, "", "", ""
}

func existWildcards(pattern string, domain string) bool {
	if domain != "" {
		if _, exists := sitesMap[domain][pattern]; exists {
			return true
		}
		return false
	}
	if _, exists := sitesMap[pattern]; exists {
		return true
	}
	return false
}

// cleanRequestPath decodes a request path and cleans it into an absolute path without "." or ".."
// segments, which can't leave the site's directory. It rejects (false): an invalid escape, an encoded "/" or
// "\\" (which doesn't separate folders), a "..", a "\\", control characters (NUL among them) or invalid
// UTF-8, and the segments that pathSegmentAllowed rejects. Rejected paths are answered with 404.
func cleanRequestPath(raw string) (string, bool) {
	if raw == "" || raw[0] != '/' {
		return "", false
	}
	if lower := strings.ToLower(raw); strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", false
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil || strings.IndexByte(decoded, '\\') != -1 || !textAllowed(decoded, false) {
		return "", false
	}
	for _, segment := range strings.Split(decoded[1:], "/") {
		if segment == ".." || !pathSegmentAllowed(segment, runtime.GOOS == "windows") {
			return "", false
		}
	}
	clean := pathpkg.Clean(decoded)
	if strings.HasSuffix(decoded, "/") && clean != "/" {
		clean += "/"
	}
	return clean, true
}

// pathSegmentAllowed reports whether a segment of a path can name a file of a site: not ending in "." or " "
// (Windows drops them, so "x.php." would open "x.php" without its preprocessor) and, with windowsNames (always
// on Windows), without ":" (alternate data streams), a reserved device name (CON, NUL, COM1...), "~" and a
// digit (an 8.3 short name: "INDEX~1.PHT" opens "index.phtml" with another extension) nor a character Windows
// doesn't allow in a name (<, >, ", |, ?, * and control characters).
func pathSegmentAllowed(segment string, windowsNames bool) bool {
	if segment == "" || segment == "." { // Removed by cleaning
		return true
	}
	if last := segment[len(segment)-1]; last == '.' || last == ' ' {
		return false
	}
	return !windowsNames || (strings.IndexByte(segment, ':') == -1 && !windowsReservedName(segment) && !shortNameMarker(segment) && !windowsForbiddenChar(segment))
}

// windowsForbiddenChar reports whether a name has a character Windows doesn't allow in file names.
func windowsForbiddenChar(name string) bool {
	for i := 0; i < len(name); i++ {
		if c := name[i]; c < 0x20 || strings.IndexByte(`<>"|?*`, c) != -1 {
			return true
		}
	}
	return false
}

// shortNameMarker reports whether a name has "~" followed by a digit, as the 8.3 short names of Windows do.
func shortNameMarker(name string) bool {
	for i := 0; i+1 < len(name); i++ {
		if name[i] == '~' && name[i+1] >= '0' && name[i+1] <= '9' {
			return true
		}
	}
	return false
}

// windowsReservedName reports whether Windows treats a file name as a device: CON, PRN, AUX, NUL, CONIN$,
// CONOUT$, COM0-9 and LPT0-9 (also with the superscripts ¹, ² and ³), in any case, with any extension and with
// dots or spaces after the name.
func windowsReservedName(name string) bool {
	base, _, _ := strings.Cut(name, ".")
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if !strings.HasPrefix(base, "COM") && !strings.HasPrefix(base, "LPT") {
		return false
	}
	switch base[3:] {
	case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
		return true
	}
	return false
}

// textProblem says why a text value can't be saved, or "" if it can: control characters (below 0x20 and
// 0x7f; tab, CR and LF only if whitespace is true) or invalid UTF-8, which turbo.config couldn't keep as is.
func textProblem(value string, whitespace bool) string {
	for i := 0; i < len(value); i++ {
		if c := value[i]; (c < 0x20 || c == 0x7f) && !(whitespace && (c == '\t' || c == '\n' || c == '\r')) {
			return "Control characters not allowed"
		}
	}
	if !utf8.ValidString(value) {
		return "Invalid UTF-8 text"
	}
	return ""
}

func textAllowed(value string, whitespace bool) bool { return textProblem(value, whitespace) == "" }

func putSlash(path string) string {
	length := len(path)
	if length > 0 && path[length-1] != '/' {
		path += "/"
	}
	return path
}

func currentDir() string {
	workingDir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return putSlash(workingDir)
}

func reqMsg(responseWriter customNetHttp.ResponseWriter, statusCode int) {
	customNetHttp.Error(responseWriter, "", statusCode)
}

// respond writes text as the body of a response, as plain text unless the response already has a type. An error
// means the client has gone away and there is no one left to tell, so it is not handled.
func respond(responseWriter customNetHttp.ResponseWriter, text string) {
	if responseWriter.Header().Get(contentTypeHeader) == "" {
		responseWriter.Header().Set(contentTypeHeader, "text/plain; charset=utf-8")
	}
	_, _ = responseWriter.Write([]byte(text))
}

// jsonContentType is the type of the panel's JSON answers.
const jsonContentType = "application/json; charset=utf-8"

// respondJSON writes a JSON document as the body of a response.
func respondJSON(responseWriter customNetHttp.ResponseWriter, document string) {
	responseWriter.Header().Set(contentTypeHeader, jsonContentType)
	respond(responseWriter, document)
}

func badReq(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, message string) {
	responseWriter.WriteHeader(400)
	respond(responseWriter, message)
}

// ext returns the extension of a path in lower case (preprocessors and MIME types are saved in lower case: a
// ".PHP" is also run, never served).
func ext(path string) string {
	path = strings.ToLower(pathpkg.Ext(path))
	if path == "." {
		path = ""
	}
	if path != "" {
		path = path[1:]
	}
	return path
}

func serverFuncBase(path string) string {
	path = pathpkg.Base(path)
	if path == "." || path == "/" {
		path = ""
	}
	return path
}

func dir(path string) string {
	path = pathpkg.Dir(path)
	if path == "." {
		path = "/"
	}
	return path
}

func siteExists(domain string, subdomain string) bool {
	var exists bool
	if _, exists = sitesMap[domain]; !exists {
		return false
	}
	if _, exists = sitesMap[domain][subdomain]; !exists {
		return false
	}
	return true
}

// The certificate of each site with HTTPS on, and the names those certificates cover. Handshakes choose the
// certificate by SNI: a name no certificate covers, or no SNI (access by IP), is rejected, so there is
// no default certificate and tlsConfig.Certificates stays empty.
var (
	siteCertificates   = make(map[string]*tls.Certificate)         // By site key; guarded by globalMutex
	certificatesByName atomic.Pointer[map[string]*tls.Certificate] // By covered name ("*.example.com" for wildcards); read without locks
	httpsListening     atomic.Bool                                 // httpsAddr (:443) is open
)

func init() {
	tlsConfig.GetCertificate = certificateForHello
}

func certificateForHello(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cert := certificateFor(hello.ServerName); cert != nil {
		return cert, nil
	}
	return nil, errors.New("no certificate for \"" + hello.ServerName + "\"")
}

// certificateFor returns the certificate that covers a host name, exactly or with a wildcard, or nil.
func certificateFor(name string) *tls.Certificate {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	byName := certificatesByName.Load()
	if name == "" || byName == nil {
		return nil
	}
	if cert := (*byName)[name]; cert != nil {
		return cert
	}
	if _, parent, found := strings.Cut(name, "."); found {
		return (*byName)["*."+parent]
	}
	return nil
}

// setSiteCertificate loads (or, with nil, removes) the certificate of a site and publishes the names covered.
// Removing one doesn't affect the others. Callers hold the global lock.
func setSiteCertificate(siteKey string, cert *tls.Certificate) {
	if cert == nil {
		delete(siteCertificates, siteKey)
	} else {
		siteCertificates[siteKey] = cert
	}
	if !certificatePublishPaused { // While a turbo.config is applied, they are published once at the end
		publishCertificates()
	}
}

// publishCertificates publishes the names covered by the panel's certificate and by those of the sites, the
// panel's first. Callers hold the global lock.
func publishCertificates() {
	siteKeys := make([]string, 0, len(siteCertificates))
	for key := range siteCertificates {
		siteKeys = append(siteKeys, key)
	}
	sort.Strings(siteKeys) // A name covered twice always gets the same certificate
	byName := make(map[string]*tls.Certificate)
	if panelCertificate != nil {
		for _, name := range certificateNames(panelCertificate) {
			byName[name] = panelCertificate
		}
	}
	for _, key := range siteKeys {
		for _, name := range certificateNames(siteCertificates[key]) {
			if _, taken := byName[name]; !taken {
				byName[name] = siteCertificates[key]
			}
		}
	}
	certificatesByName.Store(&byName)
}

// panelCertificate is the certificate of the panel's own host, read from <sites>/turbo.panel/ (nil without one),
// and panelCertificateStamp the dates and sizes of its files when it was read. Guarded by globalMutex.
var (
	panelCertificate      *tls.Certificate
	panelCertificateStamp string
)

// panelCertificateLook is what the files of <sites>/turbo.panel/ say: the dates and sizes of fullchain.pem and
// privkey.pem and, if they changed from what was known when they were looked at, the certificate they hold.
type panelCertificateLook struct {
	stamp  string
	loaded bool
	cert   *tls.Certificate
	err    error
}

// lookAtPanelCertificate looks at the panel's certificate files, and loads them unless their stamp is
// knownStamp. It doesn't need the global lock.
func lookAtPanelCertificate(baseDir string, knownStamp string) panelCertificateLook {
	dir := baseDir + panelCertDirName + "/"
	var look panelCertificateLook
	for _, name := range []string{certFileName, keyFileName} {
		if info, err := siteDirStat(dir + name); err == nil {
			look.stamp += strconv.FormatInt(info.ModTime().UnixNano(), 10) + "/" + strconv.FormatInt(info.Size(), 10) + ";"
		}
	}
	if look.stamp != knownStamp && look.stamp != "" {
		cert, err := tls.LoadX509KeyPair(dir+certFileName, dir+keyFileName)
		look.loaded, look.cert, look.err = true, &cert, err
	}
	return look
}

// loadPanelCertificate puts in use the certificate in <sites>/turbo.panel/ (fullchain.pem and privkey.pem), read
// again only when its files change. Callers hold the global lock.
func loadPanelCertificate(baseDir string) {
	applyPanelCertificate(baseDir, lookAtPanelCertificate(baseDir, panelCertificateStamp))
}

// applyPanelCertificate puts in use what look found in <sites>/turbo.panel/, if its files changed. Callers hold
// the global lock.
func applyPanelCertificate(baseDir string, look panelCertificateLook) {
	dir := baseDir + panelCertDirName + "/"
	stamp := look.stamp
	if stamp == panelCertificateStamp {
		return
	}
	if stamp != "" && !look.loaded { // The stamp in use changed after the look: read them now
		look = lookAtPanelCertificate(baseDir, "")
	}
	panelCertificateStamp = stamp
	var cert *tls.Certificate
	if stamp != "" {
		if look.err != nil {
			slog.Warn("Panel certificate invalid or incomplete: not used", "folder", dir, "error", look.err)
		} else {
			cert = look.cert
			slog.Info("Panel certificate in use", "names", strings.Join(certificateNames(cert), ","))
		}
	} else if panelCertificate != nil {
		slog.Info("Panel certificate removed", "folder", dir)
	}
	panelCertificate = cert
	publishCertificates()
	if cert != nil && servers[0] != nil && !httpsListening.Load() {
		safeServerStart(servers[0], tlsConfig) // Opens httpsAddr (:443), also with no site on HTTPS
	}
}

// certificateNames returns the host names a certificate covers: its DNS names, or its common name without them.
func certificateNames(cert *tls.Certificate) []string {
	leaf := cert.Leaf
	if leaf == nil && len(cert.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	if leaf == nil {
		return nil
	}
	names := leaf.DNSNames
	if len(names) == 0 && leaf.Subject.CommonName != "" {
		names = []string{leaf.Subject.CommonName}
	}
	lowerNames := make([]string, len(names))
	for i, name := range names {
		lowerNames[i] = strings.ToLower(name)
	}
	return lowerNames
}

// loadSiteCertificate loads the certificate files of a site folder and puts them in use for the site.
// Callers hold the global lock.
func loadSiteCertificate(siteKey string, siteDir string) error {
	cert, err := diskCertificate(siteDir)
	if err != nil {
		return err
	}
	setSiteCertificate(siteKey, cert)
	return nil
}

// diskLook is what the disk said, looked at before taking the global lock, about the paths the validators look
// at (the sites directory of M, the certificates of C and S, the executables of the preprocessors): under the
// lock they take it from here, so a slow or network disk doesn't stop every request while a reload or a panel
// action holds the lock. What wasn't looked at beforehand is looked at then.
type diskLook struct {
	stats        map[string]lookedStat
	certificates map[string]lookedCertificate // By site folder
}

type lookedStat struct {
	info os.FileInfo
	err  error
}

type lookedCertificate struct {
	cert *tls.Certificate
	err  error
}

// lookedDisk is the look of whoever holds the global lock (withDiskLook), or nil. Guarded by the global lock.
var lookedDisk *diskLook

func newDiskLook() *diskLook {
	return &diskLook{stats: map[string]lookedStat{}, certificates: map[string]lookedCertificate{}}
}

// stat looks at a path. Callers don't hold the global lock.
func (look *diskLook) stat(path string) {
	if _, done := look.stats[path]; !done {
		info, err := siteDirStat(path)
		look.stats[path] = lookedStat{info, err}
	}
}

// certificate looks at a site folder's certificate files and loads them. Callers don't hold the global lock.
func (look *diskLook) certificate(siteDir string) {
	if _, done := look.certificates[siteDir]; !done {
		cert, err := tls.LoadX509KeyPair(siteDir+certFileName, siteDir+keyFileName)
		look.certificates[siteDir] = lookedCertificate{&cert, err}
	}
}

// siteFiles looks at the certificate files of a site folder, and loads them if withCertificate.
func (look *diskLook) siteFiles(siteDir string, withCertificate bool) {
	look.stat(siteDir + certFileName)
	look.stat(siteDir + keyFileName)
	if withCertificate {
		look.certificate(siteDir)
	}
}

// diskStat is os.Stat for the validators: what the look of the lock's holder says, if it looked at the path.
// Callers hold the global lock.
func diskStat(path string) (os.FileInfo, error) {
	if lookedDisk != nil {
		if looked, done := lookedDisk.stats[path]; done {
			return looked.info, looked.err
		}
	}
	return siteDirStat(path)
}

// diskCertificate loads a site folder's certificate files, or takes them from the look of the lock's holder.
// Callers hold the global lock.
func diskCertificate(siteDir string) (*tls.Certificate, error) {
	if lookedDisk != nil {
		if looked, done := lookedDisk.certificates[siteDir]; done {
			return looked.cert, looked.err
		}
	}
	cert, err := tls.LoadX509KeyPair(siteDir+certFileName, siteDir+keyFileName)
	return &cert, err
}

// withDiskLook runs f holding the global lock, with look for the validators it calls.
func withDiskLook(look *diskLook, f func()) {
	withGlobalLock(func() {
		lookedDisk = look
		defer func() { lookedDisk = nil }()
		f()
	})
}

// siteFolder is the folder of a site or subdomain in the sites directory, as the validators of C and S name it.
func siteFolder(domain string, subdomain string) string {
	if subdomain != "" {
		return changeWildcards(domain) + "/" + changeWildcards(subdomain) + "/"
	}
	return changeWildcards(domain) + "/"
}

// certificateRenewBefore is how long before a certificate expires that Turbo renews it, and certbotFilesMaxAge
// how old the files in Certbot's archive may be to be taken as the certificate it just issued.
const (
	certificateRenewBefore = 30 * 24 * time.Hour
	certbotFilesMaxAge     = 60 * time.Hour
)

// renewCertificates asks Certbot, one site at a time, to renew the certificates issued by Turbo (the site has
// an e-mail and a folder in turbo.certificates) that expire in less than 30 days. It runs daily.
func renewCertificates() {
	type renewal struct{ siteKey, certDir, siteDir, lineageDir string }
	var candidates, due []renewal
	certificatesDir := sitesDir.Get() + putSlash(certificatesDirName)
	panelDir := sitesDir.Get() + panelCertDirName + "/"
	panelCandidate := false
	withReadLock(func() { // The sites with an e-mail; the disk is looked at after, without the lock
		for domain := range sitesMap {
			for subdomain := range sitesMap[domain] {
				siteKey, siteDir := domain, sitesDir.Get()+changeWildcards(domain)+"/"
				lineageDir := ""
				if subdomain != "" {
					siteKey = subdomain + "." + domain
					siteDir += changeWildcards(subdomain) + "/"
					lineageDir = certificatesDir + changeWildcards(domain) + "/archive/" + siteKey
				}
				if email, _ := siteSSLConfig[siteKey]["E"].(string); email != "" {
					candidates = append(candidates, renewal{siteKey, certificatesDir + changeWildcards(siteKey), siteDir, lineageDir}) // certDir as in the "C" validator
				}
			}
		}
		panelCandidate = panelCertEmail != "" && len(panelOwnHosts()) > 0
	})
	for _, site := range candidates {
		// Issued by Turbo: its own folder, or (subdomains issued before each site had one) its lineage in the
		// folder of the domain.
		if !dirExists(site.certDir) && (site.lineageDir == "" || !dirExists(site.lineageDir)) {
			continue
		}
		if expiry, err := certificateExpiry(site.siteDir + certFileName); err == nil && time.Until(expiry) < certificateRenewBefore {
			due = append(due, site)
		}
	}
	panelDue := false
	if panelCandidate && dirExists(certificatesDir+panelCertDirName) {
		if expiry, err := certificateExpiry(panelDir + certFileName); err == nil && time.Until(expiry) < certificateRenewBefore {
			panelDue = true
		}
	}
	for _, site := range due {
		slog.Info("Renewing the certificate", "site", site.siteKey)
		withGlobalLock(func() { obtainCertificate(site.siteKey, site.certDir, site.siteDir) })
	}
	if panelDue {
		slog.Info("Renewing the panel certificate")
		withGlobalLock(func() { obtainPanelCertificate(certificatesDir+panelCertDirName, panelDir) })
	}
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// certificateExpiry returns when the first certificate of a PEM file expires.
func certificateExpiry(path string) (time.Time, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- certificate file of a site, path under the sites directory chosen by the administrator (TURBO_DIR or M)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, errors.New("no PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

// servingSite returns the key of the site that serves hostname, as resolveRequest and serve find it (aliases and
// wildcards included), or "" if no site does. Callers hold the global lock.
func servingSite(hostname string) string {
	valid, wildcardDomain, subdomain, domain := host(hostname)
	fullHost := domain
	if subdomain != "" {
		fullHost = subdomain + "." + domain
	}
	if target, isAlias := domainAliases[fullHost]; isAlias {
		valid, wildcardDomain, subdomain, domain = host(target)
	}
	if !valid {
		return ""
	}
	if wildcardDomain != "" {
		domain = wildcardDomain
	}
	matched, _, _, subdomainKey := detectWildcards(subdomain, domain)
	if !matched {
		return ""
	}
	if subdomain == "" {
		return domain
	}
	return subdomainKey + "." + domain
}

// hostWithoutPort returns the host of a request without its port.
func hostWithoutPort(request *customNetHttp.Request) string {
	if hostname, _, err := net.SplitHostPort(request.Host); err == nil {
		return hostname
	}
	return request.Host
}

// httpsRedirect sends an HTTP request to HTTPS, on the host it asked for, when the site has HTTPS on and a
// certificate covers that host. An alias without a certificate keeps being served by HTTP under its own name.
// Callers hold the global read lock.
func httpsRedirect(siteKey string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) bool {
	hostname := hostWithoutPort(request)
	if !httpsEnabled(siteKey) || certificateFor(hostname) == nil || !httpsListening.Load() { // Never to an HTTPS that isn't open
		return false
	}
	customNetHttp.Redirect(responseWriter, request, "https://"+hostname+httpsPortSuffix()+request.RequestURI, 301)
	return true
}

// The panel's own certificate: the e-mail (saved as "PCE") and the DNS adapter ("PCA") that Certbot uses for it,
// and the result of the last attempt (true, false or why it failed). Guarded by globalMutex.
var (
	panelCertEmail   string
	panelCertAdapter string
	panelCertStatus  interface{} = false
)

// loadPanelCertSettings takes PCE and PCA from "." of turbo.config; one that can't be used is dropped with a
// warning.
func loadPanelCertSettings(settings map[string]interface{}) {
	panelCertEmail, panelCertAdapter = "", ""
	if value, present := settings["PCE"]; present {
		if email, isString := value.(string); !isString || certbotEmailProblem(email) != "" {
			slog.Warn("turbo.config setting discarded: invalid panel certificate e-mail", "key", "PCE")
		} else {
			panelCertEmail = email
		}
	}
	if value, present := settings["PCA"]; present {
		if adapter, isString := value.(string); !isString || !validCertbotAdapter.MatchString(adapter) {
			slog.Warn("turbo.config setting discarded: invalid panel certificate adapter", "key", "PCA")
		} else {
			panelCertAdapter = adapter
		}
	}
}

// panelCertSettingsJSON is PCE and PCA for "." of turbo.config and, for the panel (withStatus), "PCC": true with a
// certificate in use, "WAIT" while Certbot issues it, or else false. Callers hold the global lock.
func panelCertSettingsJSON(withStatus bool) string {
	settings := ""
	if panelCertEmail != "" {
		settings += ",\"PCE\":" + jsonString(panelCertEmail)
	}
	if panelCertAdapter != "" {
		settings += ",\"PCA\":" + jsonString(panelCertAdapter)
	}
	if withStatus {
		status := "false"
		if currentCertDomain == panelCertDirName {
			status = "\"WAIT\""
		} else if panelCertificate != nil {
			status = "true"
		}
		settings += ",\"PCC\":" + status
	}
	return settings
}

// panelOwnHosts returns, sorted, the host names in PA (not the IP addresses): those a certificate can cover.
func panelOwnHosts() []string {
	var hosts []string
	for host := range panelAccess.Load().hosts {
		if net.ParseIP(host) == nil {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return hosts
}

// panelCertificateAction is cfgPC: a="1" issues with Certbot a certificate for the hosts of PA, which goes to
// turbo.panel/, and a="0" deletes it; z sets the e-mail first and y, if sent (setAdapter), the DNS adapter, where
// an empty one goes back to webroot. While Certbot runs, and when another certificate is being issued, it
// answers WAIT (202). The error of the last attempt is answered once. Callers hold the global lock.
func panelCertificateAction(action string, email string, adapter string, setAdapter bool) (bool, string) {
	if action != "0" && action != "1" {
		return false, "Invalid value"
	}
	if email != "" {
		if problem := certbotEmailProblem(email); problem != "" {
			return false, problem
		}
		panelCertEmail = email
	}
	if setAdapter {
		if adapter != "" && !validCertbotAdapter.MatchString(adapter) {
			return false, "Invalid adapter: dns-<provider> is accepted"
		}
		panelCertAdapter = adapter
	}
	panelDir := sitesDir.Get() + panelCertDirName + "/"
	if action == "0" {
		removedCert := os.Remove(panelDir+certFileName) == nil
		removedKey := os.Remove(panelDir+keyFileName) == nil
		panelCertStatus = false
		panelCertificate, panelCertificateStamp = nil, ""
		publishCertificates()
		if !removedCert && !removedKey {
			return false, "No panel certificate"
		}
		return true, "Panel certificate deleted"
	}
	if currentCertDomain == panelCertDirName {
		return false, "{\"message\":\"Please wait, certificate being processed\",\"status\":\"WAIT\"}"
	}
	hosts := panelOwnHosts()
	if panelCertificate != nil && panelCertificateCovers(hosts) {
		if expiry, err := certificateExpiry(panelDir + certFileName); err == nil && time.Until(expiry) > certificateRenewBefore {
			panelCertStatus = true
			return true, "Panel certificate active"
		}
	}
	if message, failed := panelCertStatus.(string); failed {
		panelCertStatus = false
		return false, message
	}
	if len(hosts) == 0 {
		return false, "PA has no host of its own for the panel: add one first"
	}
	if panelCertEmail == "" {
		return false, "E-mail required to create the certificate"
	}
	certificatesDir := sitesDir.Get() + putSlash(certificatesDirName)
	if os.MkdirAll(certificatesDir, 0700) != nil || os.MkdirAll(panelDir+acmeWebrootDirName, 0700) != nil {
		return false, "Error creating the certificates directory"
	}
	panelCertStatus = false
	obtainPanelCertificate(certificatesDir+panelCertDirName, panelDir)
	if currentCertDomain != panelCertDirName {
		return false, "{\"message\":\"Please wait, certificate busy on " + currentCertDomain + "\",\"status\":\"WAIT\"}"
	}
	return false, "{\"message\":\"Please wait, certificate in process\",\"status\":\"WAIT\"}"
}

// panelCertificateCovers reports whether the panel's certificate covers every one of hosts. Callers hold the
// global lock.
func panelCertificateCovers(hosts []string) bool {
	names := make(map[string]bool)
	for _, name := range certificateNames(panelCertificate) {
		names[name] = true
	}
	for _, host := range hosts {
		if _, parent, _ := strings.Cut(host, "."); !names[host] && !names["*."+parent] {
			return false
		}
	}
	return true
}

// panelACMEChallenge serves, on a host of PA, the ACME challenges that Certbot leaves in turbo.panel/webroot/
// while it issues the panel's certificate: only /.well-known/acme-challenge/<token>, only regular files, opened
// through os.Root. Nothing else of turbo.panel/ is served. It reports whether it answered.
func panelACMEChallenge(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) bool {
	const challengePrefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(request.RequestURI, challengePrefix) || !panelAccess.Load().hosts[requestHostName(request.Host)] {
		return false
	}
	token := cutAt(request.RequestURI[len(challengePrefix):], '?')
	if !acmeToken.MatchString(token) {
		reqMsg(responseWriter, 404)
		return true
	}
	root, err := os.OpenRoot(sitesDir.Get() + panelCertDirName + "/" + acmeWebrootDirName + challengePrefix)
	if err != nil {
		reqMsg(responseWriter, 404)
		return true
	}
	defer root.Close()
	file, err := root.Open(token)
	if err != nil {
		reqMsg(responseWriter, 404)
		return true
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		reqMsg(responseWriter, 404)
		return true
	}
	responseWriter.Header().Set(contentTypeHeader, "text/plain")
	_, _ = io.Copy(responseWriter, file)
	return true
}

// acmeToken is an ACME http-01 token: base64url (RFC 8555).
var acmeToken = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

// certbotJob is what a Certbot attempt needs: the names to cover, the e-mail, the DNS adapter or else the webroot
// folder, Certbot's own folder (emptied first) and the folder where fullchain.pem and privkey.pem end up.
type certbotJob struct {
	names   []string
	email   string
	adapter string
	webroot string
	certDir string
	destDir string
}

// obtainCertificate starts a Certbot attempt for the site domain. Callers hold the global lock.
func obtainCertificate(domain string, certDir string, siteDir string) {
	startCertbot(domain, func() (certbotJob, bool) {
		if _, siteFound := siteSSLConfig[domain]; !siteFound {
			slog.Warn("Certificate issuance interrupted: the site was deleted", "site", domain)
			return certbotJob{}, false
		}
		adapter, _ := siteSSLConfig[domain]["A"].(string)
		email, _ := siteSSLConfig[domain]["E"].(string)
		return certbotJob{names: []string{domain}, email: email, adapter: adapter, webroot: siteDir + publicDirName, certDir: certDir, destDir: siteDir}, true
	}, func(status interface{}) {
		if _, siteFound := siteSSLConfig[domain]; siteFound {
			siteSSLConfig[domain]["C"] = status
		}
		if status != true {
			return
		}
		if httpsEnabled(domain) { // A renewed certificate replaces the one in use, without restarting
			if err := loadSiteCertificate(domain, siteDir); err != nil {
				slog.Error("Can't load the certificate", "site", domain, "error", err)
			}
		}
		slog.Info("Certificate issued", "site", domain)
	})
}

// obtainPanelCertificate starts a Certbot attempt for the hosts of PA, whose certificate goes to turbo.panel/.
// Callers hold the global lock.
func obtainPanelCertificate(certDir string, panelDir string) {
	startCertbot(panelCertDirName, func() (certbotJob, bool) {
		hosts := panelOwnHosts()
		if len(hosts) == 0 {
			panelCertStatus = "PA no longer has hosts of its own for the panel"
			return certbotJob{}, false
		}
		return certbotJob{names: hosts, email: panelCertEmail, adapter: panelCertAdapter, webroot: panelDir + acmeWebrootDirName, certDir: certDir, destDir: panelDir}, true
	}, func(status interface{}) {
		panelCertStatus = status
		if status != true {
			return
		}
		panelCertificateStamp = "" // Read the new files now
		loadPanelCertificate(sitesDir.Get())
		slog.Info("Panel certificate issued", "hosts", strings.Join(panelOwnHosts(), ","))
	})
}

// startCertbot starts a Certbot attempt for key (a site, or the panel) if none is running. prepare reads, with
// the lock, what the attempt needs (false: it is no longer wanted), and finish records the result, also with the
// lock: true, or why it failed. While another key's attempt runs, there is a single retry after certRetryDelay,
// whose delay doesn't grow. Callers hold the global lock.
func startCertbot(key string, prepare func() (certbotJob, bool), finish func(status interface{})) {
	if currentCertDomain == "" {
		currentCertDomain = key
		go func() {
			timeoutCtx, cancelFn := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancelFn()
			var job certbotJob
			var wanted bool
			withGlobalLock(func() {
				if job, wanted = prepare(); !wanted {
					currentCertDomain = ""
				}
			})
			if !wanted {
				return
			}
			status := runCertbot(timeoutCtx, job)
			withGlobalLock(func() {
				currentCertDomain = ""
				finish(status)
			})
		}()
		return
	}
	if currentCertDomain == key || certPending[key] {
		return
	}
	certPending[key] = true
	time.AfterFunc(certRetryDelay, func() {
		withGlobalLock(func() {
			delete(certPending, key)
			startCertbot(key, prepare, finish)
		})
	})
}

// runCertbot runs Certbot for job and moves the new certificate to job.destDir. It returns true, or why it
// failed (Certbot's output when Certbot fails).
func runCertbot(timeoutCtx context.Context, job certbotJob) interface{} {
	if _, err := exec.CommandContext(timeoutCtx, "certbot", "--version").CombinedOutput(); err != nil {
		return "Certbot is not installed"
	}
	if _, err := os.ReadDir(job.certDir); err == nil && os.RemoveAll(job.certDir) != nil {
		return "Error emptying the previous certificate directory"
	}
	// Names checked by hostOk (sites) or parsePanelAccess (PA), the e-mail by certbotEmailProblem and the
	// adapter by validCertbotAdapter.
	args := []string{"certonly"}
	for _, name := range job.names {
		args = append(args, "-d", name)
	}
	if job.adapter != "" { // For wildcards, or --dns-route53
		args = append(args, "--"+job.adapter)
	} else {
		args = append(args, "--webroot", "--webroot-path", job.webroot)
	}
	args = append(args,
		"-n", // Not interactive
		"--agree-tos",
		"-m", job.email, // Email for expiring notifications
		"--no-eff-email",
		"--config-dir", job.certDir,
		"--work-dir", job.certDir+"/work",
		"--logs-dir", job.certDir+"/logs")
	cmdOutput, err := exec.CommandContext(timeoutCtx, "certbot", args...).CombinedOutput() // #nosec G204 -- fixed program; arguments checked as said above
	if err != nil {
		return string(cmdOutput)
	}

	archiveDir := job.certDir + "/archive/"
	archiveEntries, err := os.ReadDir(archiveDir)
	if err != nil {
		return "Certificate directory unreadable when obtaining it"
	}
	var fullchainPath string
	var privkeyPath string
	for _, archiveEntry := range archiveEntries {
		entryDir := archiveDir + archiveEntry.Name() + "/"
		certSubEntries, err := os.ReadDir(entryDir)
		if err != nil {
			continue
		}
		for _, certEntry := range certSubEntries {
			fileName := certEntry.Name()
			fileInfo, err := os.Stat(entryDir + fileName)
			if err != nil {
				continue
			}
			if len(fileName) > 10 && time.Since(fileInfo.ModTime()) < certbotFilesMaxAge {
				switch fileName[:4] {
				case "full":
					fullchainPath = entryDir + fileName
				case "priv":
					privkeyPath = entryDir + fileName
				}
			}
		}
		break // Because is only one dir
	}
	if fullchainPath == "" || privkeyPath == "" {
		return "Certificate files missing when obtaining it"
	}
	if os.Rename(fullchainPath, job.destDir+certFileName) != nil {
		return "'Fullchain' can't be moved when obtaining it"
	}
	if os.Rename(privkeyPath, job.destDir+keyFileName) != nil {
		return "'Privkey' can't be moved when obtaining it"
	}
	return true
}
