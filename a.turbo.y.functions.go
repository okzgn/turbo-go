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
	"log/slog"
	"net"
	"os"
	"os/exec"
	pathpkg "path"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"turbo/customNetHttp"
)

func ipAddr(address string) string {
	if address[0] == '[' {
		return cutAt(address[1:], ']')
	}
	if strings.IndexByte(address, '.') != -1 {
		return cutAt(address, ':')
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

func host(hostHeader string) (bool, string, string, string) {
	/*if e[0] == '[' {
		//e = cutAt(e[1:], ']')
		//e = strings.ReplaceAll(e, ":", "_")
		return true, "", "", e
	}*/
	hostHeader = cutAt(hostHeader, ':')
	if hostDisposition(hostHeader) {
		return false, "", "", ""
	}
	return hostExist(hostHeader)
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
		strings.Contains(hostHeader, "--") ||
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
		return false, "Dirección incorrecta"
	}
	if !hostChars(hostHeader) {
		return false, "Caracteres incorrectos"
	}
	if checkExists {
		exists, _, _, _ := hostExist(hostHeader)
		if exists {
			return false, "Sitio existente"
		}
	}
	upperSubdomains, subdomain, domainName, tld := hostParts(hostHeader)
	if len(tld) > 31 {
		return false, "TLD incorrecto"
	}
	if len(domainName) > 63 {
		return false, "Dominio incorrecto"
	} // Initially unsupported 1 digit domain names: (subdomain != "" && len(domainName) == 1) ||
	if len(subdomain) > 63 {
		return false, "Longitud excesiva"
	}
	if len(upperSubdomains) > 63 {
		return false, "Longitud excesiva"
	}
	return true, ""
}

func hostChars(hostHeader string) bool {
	for index := range hostHeader {
		if (hostHeader[index] < 97 || hostHeader[index] > 122) && (hostHeader[index] < 45 || hostHeader[index] > 46) && (hostHeader[index] < 48 || hostHeader[index] > 57) && hostHeader[index] != 42 {
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
	for index := range extension {
		if (extension[index] < 97 || extension[index] > 122) && (extension[index] < 45 || extension[index] > 46) && (extension[index] < 48 || extension[index] > 57) && (extension[index] < 65 || extension[index] > 90) {
			return false
		}
	}
	return true
}

func headerChars(headerName string) bool {
	for index := range headerName {
		if (headerName[index] < 97 || headerName[index] > 122) && (headerName[index] < 45 || headerName[index] > 46) && (headerName[index] < 48 || headerName[index] > 57) && (headerName[index] < 65 || headerName[index] > 90) {
			return false
		}
	}
	return true
}

func replaceURIChars(uri string) string {
	for char, replacement := range charReplacements {
		uri = strings.ReplaceAll(uri, replacement, char)
	}
	return uri
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

		if existWildcards(currentSegment+"."+hostInput, subdomain) {
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

	if existWildcards(hostInput, subdomain) {
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

func changeChars(reverse bool, input string, pairs []string) string {
	totalLen := len(pairs)
	halfLen := totalLen / 2

	step := 1
	currIdx := 0
	stopIdx := halfLen
	offset := halfLen
	if !reverse {
		step = -1
		currIdx = totalLen - 1
		stopIdx = halfLen - 1
		offset = halfLen * step
	}
	for {
		if currIdx == stopIdx {
			break
		}
		input = strings.ReplaceAll(input, pairs[currIdx], pairs[currIdx+offset])
		currIdx += step
	}
	return input
}

func putSlash(path string) string {
	length := len(path)
	if length > 0 && path[length-1] != '/' {
		path += "/"
	}
	return path
}

func fileExists(path string) bool {
	info, err := os.Stat(path) // #nosec G703 -- helper: callers pass paths under the sites directory or already validated by the panel
	if err != nil {            // Doesn't exist or the path isn't valid on this system
		return false
	}
	return !info.IsDir()
}

func currentDir() string {
	workingDir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return putSlash(workingDir)
}

func reqMsg(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, statusCode int) {
	customNetHttp.Error(responseWriter, "", statusCode)
}

func badReq(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, message string) {
	responseWriter.WriteHeader(400)
	responseWriter.Write([]byte(message))
}

func ext(path string) string {
	path = pathpkg.Ext(path)
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
// certificate by SNI (DP11): a name no certificate covers, or no SNI (access by IP), is rejected, so there is
// no default certificate and tlsConfig.Certificates stays empty.
var (
	siteCertificates   = make(map[string]*tls.Certificate)         // By site key; guarded by globalMutex
	certificatesByName atomic.Pointer[map[string]*tls.Certificate] // By covered name ("*.example.com" for wildcards); read without locks
	httpsListening     bool                                        // httpsAddr (:443) is open; guarded by globalMutex
)

func init() {
	tlsConfig.GetCertificate = certificateForHello
}

func certificateForHello(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cert := certificateFor(hello.ServerName); cert != nil {
		return cert, nil
	}
	return nil, errors.New("sin certificado para \"" + hello.ServerName + "\"")
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
	siteKeys := make([]string, 0, len(siteCertificates))
	for key := range siteCertificates {
		siteKeys = append(siteKeys, key)
	}
	sort.Strings(siteKeys) // A name covered twice always gets the same certificate
	byName := make(map[string]*tls.Certificate)
	for _, key := range siteKeys {
		for _, name := range certificateNames(siteCertificates[key]) {
			if _, taken := byName[name]; !taken {
				byName[name] = siteCertificates[key]
			}
		}
	}
	certificatesByName.Store(&byName)
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
	cert, err := tls.LoadX509KeyPair(siteDir+certFileName, siteDir+keyFileName)
	if err != nil {
		return err
	}
	setSiteCertificate(siteKey, &cert)
	return nil
}

const certificateRenewBefore = 30 * 24 * time.Hour

// renewCertificates asks Certbot, one site at a time, to renew the certificates issued by Turbo (the site has
// an e-mail and a folder in turbo.certificates) that expire in less than 30 days (DP5). It runs daily.
func renewCertificates() {
	type renewal struct{ siteKey, certDir, siteDir string }
	var due []renewal
	globalMutex.RLock()
	certificatesDir := sitesDir.Get() + putSlash(certificatesDirName)
	for domain := range sitesMap {
		for subdomain := range sitesMap[domain] {
			siteKey, siteDir := domain, sitesDir.Get()+changeWildcards(domain)+"/"
			if subdomain != "" {
				siteKey = subdomain + "." + domain
				siteDir += changeWildcards(subdomain) + "/"
			}
			certDir := certificatesDir + changeWildcards(siteKey) // As in the "C" validator
			if email, _ := siteSSLConfig[siteKey]["E"].(string); email == "" {
				continue
			}
			// Issued by Turbo: its own folder, or (subdomains issued before each site had one) its lineage in the
			// folder of the domain.
			if !dirExists(certDir) && (subdomain == "" || !dirExists(certificatesDir+changeWildcards(domain)+"/archive/"+siteKey)) {
				continue
			}
			if expiry, err := certificateExpiry(siteDir + certFileName); err == nil && time.Until(expiry) < certificateRenewBefore {
				due = append(due, renewal{siteKey, certDir, siteDir})
			}
		}
	}
	globalMutex.RUnlock()
	for _, site := range due {
		slog.Info("Renovando el certificado", "sitio", site.siteKey)
		withGlobalLock(func() { obtainCertificate(site.siteKey, site.certDir, site.siteDir) })
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
		return time.Time{}, errors.New("sin certificado PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

// requestHostname returns the host of a request without its port.
func requestHostname(request *customNetHttp.Request) string {
	if hostname, _, err := net.SplitHostPort(request.Host); err == nil {
		return hostname
	}
	return request.Host
}

// httpsRedirect sends an HTTP request to HTTPS, on the host it asked for, when the site has HTTPS on and a
// certificate covers that host. An alias without a certificate keeps being served by HTTP under its own name.
// Callers hold the global read lock.
func httpsRedirect(siteKey string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) bool {
	hostname := requestHostname(request)
	if !httpsEnabled(siteKey) || certificateFor(hostname) == nil {
		return false
	}
	customNetHttp.Redirect(responseWriter, request, "https://"+hostname+request.RequestURI, 301)
	return true
}

// setCertificateStatus records the result of a certificate attempt, if the site still exists.
func setCertificateStatus(domain string, status interface{}) {
	withGlobalLock(func() {
		if _, siteExists := siteSSLConfig[domain]; siteExists {
			siteSSLConfig[domain]["C"] = status
		}
	})
}

// obtainCertificate starts a Certbot attempt for domain. Callers hold the global lock; the goroutine and the
// retries take it themselves.
func obtainCertificate(domain string, certDir string, siteDir string) {
	if currentCertDomain == "" {
		currentCertDomain = domain

		go func() {
			timeoutCtx, cancelFn := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancelFn()

			//j := exec.CommandContext(x, "C://timeWaitExample.exe") // Windows tests

			var siteFound bool
			var adapter, email, contentDirName string
			withGlobalLock(func() {
				if _, siteFound = siteSSLConfig[domain]; !siteFound { // If site is deleted
					currentCertDomain = ""
					return
				}
				adapter, _ = siteSSLConfig[domain]["A"].(string)
				email, _ = siteSSLConfig[domain]["E"].(string)
				contentDirName = publicDirName
			})
			if !siteFound {
				slog.Warn("Emisión de certificado interrumpida: el sitio se ha borrado", "sitio", domain)
				return
			}
			finishAttempt := func(status interface{}) {
				withGlobalLock(func() { currentCertDomain = "" })
				setCertificateStatus(domain, status)
			}

			cmd := exec.CommandContext(timeoutCtx, "certbot", "--version")
			_, execErr := cmd.CombinedOutput()

			if execErr != nil {
				finishAttempt("Certbot no está instalado")
				return
			}

			_, execErr = os.ReadDir(certDir)
			if execErr == nil {
				if os.RemoveAll(certDir) != nil {
					finishAttempt("Error al vaciar directorio de certificado anterior")
					return
				}
			}

			/*j := exec.CommandContext(x,
			"sudo", // This causes issues on other types of Linux, like Alpine
			"certbot",
			"certonly",
			"-d", domain,
			"--dns-route53",
			"-n", // Not interactive
			"--agree-tos",
			"-m", S["X"], // Email for expiring notifications
			//"--test-cert",
			"--no-eff-email", // --eff-email to acept share email with EFF
			//"--force-renewal", "--break-my-certs", // Both needed for --test-cert
			"--config-dir", certDir)*/

			if adapter != "" {
				cmd = exec.CommandContext(timeoutCtx, // #nosec G204 -- fixed program; domain checked by hostOk, email by the E validator and the adapter by validCertbotAdapter. For incompatibility with wildcards or --dns-route53
					"certbot",
					"certonly",
					"-d", domain,
					"--"+adapter,
					"-n", // Not interactive
					"--agree-tos",
					"-m", email, // Email for expiring notifications
					// "--test-cert",
					"--no-eff-email", // --eff-email
					// "--force-renewal", "--break-my-certs", // Both needed for --test-cert
					"--config-dir", certDir,
					"--work-dir", certDir+"/work",
					"--logs-dir", certDir+"/logs")
			} else {
				cmd = exec.CommandContext(timeoutCtx, // #nosec G204 -- fixed program; domain checked by hostOk, email by the E validator and the adapter by validCertbotAdapter. For incompatibility with wildcards or --dns-route53
					"certbot",
					"certonly",
					"-d", domain,
					"--webroot",
					"--webroot-path", siteDir+contentDirName,
					"-n", // Not interactive
					"--agree-tos",
					"-m", email, // Email for expiring notifications
					// "--test-cert",
					"--no-eff-email", // --eff-email
					// "--force-renewal", "--break-my-certs", // Both needed for --test-cert
					"--config-dir", certDir,
					"--work-dir", certDir+"/work",
					"--logs-dir", certDir+"/logs")
			}

			cmdOutput, execErr := cmd.CombinedOutput()
			withGlobalLock(func() { currentCertDomain = "" })

			if execErr != nil {
				setCertificateStatus(domain, string(cmdOutput))
				return
			}

			certDir += "/archive/"

			archiveEntries, execErr := os.ReadDir(certDir)
			if execErr != nil {
				setCertificateStatus(domain, "Directorio de certificado ilegible al obtenerlo")
				return
			}

			var fullchainPath string
			var privkeyPath string
			nowUnix := time.Now().Unix()
			for _, archiveEntry := range archiveEntries {
				entryDir := certDir + archiveEntry.Name() + "/"
				certSubEntries, execErr := os.ReadDir(entryDir)
				if execErr != nil {
					continue
				}
				for _, archiveEntry = range certSubEntries {
					fileName := archiveEntry.Name()
					fileInfo, execErr := os.Stat(entryDir + fileName)
					if execErr != nil {
						continue
					}
					if len(fileName) > 10 && nowUnix-fileInfo.ModTime().Unix() < 216000 {
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
				setCertificateStatus(domain, "Archivos de certificado inexistentes al obtenerlo")
				return
			}

			renameErr := os.Rename(fullchainPath, siteDir+certFileName)
			if renameErr != nil {
				setCertificateStatus(domain, "'Fullchain' inmovible al obtenerlo")
				return
			}

			renameErr = os.Rename(privkeyPath, siteDir+keyFileName)
			if renameErr != nil {
				setCertificateStatus(domain, "'Privkey' inmovible al obtenerlo")
				return
			}

			setCertificateStatus(domain, true)
			withGlobalLock(func() { // A renewed certificate replaces the one in use, without restarting
				if httpsEnabled(domain) {
					if err := loadSiteCertificate(domain, siteDir); err != nil {
						slog.Error("No se puede cargar el certificado", "sitio", domain, "error", err)
					}
				}
			})
			slog.Info("Certificado emitido", "sitio", domain)
		}()
		return
	}

	if currentCertDomain == domain {
		return
	} // To prevent new certificate attempts from the same site

	certRetryDelay += 100 * time.Millisecond
	time.AfterFunc(certRetryDelay, func() {
		withGlobalLock(func() { obtainCertificate(domain, certDir, siteDir) })
	})
}
