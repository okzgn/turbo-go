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
	"fmt"
	"os"
	"os/exec"
	pathpkg "path"
	"strings"
	"time"
	"turbo/customNetHttp"
)

func isConn(connState customNetHttp.ConnState) bool {
	if connState == customNetHttp.StateNew || connState == customNetHttp.StateActive || connState == customNetHttp.StateIdle {
		return true
	}
	return false
}

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
	c := strings.IndexByte(input, delimiter)
	if c != -1 {
		return input[:c]
	}
	return input
}

func cleanOldValues(store *map[string]int64) {
	c := time.Now().Unix()
	for a, b := range *store {
		if c > b {
			delete(*store, a)
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

func hostExist(hostHeader string) (bool, string, string, string) {
	a, b, c, d := detectWildcards(hostHeader, "")

	if !a {
		b, c, d, hostHeader = hostParts(hostHeader)
		if b != "" {
			b += "."
		}
		if d != "" {
			d += "."
		}
		//fmt.Println("UNKNOWN DOMAIN", b + c, d + e)
		return a, "", b + c, d + hostHeader
	}

	if c != "" { // c is filled when wildcard is detected
		//fmt.Println("WILDCARD", a, d, b, c)
		return a, d, b, c
	}
	//fmt.Println("DOMAIN", a, c, b, d)
	return a, c, b, d
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
	l := len(hostHeader)
	m := strings.LastIndexByte(hostHeader, '*')
	if l < 1 || l > 220 ||
		hostHeader[0] == '.' || hostHeader[l-1] == '.' ||
		hostHeader[0] == '-' || hostHeader[l-1] == '-' ||
		strings.Contains(hostHeader, "--") ||
		strings.Contains(hostHeader, "..") ||
		strings.Contains(hostHeader, ".-") ||
		strings.Contains(hostHeader, "-.") ||
		((m != -1) && l > 1 && ((m != 0) || (hostHeader[m+1] != '.'))) {
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
		c, _, _, _ := hostExist(hostHeader)
		if c {
			return false, "Sitio existente"
		}
	}
	a, b, d, hostHeader := hostParts(hostHeader)
	k := len(hostHeader)
	if k > 31 {
		return false, "TLD incorrecto"
	}
	k = len(d)
	if k > 63 {
		return false, "Dominio incorrecto"
	} // Initially unsupported 1 digit domain names: (b != "" && k == 1) ||
	k = len(b)
	if k > 63 {
		return false, "Longitud excesiva"
	}
	k = len(a)
	if k > 63 {
		return false, "Longitud excesiva"
	}
	return true, ""
}

func hostChars(hostHeader string) bool {
	for k, _ := range hostHeader {
		if (hostHeader[k] < 97 || hostHeader[k] > 122) && (hostHeader[k] < 45 || hostHeader[k] > 46) && (hostHeader[k] < 48 || hostHeader[k] > 57) && hostHeader[k] != 42 {
			return false
		}
	}
	return true
}

func extChars(extension string) bool {
	if extension[0] == '.' {
		extension = extension[1:]
	}
	if extension[0] == '-' || extension[len(extension)-1] == '.' || extension[len(extension)-1] == '-' || strings.Contains(extension, "..") || strings.Contains(extension, "--") {
		return false
	}
	for k, _ := range extension {
		if (extension[k] < 97 || extension[k] > 122) && (extension[k] < 45 || extension[k] > 46) && (extension[k] < 48 || extension[k] > 57) && (extension[k] < 65 || extension[k] > 90) {
			return false
		}
	}
	return true
}

func headerChars(headerName string) bool {
	for k, _ := range headerName {
		if (headerName[k] < 97 || headerName[k] > 122) && (headerName[k] < 45 || headerName[k] > 46) && (headerName[k] < 48 || headerName[k] > 57) && (headerName[k] < 65 || headerName[k] > 90) {
			return false
		}
	}
	return true
}

func replaceURIChars(uri string) string {
	for k, v := range charReplacements {
		uri = strings.ReplaceAll(uri, v, k)
	}
	return uri
}
func changeWildcards(input ...string) string {
	r := "#"
	if len(input) == 2 {
		r = input[1]
	}
	return strings.ReplaceAll(input[0], "*", r)
}
func putWildcards(input ...string) string {
	r := "#"
	if len(input) == 2 {
		r = input[1]
	}
	return strings.ReplaceAll(input[0], r, "*")
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
		if _, c := sitesMap[domain][pattern]; c {
			return true
		}
		return false
	}
	if _, c := sitesMap[pattern]; c {
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
	l := len(path)
	if l > 0 && path[l-1] != '/' {
		path += "/"
	}
	return path
}

func fileExists(path string) bool {
	m, i := os.Stat(path)
	if !os.IsNotExist(i) && !m.IsDir() {
		return true
	}
	return false
}

func currentDir() string {
	d, e := os.Getwd()
	if e != nil {
		return ""
	}
	return putSlash(d)
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
	var i bool
	if _, i = sitesMap[domain]; !i {
		return false
	}
	if _, i = sitesMap[domain][subdomain]; !i {
		return false
	}
	return true
}

func deleteCertificate(siteKey string) {
	var hasSSL bool
	if _, hasSSL = siteSSLConfig[siteKey]["S"]; !hasSSL {
		return
	}
	certCount := len(tlsConfig.Certificates)
	if certCount > 1 {
		targetIdx := siteSSLConfig[siteKey]["S"].(int)
		if certCount != targetIdx {
			for currentSiteKey, _ := range siteSSLConfig {
				if siteSSLConfig[currentSiteKey]["S"] == certCount { // Assign the map key and value to deletion to the last one that will be removed instead
					tlsConfig.Certificates[targetIdx-1] = tlsConfig.Certificates[certCount-1]
					tlsConfig.NameToCertificate[currentSiteKey] = &tlsConfig.Certificates[targetIdx-1]
					siteSSLConfig[currentSiteKey]["S"] = targetIdx
					break
				}
			}
		}
		tlsConfig.Certificates = tlsConfig.Certificates[:certCount-1]
		delete(tlsConfig.NameToCertificate, siteKey)
	} else {
		tlsConfig.Certificates = []tls.Certificate{}
		tlsConfig.NameToCertificate = nil
		// Don't close servers[0] because need to restart createSafeServer(tlsConfig)
	}
}

func obtainCertificate(domain string, certDir string, siteDir string) {
	if currentCertDomain == "" {
		currentCertDomain = domain

		go func() {
			timeoutCtx, cancelFn := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancelFn()

			//j := exec.CommandContext(x, "C://timeWaitExample.exe") // Windows tests

			if _, b := siteSSLConfig[domain]; !b { // If site is deleted
				currentCertDomain = ""
				fmt.Println("Certificate intent truncated from deleted site \"" + domain + "\"")
				return
			}

			cmd := exec.CommandContext(timeoutCtx, "certbot", "--version")
			_, execErr := cmd.CombinedOutput()

			if execErr != nil {
				currentCertDomain = ""
				siteSSLConfig[domain]["C"] = "Certbot no está instalado"
				return
			}

			_, execErr = os.ReadDir(certDir)
			if execErr == nil {
				if os.RemoveAll(certDir) != nil {
					currentCertDomain = ""
					siteSSLConfig[domain]["C"] = "Error al vaciar directorio de certificado anterior"
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

			if siteSSLConfig[domain]["A"] != "" {
				cmd = exec.CommandContext(timeoutCtx, // For incompatibility with wildcards or --dns-route53
					"certbot",
					"certonly",
					"-d", domain,
					"--"+siteSSLConfig[domain]["A"].(string),
					"-n", // Not interactive
					"--agree-tos",
					"-m", siteSSLConfig[domain]["E"].(string), // Email for expiring notifications
					// "--test-cert",
					"--no-eff-email", // --eff-email
					// "--force-renewal", "--break-my-certs", // Both needed for --test-cert
					"--config-dir", certDir)
			} else {
				cmd = exec.CommandContext(timeoutCtx, // For incompatibility with wildcards or --dns-route53
					"certbot",
					"certonly",
					"-d", domain,
					"--webroot",
					"--webroot-path", siteDir+stringStore["F"],
					"-n", // Not interactive
					"--agree-tos",
					"-m", siteSSLConfig[domain]["E"].(string), // Email for expiring notifications
					// "--test-cert",
					"--no-eff-email", // --eff-email
					// "--force-renewal", "--break-my-certs", // Both needed for --test-cert
					"--config-dir", certDir)
			}

			cmdOutput, execErr := cmd.CombinedOutput()
			currentCertDomain = ""

			if execErr != nil {
				siteSSLConfig[domain]["C"] = string(cmdOutput)
				return
			}

			certDir += "/archive/"

			archiveEntries, execErr := os.ReadDir(certDir)
			if execErr != nil {
				siteSSLConfig[domain]["C"] = "Directorio de certificado ilegible al obtenerlo"
				return
			}

			var fullchainPath string
			var privkeyPath string
			nowUnix := time.Now().Unix()
			for _, f := range archiveEntries {
				n := certDir + f.Name() + "/"
				certSubEntries, execErr := os.ReadDir(n)
				if execErr != nil {
					continue
				}
				for _, f = range certSubEntries {
					m := f.Name()
					fileInfo, execErr := os.Stat(n + m)
					if execErr != nil {
						continue
					}
					if len(m) > 10 && nowUnix-fileInfo.ModTime().Unix() < 216000 {
						switch m[:4] {
						case "full":
							fullchainPath = n + m
						case "priv":
							privkeyPath = n + m
						}
					}
				}
				break // Because is only one dir
			}

			if fullchainPath == "" || privkeyPath == "" {
				siteSSLConfig[domain]["C"] = "Archivos de certificado inexistentes al obtenerlo"
				return
			}

			renameErr := os.Rename(fullchainPath, siteDir+stringStore["C"])
			if renameErr != nil {
				siteSSLConfig[domain]["C"] = "'Fullchain' inmovible al obtenerlo"
				return
			}

			renameErr = os.Rename(privkeyPath, siteDir+stringStore["K"])
			if renameErr != nil {
				siteSSLConfig[domain]["C"] = "'Privkey' inmovible al obtenerlo"
				return
			}

			siteSSLConfig[domain]["C"] = true
			fmt.Println("SSL cert: " + domain)
			currentCertDomain = ""
		}()
		return
	}

	if currentCertDomain == domain {
		return
	} // To prevent new certificate attempts from the same site

	certRetryDelayMs += 100
	time.AfterFunc(certRetryDelayMs*time.Millisecond, func() { obtainCertificate(domain, certDir, siteDir) })
}
