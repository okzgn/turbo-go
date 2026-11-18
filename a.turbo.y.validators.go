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
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"turbo/customNetHttp"
	"unicode"
)

// Answers of the validators that the code looks for, to decide by them: those that give them and those that compare
// them use these names. The API gives these texts as they are.
const (
	msgValueUnchanged       = "Value unchanged"           // A setting that is already the one in use: kept, not reset to its default
	msgSitesDirUnchanged    = "Sites directory unchanged" // "M", the same
	msgFixedReplacement     = "Fixed replacement"         // One of the replacements that can't be changed: no mistake of turbo.config
	msgExpiredDate          = "Expired UNIX date"         // A denial that has ended: no mistake of turbo.config
	msgDeniedIPUnchanged    = "Denied IP unchanged"       // The entries of a list of turbo.config that repeat what is in use
	msgResponseUnchanged    = "Response unchanged"
	msgReplacementUnchanged = "Replacement unchanged"
	certificateWaitStatus   = `"status":"WAIT"` // In the answer of a certificate action while Certbot works (certificateWait)
)

// joinedSite is "subdomain.domain", or the domain alone without a subdomain.
func joinedSite(subdomain string, domain string) string {
	if subdomain != "" {
		return subdomain + "." + domain
	}
	return domain
}

// missingSiteMessage is the answer of an action on a site that isn't one: the subdomain named, or the site.
func missingSiteMessage(subdomain string) string {
	if subdomain != "" {
		return "Subdomain not found"
	}
	return "Site not found"
}

// listEntryUnchanged reports whether the answer of adding an entry to a list ("_", "@", "#") says that it was there.
func listEntryUnchanged(answer string) bool {
	return answer == msgDeniedIPUnchanged || answer == msgResponseUnchanged || answer == msgReplacementUnchanged
}

// certificateWait is the answer of a certificate action while Certbot works on a certificate: the JSON that the
// panel gets with 202, which is no error.
func certificateWait(text string) string {
	return `{"message":"` + text + `",` + certificateWaitStatus + `}`
}

// isCertificateWait reports whether the answer of a certificate action is one of certificateWait.
func isCertificateWait(answer string) bool {
	return strings.Contains(answer, certificateWaitStatus)
}

var (
	currentDirPlaceholder = "TURBO_CURRENT_DIR"
	rawConfigMap          map[string]map[string]interface{}

	// siteDirStat looks at the folders of a site (a variable so that tests can make it slow).
	siteDirStat = os.Stat
	// siteFileRemove, siteDirMake, certificateFileRead and certificatePairLoad delete a certificate file, make the
	// folders of a site or of the certificates, read a certificate file and load a pair (variables so that tests can
	// make them slow, or fail).
	siteFileRemove      = os.Remove
	siteDirMake         = os.MkdirAll
	certificateFileRead = os.ReadFile
	certificatePairLoad = tls.LoadX509KeyPair

	siteExistenceCheckers = map[string]func(bool, string, string) (bool, string){ // Site & subdomains existence check
		"/": func(checkExists bool, domain string, subdomain string) (bool, string) {
			domainDir := domain
			subdomainDir := subdomain
			targetPath := ""
			origDomain := domainDir
			origSubdomain := subdomainDir
			if subdomainDir != "" {
				targetPath = subdomainDir + "." + changeWildcards(domainDir, "x") // To check if domain name is correct, because it can't be verified if '*' or '#' is present
			} else {
				targetPath = domainDir
			}
			if isValidHost, _ := hostOk(targetPath, false); !isValidHost {
				return false, "Invalid site directory name"
			}
			domainDir = changeWildcards(domainDir)
			pathSeparator := ""
			if subdomainDir != "" {
				pathSeparator = "/"
				subdomainDir = changeWildcards(subdomainDir)
			}
			// What the reload looked at before taking the lock (lookAheadSettings), if it did
			if info, statErr := diskStat(sitesDir.Get() + domainDir + pathSeparator + subdomainDir); statErr != nil || !info.IsDir() {
				return false, "Site directory not found: " + domainDir + pathSeparator + subdomainDir
			}
			if info, statErr := diskStat(sitesDir.Get() + domainDir + pathSeparator + subdomainDir + "/" + publicDirName); statErr != nil || !info.IsDir() {
				return false, "Site content directory not found: " + domainDir + pathSeparator + subdomainDir + "/" + publicDirName
			}
			if checkExists && !siteExists(origDomain, origSubdomain) {
				if problem := siteNameProblem(origDomain, origSubdomain); problem != "" {
					slog.Warn("turbo.config site discarded", "site", origDomain, "subdomain", origSubdomain, "reason", problem)
					return false, problem
				}
				constructSiteWithoutIndex(origDomain, origSubdomain)
				if origSubdomain != "" {
					warnSiteNamedAsIPLocked(origSubdomain + "." + origDomain)
				} else {
					warnSiteNamedAsIPLocked(origDomain)
				}
			}
			return true, "Site directory processed"
		},
	}

	adminDeleteHandlers = map[string]func(string) (bool, string){
		"@": func(ip string) (bool, string) {
			ip = ipAddr(strings.TrimSpace(ip)) // As it was saved: canonical
			if _, exists := deniedIPsInUse()[ip]; !exists {
				return false, "IP not found"
			}
			setDeniedIPs(func(list map[string]int64) { delete(list, ip) })
			return true, "Denied IP removed"
		},
		"#": func(httpCode string) (bool, string) {
			code, err := strconv.Atoi(httpCode)
			if err != nil {
				return false, "Invalid HTTP code"
			}
			var exists bool
			if _, exists = (*httpResponses.Load())[code]; !exists {
				return false, "Response not found"
			}
			if _, exists = fixedHTTPResponses[code]; exists {
				return false, "Fixed response"
			}
			setHTTPResponses(func(responses map[int]string) { delete(responses, code) })
			return true, "HTTP code response removed"
		},
		"_": func(char string) (bool, string) { // The API already undid the replacements of the parameter
			var exists bool
			if _, exists = charReplacements[char]; !exists {
				return false, "Replacement not found"
			}
			if _, exists = fixedCharReplacements[char]; exists {
				return false, msgFixedReplacement
			}
			delete(charReplacements, char)
			return true, "Character replacement removed"
		},
	}

	adminAddHandlers = map[string]func(string, string) (bool, string){
		"@": func(ip string, unixDate string) (bool, string) {
			ip = strings.TrimSpace(ip)
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil || parsedIP.IsUnspecified() {
				return false, "Invalid IP"
			}
			if parsedIP.IsLoopback() {
				return false, "Loopback IP"
			}
			address := ipAddr(ip)
			// An IPv6 denial covers its /64 (deniedNetworks): one of ::/64 (::2, ::7f00:1) denied ::1 too, closing the
			// connections of the health checks, a local proxy or an SSH tunnel.
			if limiterKey(address) == limiterKey("::1") {
				return false, "Loopback IP: its /64 holds ::1"
			}
			dateText := strings.TrimSpace(unixDate)
			parsedUnix, parseErr := strconv.ParseInt(dateText, 10, 64)
			if parseErr != nil {
				return false, "Invalid UNIX date"
			}
			existingUnix, exists := deniedIPsInUse()[address] // Also while a turbo.config is applied
			if parsedUnix == 0 || time.Now().Unix() > parsedUnix {
				if exists {
					setDeniedIPs(func(list map[string]int64) { delete(list, address) })
					return true, "Denied IP removed"
				}
				return false, msgExpiredDate
			}
			isModified, answer := true, "Denied IP added"
			if exists && existingUnix == parsedUnix { // The date as a number: "05" is 5
				isModified, answer = false, msgDeniedIPUnchanged
			} else if exists {
				answer = "Denied IP modified"
			}
			setDeniedIPs(func(list map[string]int64) { list[address] = parsedUnix })
			return isModified, answer
		},
		"#": func(httpCode string, response string) (bool, string) {
			value := response
			codeInt, parseErr := strconv.Atoi(httpCode)
			if parseErr != nil {
				return false, "Invalid HTTP code"
			}
			if (codeInt < 400 || codeInt > 599) && codeInt != 0 {
				return false, "HTTP code out of range"
			}
			value = strings.TrimSpace(value)
			length := len(value)
			if length < 1 || length > 2048 {
				return false, "Response too short or too long"
			}
			current, exists := (*httpResponses.Load())[codeInt]
			if exists && current == value {
				return false, msgResponseUnchanged
			}
			setHTTPResponses(func(responses map[int]string) { responses[codeInt] = value })
			return true, "Response saved"
		},
		"_": func(char string, replacement string) (bool, string) { // replacement is the token that stands for char
			if char != " " {
				char = strings.TrimSpace(char)
			}
			if fixedCharReplacements[char] { // As it is saved: " ;" was taken for another character, and replaced the fixed one
				return false, msgFixedReplacement
			}
			if length := len(char); length < 1 {
				return false, "No character"
			} else if length > 4 {
				return false, "Too many characters"
			}
			replacement = strings.TrimSpace(replacement)
			if length := len(replacement); length < 2 || length > 16 {
				return false, "Replacement too short or too long"
			}
			if problem := replacementTokenProblem(char, replacement); problem != "" {
				return false, problem
			}
			if current, exists := charReplacements[char]; exists && current == replacement {
				return false, msgReplacementUnchanged
			}
			charReplacements[char] = replacement
			return true, "Character replacement saved"
		},
	}

	// shortcutWordReplacers gives the value of each placeholder of a rewrite target, for a request served by site
	// whose decoded, clean path (requestPath) matched the rewrite key rewriteMatch. The values aren't encoded here:
	// shortcutWords does it for where they go.
	shortcutWordReplacers = map[string]func(request *customNetHttp.Request, site siteMatch, rewriteMatch string, requestPath string) string{
		currentDirPlaceholder: func(*customNetHttp.Request, siteMatch, string, string) string { return currentDir() },
		"WILDCARD_SITE": func(_ *customNetHttp.Request, site siteMatch, _ string, _ string) string {
			return joinedSite(site.siteSubdomain, site.siteDomain)
		},
		"WILDCARD_DOMAIN":    func(_ *customNetHttp.Request, site siteMatch, _ string, _ string) string { return site.siteDomain },
		"WILDCARD_SUBDOMAIN": func(_ *customNetHttp.Request, site siteMatch, _ string, _ string) string { return site.siteSubdomain },
		"DOMAIN":             func(_ *customNetHttp.Request, site siteMatch, _ string, _ string) string { return site.domain },
		"SUBDOMAIN":          func(_ *customNetHttp.Request, site siteMatch, _ string, _ string) string { return site.subdomain },
		"SITE": func(_ *customNetHttp.Request, site siteMatch, _ string, _ string) string {
			return joinedSite(site.subdomain, site.domain)
		},
		"FIRST_DOMAIN":    func(_ *customNetHttp.Request, site siteMatch, _ string, _ string) string { return site.firstDomain },
		"FIRST_SUBDOMAIN": func(_ *customNetHttp.Request, site siteMatch, _ string, _ string) string { return site.firstSubdomain },
		"FIRST_SITE": func(_ *customNetHttp.Request, site siteMatch, _ string, _ string) string {
			return joinedSite(site.firstSubdomain, site.firstDomain)
		},
		"FIRST_REQUEST": func(_ *customNetHttp.Request, _ siteMatch, _ string, requestPath string) string { return requestPath },
		"FIRST_QUERY": func(request *customNetHttp.Request, _ siteMatch, _ string, _ string) string {
			_, query, _ := strings.Cut(request.RequestURI, "?")
			return query
		},
		"DIR": func(_ *customNetHttp.Request, _ siteMatch, _ string, requestPath string) string {
			if requestDir := dir(requestPath); requestDir != "/" {
				return requestDir
			}
			return ""
		},
		"FILE": func(_ *customNetHttp.Request, _ siteMatch, _ string, requestPath string) string {
			if requestPath != "" && requestPath[len(requestPath)-1] != '/' {
				return serverFuncBase(requestPath)
			}
			return ""
		},
		"EXT": func(_ *customNetHttp.Request, _ siteMatch, _ string, requestPath string) string {
			return ext(requestPath)
		},
		"REWRITE": func(_ *customNetHttp.Request, _ siteMatch, rewriteMatch string, _ string) string { return rewriteMatch },
		"REWRITE_COMPLEMENT": func(request *customNetHttp.Request, _ siteMatch, rewriteMatch string, requestPath string) string {
			// What follows the key in the decoded, clean path it matched, and the query
			complement := ""
			if length := len(rewriteMatch); length < len(requestPath) {
				complement = requestPath[length:]
			}
			if queryStart := strings.IndexByte(request.RequestURI, '?'); queryStart != -1 {
				complement += request.RequestURI[queryStart:]
			}
			return complement
		},
	}
)

// replacementTokenProblem says why token can't stand for char among the character replacements in use, or "": a
// token can't have a replaced character (its own included), contain another token or be inside one, and char
// can't be inside another token. Otherwise undoing the replacements would depend on their order, or turn a text
// typed on purpose into something else. Callers hold the global lock.
func replacementTokenProblem(char string, token string) string {
	// A replacement stands for characters that a URL can't carry as they are (";", "#", "&"…): a letter or a digit
	// never needs one, and with them a token could turn a site's or an extension's name into another one.
	if strings.IndexFunc(char, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) != -1 {
		return "Letters and digits are never replaced"
	}
	if strings.Contains(token, char) {
		return "Replacement with its own character"
	}
	others := make([]string, 0, len(charReplacements))
	for other := range charReplacements {
		others = append(others, other)
	}
	sort.Strings(others)
	for _, other := range others {
		if other == char {
			continue
		}
		otherToken := charReplacements[other]
		switch {
		case strings.Contains(token, other):
			return "Replacement with a replaced character (" + other + ")"
		case strings.Contains(token, otherToken) || strings.Contains(otherToken, token):
			return "Replacement that overlaps with that of " + other + " (" + otherToken + ")"
		case strings.Contains(otherToken, char):
			return "Character present in the replacement of " + other + " (" + otherToken + ")"
		}
	}
	return ""
}
