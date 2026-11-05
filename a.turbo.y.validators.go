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
	"log/slog"
	"mime"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"turbo/customNetHttp"
	"unicode"
)

var (
	currentDirPlaceholder = "TURBO_CURRENT_DIR"
	rawConfigMap          map[string]map[string]interface{}

	// siteDirStat looks at the folders of a site (a variable so that tests can make it slow).
	siteDirStat = os.Stat

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
			}
			return true, "Site directory processed"
		},
	}

	defaultSettingsResetFallbacks = map[string]map[string]func(){ // Default settings check reset fallback
		".": {
			"C":   func() {},
			"U":   func() {},
			"P":   func() {},
			"M":   func() {},
			"PA":  func() { panelAccess.Store(&panelAccessList{}) },
			"MUB": func() { maxURILength.Store(1000) },
			"MHB": func() { maxHeaderBytes.Store(5000) },
			"MBB": func() { maxBodySize.Store(1048576) }, // 1 Mb
			"CIL": func() { serverRequestLimits.CIL.Store(10000 * int64(time.Millisecond)) },
			"CIS": func() { serverRequestLimits.CIS.Store(1000 * int64(time.Millisecond)) },
			"CII": func() { serverRequestLimits.CII.Store(100) },
			"CGL": func() { globalRequestLimit.Store(0) },
			"CGP": func() { cgiProcesses.Store(0) },
			"RT":  func() { setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.RT = 5 * time.Second }) },
			"RHT": func() { setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.RHT = 1 * time.Second }) },
			"WT":  func() { setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.WT = 10 * time.Second }) },
			"IT":  func() { setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.IT = 2 * time.Second }) },
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
				return false, "Fixed replacement"
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
				return false, "Expired UNIX date"
			}
			isModified := true
			change := "added"
			if strconv.FormatInt(existingUnix, 10) == dateText {
				isModified = false
				change = "unchanged"
			} else if exists {
				change = "modified"
			}
			setDeniedIPs(func(list map[string]int64) { list[address] = parsedUnix })
			return isModified, "Denied IP " + change
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
				return false, "Response unchanged"
			}
			setHTTPResponses(func(responses map[int]string) { responses[codeInt] = value })
			return true, "Response saved"
		},
		"_": func(char string, replacement string) (bool, string) { // replacement is the token that stands for char
			if fixedCharReplacements[char] {
				return false, "Fixed replacement"
			}
			if char != " " {
				char = strings.TrimSpace(char)
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
				return false, "Replacement unchanged"
			}
			charReplacements[char] = replacement
			return true, "Character replacement saved"
		},
	}

	// indexPosition reads the position saved for an index ("1", "2"...); anything else goes last.
	indexPosition = func(value interface{}) int {
		if text, isString := value.(string); isString {
			if number, err := strconv.Atoi(text); err == nil && number > 0 {
				return number
			}
		}
		return int(^uint(0) >> 1)
	}

	defaultSettingKeysGroup = map[string][]string{
		".": {"M", "PA", "MUB", "MHB", "MBB", "CIL", "CIS", "CII", "CGL", "CGP", "RT", "RHT", "WT", "IT"}, // Not "C": saving is an action
	}

	defaultSettingErrorExceptions = map[string]map[string]map[string]bool{ // Refusals that keep the setting as it is, instead of resetting it to its default
		".": {
			"M":   map[string]bool{"Sites directory unchanged": true},
			"PA":  map[string]bool{"Value unchanged": true},
			"MUB": map[string]bool{"Value unchanged": true},
			"MHB": map[string]bool{"Value unchanged": true},
			"MBB": map[string]bool{"Value unchanged": true},
			"CIL": map[string]bool{"Value unchanged": true},
			"CIS": map[string]bool{"Value unchanged": true},
			"CII": map[string]bool{"Value unchanged": true},
			"CGL": map[string]bool{"Value unchanged": true},
			"CGP": map[string]bool{"Value unchanged": true},
			"RT":  map[string]bool{"Value unchanged": true},
			"RHT": map[string]bool{"Value unchanged": true},
			"WT":  map[string]bool{"Value unchanged": true},
			"IT":  map[string]bool{"Value unchanged": true},
		},
	}

	defaultSettingValidators = map[string]map[string]func(...string) (bool, string){ // Default settings check
		".": {
			"C": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " for C"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong password"
				}
				var schemaRead int // Saving takes the locks itself: callers of "C" don't hold the global lock
				withReadLock(func() { schemaRead = configSchemaRead })
				if schemaRead > configSchema && args[0] != "overwrite" {
					return false, "turbo.config is from a later version of Turbo (schema " + strconv.Itoa(schemaRead) + "): saving would lose its new settings. To overwrite it, confirm (in the API, a=overwrite)"
				}
				if !saveDefaultConfig() {
					return false, "Error saving"
				}
				return true, "Configuration saved"
			},
			"U": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " for U"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				length := len(args[0])
				if length < 1 || length > 24 {
					return false, "User too long or too short"
				}
				if args[0] == panelUser.Get() {
					return false, "User unchanged"
				}
				panelUser.Set(args[0])
				return true, "User changed"
			},
			"P": func(args ...string) (bool, string) { // args[2], if given, is newPasswordHash(args[0]), computed before the lock
				if len(args) != 2 && len(args) != 3 {
					return false, msgMissingData + " for P"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				hash := ""
				if len(args) == 3 {
					hash = args[2]
				} else if newHash, problem, err := newPasswordHash(args[0]); err != nil {
					return false, "Error hashing the password"
				} else if problem != "" {
					return false, problem
				} else {
					hash = newHash
				}
				applyPasswordHash(hash, args[0])
				return true, "Password changed"
			},
			"M": func(args ...string) (bool, string) {
				if len(args) < 2 {
					return false, msgMissingData + " for M"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}

				resolved, err := resolveSitesDir(args[0])
				if err != nil {
					return false, "Sites directory not found"
				}
				if sameDirWith(resolved, sitesDir.Get(), diskStat) {
					if loadingConfig { // The same folder written another way: saved as the file writes it
						sitesDirValue.Set(args[0])
					}
					return false, "Sites directory unchanged"
				}
				// While a turbo.config is applied, the reload has followed its "M" already (updateSettingsFollowing), or
				// chose not to (setM to the start directory): the sites directory changes only with the reload that
				// applies its configuration, at once.
				if loadingConfig {
					return false, "Sites directory unchanged"
				}
				info, err := diskStat(resolved)
				if err != nil || !info.IsDir() { // Doesn't exist or the path isn't valid on this system
					return false, "Sites directory not found"
				}
				sitesDir.Set(resolved)
				sitesDirValue.Set(args[0])
				return true, "Sites directory set"
			},
			"PA": func(args ...string) (bool, string) { // Where the panel answers
				if len(args) != 2 {
					return false, msgMissingData + " for PA"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				list, errorMsg := parsePanelAccess(args[0])
				if list == nil {
					return false, errorMsg
				}
				if list.setting == panelAccess.Load().setting {
					return false, "Value unchanged"
				}
				panelAccess.Store(list)
				if list.setting == "" {
					return true, "Panel reachable from any host"
				}
				message := "Panel hosts and networks saved"
				for _, ip := range list.ipHosts { // Easy to take for a network
					mask := "/32"
					if strings.IndexByte(ip, ':') != -1 {
						mask = "/128"
					}
					message += ". " + ip + " is a host (it is compared with the Host header); to limit the client's IP, use " + ip + mask
				}
				return true, message
			},
			"MUB": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " for MUB"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				value, err := strconv.Atoi(args[0])
				if err != nil {
					return false, "Invalid value"
				}
				if int64(value) == maxURILength.Load() {
					return false, "Value unchanged"
				}
				if value < 40 {
					return false, "Less than 40 bytes"
				}
				if value > 10240 {
					return false, "More than 10240 bytes"
				}
				maxURILength.Store(int64(value))
				return true, "Maximum URI length saved"
			},
			"MHB": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " for MHB"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				value, err := strconv.Atoi(args[0])
				if err != nil {
					return false, "Invalid value"
				}
				if int64(value) == maxHeaderBytes.Load() {
					return false, "Value unchanged"
				}
				if value < 600 {
					return false, "Less than 600 bytes"
				}
				if value > 20480 {
					return false, "More than 20480 bytes"
				}
				maxHeaderBytes.Store(int64(value))
				return true, "Maximum header length saved"
			},
			"MBB": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " for MBB"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				value, err := strconv.ParseInt(args[0], 10, 64)
				if err != nil {
					return false, "Invalid value"
				}
				if value == maxBodySize.Load() {
					return false, "Value unchanged"
				}
				if value < 1 {
					return false, "Less than 1 byte"
				}
				if value > 104857600 {
					return false, "More than 104857600 bytes (100 MB)"
				}
				maxBodySize.Store(value)
				return true, "Maximum body size saved"
			},
			"CIL": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " for CIL"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				value, err := strconv.ParseInt(args[0], 10, 64)
				if err != nil {
					return false, "Invalid value"
				}
				if value*int64(time.Millisecond) == serverRequestLimits.CIL.Load() {
					return false, "Value unchanged"
				}
				if value < 1000 {
					return false, "Less than 1000 milliseconds"
				}
				if value > 800000 {
					return false, "More than 800000 milliseconds"
				}
				serverRequestLimits.CIL.Store(value * int64(time.Millisecond))
				return true, "Request interval limit saved"
			},
			"CIS": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " for CIS"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				value, err := strconv.ParseInt(args[0], 10, 64)
				if err != nil {
					return false, "Invalid value"
				}
				if value < 10 {
					return false, "Less than 10 milliseconds"
				}
				if value > 50000 {
					return false, "More than 50000 milliseconds"
				}
				if problem := rateLimitProblem(value, serverRequestLimits.CII.Load()); problem != "" && !loadingConfig {
					return false, "Value incompatible with CII (" + strconv.FormatInt(serverRequestLimits.CII.Load(), 10) + "): " + problem
				}
				if value*int64(time.Millisecond) == serverRequestLimits.CIS.Load() {
					return false, "Value unchanged"
				}
				serverRequestLimits.CIS.Store(value * int64(time.Millisecond))
				return true, "Request interval saved"
			},
			"CII": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " for CII"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				value, err := strconv.ParseInt(args[0], 10, 64)
				if err != nil {
					return false, "Invalid value"
				}
				if value < 1 {
					return false, "Less than 1"
				}
				if problem := rateLimitProblem(serverRequestLimits.CIS.Load()/int64(time.Millisecond), value); problem != "" && !loadingConfig {
					return false, problem
				}
				if value == serverRequestLimits.CII.Load() {
					return false, "Value unchanged"
				}
				serverRequestLimits.CII.Store(value)
				return true, "Maximum requests per interval saved"
			},
			"CGL": func(args ...string) (bool, string) { // Requests per second for the whole server
				if len(args) != 2 {
					return false, msgMissingData + " for CGL"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				value, err := strconv.ParseInt(args[0], 10, 64)
				if err != nil {
					return false, "Invalid value"
				}
				if value == globalRequestLimit.Load() {
					return false, "Value unchanged"
				}
				if value != 0 && (value < 10 || value > 1000000) {
					return false, "Must be 0 (no limit) or from 10 to 1000000"
				}
				globalRequestLimit.Store(value)
				if value == 0 {
					return true, "Global request limit disabled"
				}
				return true, "Global request limit saved"
			},
			"CGP": func(args ...string) (bool, string) { // CGI processes at a time
				if len(args) != 2 {
					return false, msgMissingData + " for CGP"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				value, err := strconv.ParseInt(args[0], 10, 64)
				if err != nil {
					return false, "Invalid value"
				}
				if value == cgiProcesses.Load() {
					return false, "Value unchanged"
				}
				if value < 0 || value > 100000 {
					return false, "Must be 0 (automatic) or from 1 to 100000"
				}
				cgiProcesses.Store(value)
				if value == 0 {
					return true, "Concurrent CGI processes: automatic (" + strconv.FormatInt(cgiProcessLimit(), 10) + " on this machine)"
				}
				return true, "Concurrent CGI processes saved"
			},
			"RT": func(args ...string) (bool, string) {
				settingArgs := args
				if len(settingArgs) != 2 {
					return false, msgMissingData + " for RT"
				}
				if !passwordMatches(settingArgs[1]) {
					return false, "Wrong current password"
				}
				value, err := time.ParseDuration(settingArgs[0])
				if err != nil {
					return false, "Invalid value"
				}
				if value != 0 {
					if value < 100*time.Millisecond {
						return false, "Less than 100 milliseconds"
					}
					if value > 900000*time.Millisecond {
						return false, "More than 15 minutes"
					}
				}
				if readTimeProblem(value, serverTimeLimits.Load().RHT) && !loadingConfig {
					return false, "Less than twice the header read timeout (RHT " + serverTimeLimits.Load().RHT.String() + ")"
				}
				if value == serverTimeLimits.Load().RT {
					return false, "Value unchanged"
				}
				setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.RT = value })
				if value == 0 && !loadingConfig {
					warnUnlimitedTimeouts()
				}
				return true, "Request read timeout saved"
			},
			"RHT": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " for RHT"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				value, err := time.ParseDuration(args[0])
				if err != nil {
					return false, "Invalid value"
				}
				if value != 0 {
					if value < 50*time.Millisecond {
						return false, "Less than 50 milliseconds"
					}
					if readTimeProblem(serverTimeLimits.Load().RT, value) && !loadingConfig {
						return false, "More than half the request read timeout"
					}
					if value > 450000*time.Millisecond {
						return false, "More than 7.5 minutes"
					}
				}
				if value == serverTimeLimits.Load().RHT {
					return false, "Value unchanged"
				}
				setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.RHT = value })
				if value == 0 && !loadingConfig {
					warnUnlimitedTimeouts()
				}
				return true, "Header read timeout saved"
			},
			"WT": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " for WT"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				value, err := time.ParseDuration(args[0])
				if err != nil {
					return false, "Invalid value"
				}
				if value == serverTimeLimits.Load().WT {
					return false, "Value unchanged"
				}
				if value != 0 {
					if value < 100*time.Millisecond {
						return false, "Less than 100 milliseconds"
					}
					if value > 1800000*time.Millisecond {
						return false, "More than 30 minutes"
					}
				}
				setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.WT = value })
				if value == 0 && !loadingConfig {
					warnUnlimitedTimeouts()
				}
				return true, "Response write timeout saved"
			},
			"IT": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " for IT"
				}
				if !passwordMatches(args[1]) {
					return false, "Wrong current password"
				}
				value, err := time.ParseDuration(args[0])
				if err != nil {
					return false, "Invalid value"
				}
				if value == serverTimeLimits.Load().IT {
					return false, "Value unchanged"
				}
				if value != 0 {
					if value < 100*time.Millisecond {
						return false, "Less than 100 milliseconds"
					}
					if value > 300000*time.Millisecond {
						return false, "More than 5 minutes"
					}
				}
				setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.IT = value })
				if value == 0 && !loadingConfig {
					warnUnlimitedTimeouts()
				}
				return true, "Idle connection timeout saved"
			},
		},
	}

	// siteSSLSettingOrder is the order of the settings of "!": with R and W both at 1, R comes first and W is
	// refused (only one of the two redirections can be on).
	siteSSLSettingOrder = []string{"S", "C", "R", "W", "E", "A"}

	subdomainContentCheckers = map[string]func(bool, interface{}, bool, ...string) (bool, string){ // Subdomains content check
		"!": func(printErrors bool, configData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // SSLs check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " for configurations"
			}
			mapData, isMap := configData.(map[string]interface{})
			if !isMap {
				return false, "Invalid configuration data"
			}

			for _, setting := range siteSSLSettingOrder {
				if _, exists := mapData[setting]; !exists {
					continue
				}

				strVal, isValue := configNumberOrString(mapData[setting]) // A string, or a JSON integer ("S": 1)
				if !isValue {
					boolVal, isBool := mapData[setting].(bool)
					if isBool {
						isValue = true
						if boolVal {
							strVal = "1"
						} else {
							strVal = "0"
						}
					} else {
						intVal, isInt := mapData[setting].(int)
						if isInt {
							isValue = true
							strVal = strconv.Itoa(intVal)
						}
					}
				}

				if !isValue {
					if printErrors {
						return false, "Invalid configuration value"
					}
					slog.Warn("turbo.config site setting discarded: wrong type", "site", siteKeys[0], "subdomain", siteKeys[1], "setting", setting)
					continue
				}

				if applied, msg := siteSSLSettingCheckers[setting](isFromFile, strVal, siteKeys[0], siteKeys[1]); !applied {
					if printErrors {
						return false, msg
					}
					// The state of the certificate (C), an empty e-mail or adapter, and R or W off in a subdomain (as
					// Turbo itself saves them, and v2.3.rc3 too) aren't errors of the file.
					redirectOffInSubdomain := (setting == "R" || setting == "W") && siteKeys[1] != "" && strVal == "0"
					if setting != "C" && strVal != "" && !redirectOffInSubdomain {
						slog.Warn("turbo.config site setting discarded", "site", siteKeys[0], "subdomain", siteKeys[1], "setting", setting, "value", strVal, "reason", msg)
					}
				}
			}
			return true, "Configurations processed"
		},
		"=": func(printErrors bool, rewriteData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Rewrites check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " for rewrites"
			}
			mapData, isMap := rewriteData.(map[string]interface{})
			if !isMap {
				return false, "Invalid rewrites content"
			}

			if printErrors && !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}

			for _, targetURI := range sortedKeys(mapData) {
				rawTarget := mapData[targetURI]
				strVal, isString := rawTarget.(string)
				if !isString {
					if printErrors {
						return false, "Invalid rewrite value"
					}
					continue
				}

				var isExisting bool
				if !isFromFile { // turbo.config keeps the values decoded
					targetURI = replaceURIChars(targetURI)
				}
				if _, isExisting = sitesMap[siteKeys[0]][siteKeys[1]][targetURI]; isExisting {
					if sitesMap[siteKeys[0]][siteKeys[1]][targetURI][1:] == strVal {
						if printErrors {
							return false, "Rewrite unchanged"
						}
						continue
					}
				}
				valueLen := len(targetURI)
				if valueLen < 1 || strings.Contains(targetURI, "//") || strings.Contains(targetURI, "..") || targetURI[0] != '/' {
					if printErrors {
						return false, "Invalid relative address"
					}
					continue
				}
				if valueLen > 128 {
					if printErrors {
						return false, "Relative address too long"
					}
					continue
				}
				if !isFromFile {
					strVal = replaceURIChars(strVal)
				}
				valueLen = len(strVal)
				if valueLen < 1 || strings.Contains(strVal, "..") {
					if printErrors {
						return false, "Invalid rewrite"
					}
					continue
				}
				schemeMode := "N"
				if lower := strings.ToLower(strVal); strings.HasPrefix(lower, "http://") { // The scheme in any case
					schemeMode = "H"
					strVal = strVal[7:]
				} else if strings.HasPrefix(lower, "https://") {
					schemeMode = "S"
					strVal = strVal[8:]
				}
				if schemeMode != "N" && (strVal == "" || strVal[0] == '/' || strVal[0] == '?') { // "https://" alone would redirect anywhere
					if printErrors {
						return false, "The target needs a host"
					}
					if isFromFile {
						slog.Warn("Rewrite discarded: the target has no host", "site", siteKeys[0], "subdomain", siteKeys[1], "source", targetURI)
					}
					continue
				}
				if unknown := unknownPlaceholder(strVal); unknown != "" {
					if printErrors {
						return false, "Unknown keyword: " + unknown
					}
					if isFromFile {
						slog.Warn("Rewrite discarded: unknown keyword", "site", siteKeys[0], "subdomain", siteKeys[1], "source", targetURI, "keyword", unknown)
					}
					continue
				}
				if strings.Contains(strVal, "//") {
					if printErrors {
						return false, "Invalid rewrite"
					}
					continue
				}
				if schemeMode == "N" && strVal[0] != '/' {
					if printErrors {
						return false, "The rewrite must start with /, http:// or https://"
					}
					if isFromFile { // Accepted by older versions: say why it disappears from the config
						slog.Warn("Rewrite discarded: the target must start with /, http:// or https://", "site", siteKeys[0], "subdomain", siteKeys[1], "source", targetURI, "target", strVal)
					}
					continue
				}
				if valueLen > 512 {
					if printErrors {
						return false, "Rewrite too long"
					}
					continue
				}
				sitesMap[siteKeys[0]][siteKeys[1]][targetURI] = schemeMode + strVal
				if printErrors {
					if !isExisting {
						return true, "Rewrite created"
					} else {
						return true, "Rewrite changed"
					}
				}
			}
			return true, "Rewrites processed"
		},
		"$": func(printErrors bool, mimeData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // MIMEs check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " for MIMEs"
			}
			entries, isMap := mimeData.(map[string]interface{})
			if !isMap {
				return false, "Invalid MIMEs content"
			}

			if printErrors && !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}
			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := mimeTypes[siteKeys[1]]; !exists {
				return false, "No MIMEs defined"
			}

			for _, writtenExt := range sortedKeys(entries) {
				rawMIME := entries[writtenExt]
				ext := strings.ToLower(writtenExt) // Looked up in lower case (ext): ".PHP" is also preprocessed
				mimeType, isString := rawMIME.(string)
				if !isString {
					if printErrors {
						return false, "Invalid MIME value"
					}
					continue
				}

				var existed bool
				if !isFromFile {
					mimeType = replaceURIChars(mimeType)
				}
				if current, exists := mimeTypes[siteKeys[1]][strings.TrimPrefix(ext, ".")]; exists {
					existed = true
					if current == mimeType {
						if printErrors {
							return false, "MIME unchanged"
						}
						continue
					}
				} else {
					existed = false
				}
				extLen := len(ext)
				if extLen > 12 {
					if printErrors {
						return false, "Extension too long"
					}
					continue
				}
				if extLen > 0 && !extChars(ext) {
					if printErrors {
						return false, "Invalid extension"
					}
					continue
				}
				if extLen > 0 && ext[0] == '.' {
					ext = ext[1:]
				}
				if mimeLen := len(mimeType); mimeLen < 4 || mimeLen > 128 {
					if printErrors {
						return false, "MIME too long or too short"
					}
					continue
				}
				_, _, parseErr := mime.ParseMediaType(mimeType)
				if parseErr != nil {
					if printErrors {
						return false, "Invalid MIME"
					}
					continue
				}
				mimeTypes[siteKeys[1]][ext] = mimeType
				if printErrors {
					if !existed {
						return true, "MIME created"
					} else {
						return true, "MIME changed"
					}
				}
			}
			return true, "MIMEs processed"
		},
		".": func(printErrors bool, headerData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Headers check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " for headers"
			}
			entries, isMap := headerData.(map[string]interface{})
			if !isMap {
				return false, "Invalid headers content"
			}

			if printErrors && !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}
			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := customHeaders[siteKeys[1]]; !exists {
				return false, "No headers defined"
			}

			for _, header := range sortedKeys(entries) {
				rawValue := entries[header]
				if isFromFile && headerSetCaseInsensitive(customHeaders[siteKeys[1]], header) {
					slog.Warn("Header repeated in turbo.config (in upper or lower case): the first one is kept", "site", siteKeys[1], "header", header)
					continue
				}
				value, isString := rawValue.(string)
				if !isString {
					if printErrors {
						return false, "Invalid header value"
					}
					continue
				}

				var existed bool
				if !isFromFile {
					value = replaceURIChars(value)
				}
				if _, exists := customHeaders[siteKeys[1]][header]; exists {
					existed = true
					if customHeaders[siteKeys[1]][header] == value {
						if printErrors {
							return false, "Header unchanged"
						}
						continue
					}
				} else {
					existed = false
				}
				if !headerChars(header) {
					if printErrors {
						return false, "Invalid header"
					}
					continue
				}
				if nameLen := len(header); nameLen < 1 || nameLen > maxHeaderKeyLength {
					if printErrors {
						return false, "Header too long or too short"
					}
					continue
				}
				if valueLen := len(value); valueLen < 1 || valueLen > maxHeaderValueLength {
					if printErrors {
						return false, "Content too long or too short"
					}
					continue
				}
				if !isFromFile { // The same header in other case is this one: replaced (both would go out, either first)
					for existing := range customHeaders[siteKeys[1]] {
						if existing != header && strings.EqualFold(existing, header) {
							delete(customHeaders[siteKeys[1]], existing)
							existed = true
						}
					}
				}
				customHeaders[siteKeys[1]][header] = value
				if printErrors {
					if !existed {
						return true, "Header created"
					} else {
						return true, "Header changed"
					}
				}
			}
			return true, "Headers processed"
		},
		"?": func(printErrors bool, preprocessorData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Preprocessors check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " for preprocessors"
			}
			entries, isMap := preprocessorData.(map[string]interface{})
			if !isMap {
				return false, "Invalid preprocessors content"
			}

			if printErrors && !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}
			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := preprocessors[siteKeys[1]]; !exists {
				return false, "No preprocessors defined"
			}

			for _, writtenExt := range sortedKeys(entries) {
				rawValue := entries[writtenExt]
				ext := strings.ToLower(writtenExt) // Looked up in lower case (ext): ".PHP" is also preprocessed
				site := siteKeys[1]
				if _, repeated := preprocessors[site][strings.TrimPrefix(ext, ".")]; repeated && isFromFile {
					slog.Warn("Preprocessor repeated in turbo.config (in upper or lower case): the first one is kept", "site", site, "extension", writtenExt)
					continue
				}
				// From turbo.config, an entry that can't be used is kept and its extension answers 500: never the
				// source of the files it should run, and saving doesn't lose it.
				keepFailing := func(value string, reason string) {
					if value == "" { // An empty value would mean no preprocessor
						value = invalidPreprocessorMark
					}
					slog.Warn("turbo.config preprocessor that can't be used: the extension will answer 500", "site", site, "extension", ext, "reason", reason)
					preprocessors[site][strings.TrimPrefix(ext, ".")] = value
				}
				value, isString := rawValue.(string) // From the panel, as sent: no character replacements (literalActions)
				if !isString {
					if printErrors {
						return false, "Invalid preprocessor value"
					}
					keepFailing(invalidPreprocessorMark, "the value is not a string")
					continue
				}
				if extLen := len(ext); extLen > 12 || extLen > 0 && !extChars(ext) {
					reason := "Invalid extension"
					if extLen > 12 {
						reason = "Extension too long"
					}
					if printErrors {
						return false, reason
					}
					keepFailing(invalidPreprocessorMark+value, reason)
					continue
				}
				ext = strings.TrimPrefix(ext, ".")

				var existed bool
				if current, exists := preprocessors[site][ext]; exists {
					existed = true
					if current == value {
						if printErrors {
							return false, "Preprocessor unchanged"
						}
						continue
					}
				}
				executable, problem := preprocessorCommand(value)
				if problem != "" {
					if printErrors {
						return false, problem
					}
					keepFailing(value, problem)
					continue
				}
				if info, err := diskStat(executable); err != nil || info.IsDir() { // Doesn't exist, the path isn't valid on this system or it is a folder
					if printErrors {
						if err != nil {
							return false, "Preprocessor not found"
						}
						return false, "Invalid preprocessor"
					}
					keepFailing(value, "the executable does not exist or is a folder: "+executable)
					continue
				}

				preprocessors[site][ext] = value // As written: {TURBO_CURRENT_DIR} is replaced when it runs
				if printErrors {
					if !existed {
						return true, "Preprocessor added"
					} else {
						return true, "Preprocessor modified"
					}
				}
			}
			return true, "Preprocessors processed"
		},
		"-": func(printErrors bool, indexData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Indexes check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " for indexes"
			}
			entries, isMap := indexData.(map[string]interface{})
			if !isMap {
				return false, "Invalid indexes content"
			}

			if printErrors && !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}
			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := indexFiles[siteKeys[1]]; !exists {
				return false, "No indexes defined"
			}

			// From turbo.config, each index comes with its position; from the panel, it goes after the rest.
			names := sortedKeys(entries) // Indexes with the same position go by name
			sort.SliceStable(names, func(left, right int) bool {
				return indexPosition(entries[names[left]]) < indexPosition(entries[names[right]])
			})
			for _, name := range names {
				if !isFromFile {
					name = replaceURIChars(name)
				}
				length := len(name)
				if length < 1 || length > 48 {
					if printErrors {
						return false, "Index file too long or too short"
					}
					continue
				}
				// The rules of the request paths, with those of Windows on every system: there, "index.php." or
				// "INDEX~1.PHT" would open another file than the name says, and its extension wouldn't be preprocessed.
				if strings.IndexByte(name, '\\') != -1 || strings.IndexByte(name, '/') != -1 || strings.Contains(name, "..") || !textAllowed(name, false) || !pathSegmentAllowed(name, true) {
					if printErrors {
						return false, "Invalid index file"
					}
					if isFromFile {
						slog.Warn("turbo.config index discarded: name not allowed", "site", siteKeys[1], "index", name)
					}
					continue
				}
				addIndex(siteKeys[1], name)
				if printErrors {
					return true, "Index assigned"
				}
			}
			return true, "Indexes processed"
		},
		"&": func(printErrors bool, aliasData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Alias check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " for aliases"
			}
			entries, isMap := aliasData.(map[string]interface{})
			if !isMap {
				return false, "Invalid aliases content"
			}

			if printErrors && !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}
			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			for _, alias := range sortedKeys(entries) {
				if strings.IndexByte(alias, '*') != -1 {
					if printErrors {
						return false, "Wildcards not allowed"
					}
					continue
				}
				validHost, hostMsg := hostOk(alias, false)
				if !validHost {
					if printErrors {
						return false, hostMsg
					}
					continue
				}
				if served, _, _, _ := hostExist(alias); served { // The alias would hide the site (aliases go first)
					if printErrors {
						return false, "The alias is a site's host"
					}
					// The site wins. Of a site already there when the alias is read (one of turbo.config before it, or
					// one that came while this one was kept without its folder); dropAliasesOfSites tells the others.
					slog.Warn("Alias discarded: its host is a site's", "alias", alias, "site", siteKeys[1])
					continue
				}
				if target, assigned := domainAliases[alias]; assigned {
					if target == siteKeys[1] && printErrors {
						return false, "Alias unchanged"
					}
					if printErrors {
						return false, "Alias already assigned"
					}
					if isFromFile && target != siteKeys[1] { // From turbo.config, or kept with a site that comes back
						slog.Warn("Alias of two sites: the first one is kept", "alias", alias, "site", target, "discarded", siteKeys[1])
					}
					continue
				}
				domainAliases[alias] = siteKeys[1]
				if printErrors {
					return true, "Alias assigned"
				}
			}
			return true, "Aliases processed"
		},
	}

	subdomainContentDeleters = map[string]func(bool, interface{}, ...string) (bool, string){ // Subdomains content deletion check
		"=": func(printErrors bool, rewriteData interface{}, siteKeys ...string) (bool, string) {
			if len(siteKeys) != 2 {
				return false, msgMissingData + " for deleting rewrites"
			}
			entries, isMap := rewriteData.(map[string]interface{})
			if !isMap {
				return false, "Invalid rewrites content"
			}

			if !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}

			for rewriteKey := range entries {
				rewriteKey = replaceURIChars(rewriteKey)
				if _, exists := sitesMap[siteKeys[0]][siteKeys[1]][rewriteKey]; !exists {
					if printErrors {
						return false, "Rewrite not found"
					}
					continue
				}
				delete(sitesMap[siteKeys[0]][siteKeys[1]], rewriteKey)
				if printErrors {
					return true, "Rewrite deleted"
				}
			}
			return true, "Rewrites processed"
		},
		"$": func(printErrors bool, mimeData interface{}, siteKeys ...string) (bool, string) {
			if len(siteKeys) != 2 {
				return false, msgMissingData + " for deleting MIMEs"
			}
			entries, isMap := mimeData.(map[string]interface{})
			if !isMap {
				return false, "Invalid MIMEs content"
			}

			if !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}

			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := mimeTypes[siteKeys[1]]; !exists {
				return false, "No MIMEs defined"
			}

			for ext := range entries {
				ext = strings.ToLower(ext)
				if len(ext) > 0 && ext[0] == '.' {
					ext = ext[1:]
				}
				if _, exists := mimeTypes[siteKeys[1]][ext]; !exists {
					if printErrors {
						return false, "MIME not found"
					}
					continue
				}
				delete(mimeTypes[siteKeys[1]], ext)
				if printErrors {
					return true, "MIME deleted"
				}
			}
			return true, "MIMEs processed"
		},
		".": func(printErrors bool, headerData interface{}, siteKeys ...string) (bool, string) {
			if len(siteKeys) != 2 {
				return false, msgMissingData + " for deleting headers"
			}
			entries, isMap := headerData.(map[string]interface{})
			if !isMap {
				return false, "Invalid headers content"
			}

			if !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}

			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := customHeaders[siteKeys[1]]; !exists {
				return false, "No headers defined"
			}

			for header := range entries {
				if _, exists := customHeaders[siteKeys[1]][header]; !exists {
					if printErrors {
						return false, "Header not found"
					}
					continue
				}
				delete(customHeaders[siteKeys[1]], header)
				if printErrors {
					return true, "Header deleted"
				}
			}
			return true, "Headers processed"
		},
		"?": func(printErrors bool, preprocessorData interface{}, siteKeys ...string) (bool, string) {
			if len(siteKeys) != 2 {
				return false, msgMissingData + " for deleting preprocessors"
			}
			entries, isMap := preprocessorData.(map[string]interface{})
			if !isMap {
				return false, "Invalid preprocessors content"
			}

			if !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}

			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := preprocessors[siteKeys[1]]; !exists {
				return false, "No preprocessors defined"
			}

			for ext := range entries {
				ext = strings.ToLower(ext)
				if len(ext) > 0 && ext[0] == '.' {
					ext = ext[1:]
				}
				if _, exists := preprocessors[siteKeys[1]][ext]; !exists {
					if printErrors {
						return false, "Preprocessor not found"
					}
					continue
				}
				delete(preprocessors[siteKeys[1]], ext)
				if printErrors {
					return true, "Preprocessor deleted"
				}
			}
			return true, "Preprocessors processed"
		},
		"-": func(printErrors bool, indexData interface{}, siteKeys ...string) (bool, string) {
			if len(siteKeys) != 2 {
				return false, msgMissingData + " for deleting indexes"
			}
			entries, isMap := indexData.(map[string]interface{})
			if !isMap {
				return false, "Invalid indexes content"
			}

			if !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}

			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := indexFiles[siteKeys[1]]; !exists {
				return false, "No indexes defined"
			}

			for indexName := range entries {
				indexName = replaceURIChars(indexName)
				if _, exists := indexFiles[siteKeys[1]][indexName]; !exists {
					if printErrors {
						return false, "Index not found"
					}
					continue
				}
				delete(indexFiles[siteKeys[1]], indexName)
				if printErrors {
					return true, "Index deleted"
				}
			}
			return true, "Indexes processed"
		},
		"&": func(printErrors bool, aliasData interface{}, siteKeys ...string) (bool, string) {
			if len(siteKeys) != 2 {
				return false, msgMissingData + " for deleting aliases"
			}
			entries, isMap := aliasData.(map[string]interface{})
			if !isMap {
				return false, "Invalid aliases content"
			}

			if !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}

			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			for alias := range entries {
				if _, exists := domainAliases[alias]; !exists {
					if printErrors {
						return false, "Alias not found"
					}
					continue
				} else if domainAliases[alias] != siteKeys[1] {
					if printErrors {
						return false, "Alias of another site"
					}
					continue
				}
				delete(domainAliases, alias)
				if printErrors {
					return true, "Alias deleted"
				}
			}
			return true, "Aliases processed"
		},
	}

	validCertbotAdapter    = regexp.MustCompile(`^dns-[a-z0-9-]{2,30}$`) // Certbot DNS plugins, passed as --<adapter>
	siteSSLSettingCheckers = map[string]func(bool, ...string) (bool, string){
		"E": func(fromFile bool, args ...string) (bool, string) {
			argCount := len(args)
			if argCount < 3 || argCount > 5 {
				return false, msgMissingData + " for E"
			}
			// From turbo.config, which keeps it URL-encoded (createSiteSettingsList, where a "+" is "%2B"); the API gets it
			// decoded. A "+" is kept as it is: no e-mail has a space, and one written by hand (admin+certs@…) was dropped.
			if fromFile {
				email, err := url.PathUnescape(args[0])
				if err != nil {
					return false, "Invalid e-mail value"
				}
				args[0] = email
			}
			if problem := certbotEmailProblem(args[0]); problem != "" {
				return false, problem
			}

			if !siteExists(args[1], args[2]) {
				if args[2] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}
			if args[2] != "" {
				args[2] += "." + args[1]
			} else {
				args[2] = args[1]
			}

			if _, exists := siteSSLConfig[args[2]]; !exists {
				return false, "No configuration defined"
			}
			siteSSLConfig[args[2]]["E"] = args[0]
			return true, "E-mail saved"
		},
		"A": func(fromFile bool, args ...string) (bool, string) {
			argCount := len(args)
			if argCount < 3 || argCount > 5 {
				return false, msgMissingData + " for A"
			}

			adapter, err := url.QueryUnescape(args[0])
			if err != nil || (adapter != "" && !validCertbotAdapter.MatchString(adapter)) { // Empty means webroot
				return false, "Invalid adapter: dns-<provider> is accepted"
			}
			args[0] = adapter

			if !siteExists(args[1], args[2]) {
				if args[2] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}
			if args[2] != "" {
				args[2] += "." + args[1]
			} else {
				args[2] = args[1]
			}

			if _, exists := siteSSLConfig[args[2]]; !exists {
				return false, "No configuration defined"
			}

			siteSSLConfig[args[2]]["A"] = args[0]
			return true, "Adapter saved"
		},
		"C": func(fromFile bool, args ...string) (bool, string) {
			argCount := len(args)
			if argCount < 3 || argCount > 5 {
				return false, msgMissingData + " for C"
			}

			if !siteExists(args[1], args[2]) {
				if args[2] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}

			siteKey := args[1]
			if args[2] != "" {
				siteKey = args[2] + "." + args[1]
			}
			siteDir := sitesDir.Get() + siteFolder(args[1], args[2]) // Where the certificate stays, with the site

			if _, exists := siteSSLConfig[siteKey]; !exists {
				return false, "No configuration defined"
			}
			if argCount == 5 {
				if args[3] != "" {
					if problem := certbotEmailProblem(args[3]); problem != "" {
						return false, problem
					}
					siteSSLConfig[siteKey]["E"] = args[3]
				}
				if args[4] != "" {
					if !validCertbotAdapter.MatchString(args[4]) {
						return false, "Invalid adapter: dns-<provider> is accepted"
					}
					siteSSLConfig[siteKey]["A"] = args[4]
				}
			}

			filesExist := true
			fileInfo, statErr := diskStat(siteDir + certFileName)
			if statErr != nil || fileInfo.IsDir() {
				filesExist = false
			}
			fileInfo, statErr = diskStat(siteDir + keyFileName)
			if statErr != nil || fileInfo.IsDir() {
				filesExist = false
			}

			if filesExist && !fromFile && args[0] == "0" { // "Delete SSL", also for a certificate older than certificateStaleAfter
				if os.Remove(siteDir+certFileName) != nil ||
					os.Remove(siteDir+keyFileName) != nil {
					return false, "Error deleting the SSL files"
				}
				siteSSLConfig[siteKey]["C"] = false
				return true, "SSL certificate deleted"
			}

			if filesExist && time.Since(fileInfo.ModTime()) > certificateStaleAfter {
				filesExist = false
			}

			if filesExist {
				siteSSLConfig[siteKey]["C"] = true
				return true, "SSL certificate active"
			}

			// Without valid certificate files, Certbot only runs when the administrator asks for it (a=1):
			if fromFile { // Read from the config file or found with the site folder: only record the state
				siteSSLConfig[siteKey]["C"] = false
				return false, "No certificate"
			}
			if args[0] != "1" {
				return false, "No certificate"
			}

			if _, isBool := siteSSLConfig[siteKey]["C"].(bool); !isBool { // The error of the last attempt is answered once
				message, isString := siteSSLConfig[siteKey]["C"].(string)
				if !isString {
					message = "Invalid certificate response"
				}
				siteSSLConfig[siteKey]["C"] = false
				return false, message
			}

			if email, _ := siteSSLConfig[siteKey]["E"].(string); email == "" {
				return false, "E-mail required to create the certificate"
			}

			siteSSLConfig[siteKey]["C"] = false

			certificatesDir := sitesDir.Get() + putSlash(certificatesDirName)
			fileInfo, statErr = diskStat(certificatesDir)
			if statErr != nil || !fileInfo.IsDir() {
				slog.Info("Creating the certificates directory", "directory", certificatesDir)
				if os.Mkdir(certificatesDir, 0700) != nil {
					return false, "Error creating the certificates directory"
				}
			}
			certDir := certificatesDir + changeWildcards(siteKey) // One Certbot folder per site: runCertbot removes the previous certificate before each attempt, and keeps the ACME account

			if currentCertDomain == siteKey {
				return false, "{\"message\":\"Please wait, certificate being processed\",\"status\":\"WAIT\"}"
			}

			obtainCertificate(siteKey, certDir, siteDir) // Creates a loop of attempts to get a certificate

			if currentCertDomain != siteKey {
				return false, "{\"message\":\"Please wait, certificate busy on " + currentCertDomain + "\",\"status\":\"WAIT\"}"
			}
			return false, "{\"message\":\"Please wait, certificate in process\",\"status\":\"WAIT\"}"
		},
		"S": func(fromFile bool, args ...string) (bool, string) {
			argCount := len(args)
			if argCount < 3 || argCount > 5 {
				return false, msgMissingData + " for S"
			}

			value, err := strconv.Atoi(args[0])
			if err != nil {
				return false, "Invalid value"
			}

			if !siteExists(args[1], args[2]) {
				if args[2] != "" {
					return false, "Subdomain not found"
				}
				return false, "Site not found"
			}
			var configKey string
			if args[2] != "" {
				configKey = args[2] + "." + args[1]
			} else {
				configKey = args[1]
			}

			if _, exists := siteSSLConfig[configKey]; !exists {
				return false, "No configuration defined"
			}

			if value != 0 { // S is 0 or 1; older turbo.config files kept a certificate index, any value but 0 means on
				if _, exists := siteCertificates[configKey]; exists {
					return false, "HTTPS redirect already enabled"
				}
				if loadSiteCertificate(configKey, sitesDir.Get()+siteFolder(args[1], args[2])) != nil {
					if !fromFile {
						return false, "SSL certificates invalid or missing"
					}
					// From turbo.config, HTTPS stays on until its files can be loaded (a folder restored before its
					// .pem, a key not readable yet): turned off, the next save wrote "S": 0 for good. Nothing is
					// redirected to HTTPS without a certificate (httpsRedirect), and loadPendingCertificates loads it
					// every 30 s.
					siteSSLConfig[configKey]["S"] = 1
					slog.Warn("HTTPS is on, but the site's certificate can't be loaded: it is tried again every 30 s", "site", configKey)
					return true, "HTTPS redirect enabled, certificate pending"
				}
				siteSSLConfig[configKey]["S"] = 1
				if servers[0] != nil && !httpsListening.Load() {
					safeServerStart(servers[0], tlsConfig) // Opens httpsAddr (:443) with the first certificate
				}

				slog.Info("HTTPS enabled", "site", configKey)
				return true, "HTTPS redirect enabled"
			}

			// If the setting values is 0:
			setSiteCertificate(configKey, nil)
			siteSSLConfig[configKey]["S"] = 0
			return true, "HTTPS redirect disabled"
		},
		"R": func(fromFile bool, args ...string) (bool, string) {
			argCount := len(args)
			if argCount < 3 || argCount > 5 {
				return false, msgMissingData + " for R"
			}
			if args[2] != "" { // Read at the root, it applies to www.<site>
				return false, "Only set at the site's root (empty d): it redirects www.<site> to <site>"
			}
			if args[0] != "0" && args[0] != "1" {
				return false, "Invalid value"
			}
			if !siteExists(args[1], "") {
				return false, "Site not found"
			}
			siteKey := args[1]
			if _, exists := siteSSLConfig[siteKey]; !exists {
				return false, "No configuration defined"
			}
			if args[0] == "0" {
				siteSSLConfig[siteKey]["R"] = false
				return true, "Redirect to root disabled"
			}
			if siteSSLConfig[siteKey]["W"] == true {
				return false, "Redirect to www enabled"
			}
			siteSSLConfig[siteKey]["R"] = true
			return true, "Redirect to root enabled"
		},
		"W": func(fromFile bool, args ...string) (bool, string) {
			argCount := len(args)
			if argCount < 3 || argCount > 5 {
				return false, msgMissingData + " for W"
			}
			if args[2] != "" { // Read at the root, it applies to <site>
				return false, "Only set at the site's root (empty d): it redirects <site> to www.<site>"
			}
			if args[0] != "0" && args[0] != "1" {
				return false, "Invalid value"
			}
			if !siteExists(args[1], "") {
				return false, "Site not found"
			}
			siteKey := args[1]
			if _, exists := siteSSLConfig[siteKey]; !exists {
				return false, "No configuration defined"
			}
			if args[0] == "0" {
				siteSSLConfig[siteKey]["W"] = false
				return true, "Redirect to WWW disabled"
			}
			if siteSSLConfig[siteKey]["R"] == true {
				return false, "Redirect to root enabled"
			}
			siteSSLConfig[siteKey]["W"] = true
			return true, "Redirect to WWW enabled"
		},
	}

	shortcutWordReplacers = map[string]func(*customNetHttp.Request, ...string) string{
		currentDirPlaceholder: func(request *customNetHttp.Request, wildcardParts ...string) string {
			return currentDir()
		},
		"WILDCARD_SITE": func(request *customNetHttp.Request, wildcardParts ...string) string {
			if wildcardParts[1] != "" {
				return wildcardParts[1] + "." + wildcardParts[0]
			}
			return wildcardParts[0]
		},
		"WILDCARD_DOMAIN":    func(request *customNetHttp.Request, wildcardParts ...string) string { return wildcardParts[0] },
		"WILDCARD_SUBDOMAIN": func(request *customNetHttp.Request, wildcardParts ...string) string { return wildcardParts[1] },
		"DOMAIN":             func(request *customNetHttp.Request, wildcardParts ...string) string { return wildcardParts[2] },
		"SUBDOMAIN":          func(request *customNetHttp.Request, wildcardParts ...string) string { return wildcardParts[3] },
		"SITE": func(request *customNetHttp.Request, wildcardParts ...string) string {
			if wildcardParts[3] != "" {
				return wildcardParts[3] + "." + wildcardParts[2]
			}
			return wildcardParts[2]
		},
		"FIRST_DOMAIN":    func(request *customNetHttp.Request, wildcardParts ...string) string { return wildcardParts[4] },
		"FIRST_SUBDOMAIN": func(request *customNetHttp.Request, wildcardParts ...string) string { return wildcardParts[5] },
		"FIRST_SITE": func(request *customNetHttp.Request, wildcardParts ...string) string {
			if wildcardParts[5] != "" {
				return wildcardParts[5] + "." + wildcardParts[4]
			}
			return wildcardParts[4]
		},
		// The path ones come from the decoded, clean path of the request (wildcardParts[7]); the values are not encoded
		// here, shortcutWords does it for where they go.
		"FIRST_REQUEST": func(request *customNetHttp.Request, wildcardParts ...string) string {
			return wildcardParts[7]
		},
		"FIRST_QUERY": func(request *customNetHttp.Request, wildcardParts ...string) string {
			_, query, _ := strings.Cut(request.RequestURI, "?")
			return query
		},
		"DIR": func(request *customNetHttp.Request, wildcardParts ...string) string {
			if requestDir := dir(wildcardParts[7]); requestDir != "/" {
				return requestDir
			}
			return ""
		},
		"FILE": func(request *customNetHttp.Request, wildcardParts ...string) string {
			if requestPath := wildcardParts[7]; requestPath != "" && requestPath[len(requestPath)-1] != '/' {
				return serverFuncBase(requestPath)
			}
			return ""
		},
		"EXT": func(request *customNetHttp.Request, wildcardParts ...string) string {
			return ext(wildcardParts[7])
		},
		"REWRITE": func(request *customNetHttp.Request, wildcardParts ...string) string {
			return wildcardParts[6]
		},
		"REWRITE_COMPLEMENT": func(request *customNetHttp.Request, wildcardParts ...string) string {
			// What follows the key in the decoded, clean path it matched, and the query
			complement := ""
			if length := len(wildcardParts[6]); length < len(wildcardParts[7]) {
				complement = wildcardParts[7][length:]
			}
			if queryStart := strings.IndexByte(request.RequestURI, '?'); queryStart != -1 {
				complement += request.RequestURI[queryStart:]
			}
			return complement
		},
	}
)

// certificateStaleAfter is the age of a site's certificate files from which they don't count as a certificate in
// use (Certbot's last 90 days): "Create SSL" issues a new one, and "Delete SSL" deletes them.
const certificateStaleAfter = 75 * 24 * time.Hour

// unknownPlaceholder returns the first "{NAME}" of a rewrite target that isn't a placeholder, or "".
func unknownPlaceholder(target string) string {
	for {
		openBraceIdx := strings.IndexByte(target, '{')
		if openBraceIdx == -1 {
			return ""
		}
		closeBraceIdx := strings.IndexByte(target[openBraceIdx:], '}')
		if closeBraceIdx == -1 {
			return ""
		}
		placeholder := target[openBraceIdx : openBraceIdx+closeBraceIdx+1]
		if _, known := shortcutWordReplacers[placeholder[1:len(placeholder)-1]]; !known {
			return placeholder
		}
		target = target[openBraceIdx+closeBraceIdx+1:]
	}
}

// headerSetCaseInsensitive reports whether headers has name, in any case.
func headerSetCaseInsensitive(headers map[string]string, name string) bool {
	for header := range headers {
		if strings.EqualFold(header, name) {
			return true
		}
	}
	return false
}

// invalidPreprocessorMark starts the value of a preprocessor of turbo.config whose extension or type is wrong: no
// value written can have a NUL, so it only marks it (the rest is the value as written, kept for saving).
const invalidPreprocessorMark = "\x00"

// preprocessorCommand returns the executable a preprocessor value runs ("[<protocol>>]<path>", as written in
// turbo.config or addPreprocessor, with {TURBO_CURRENT_DIR} replaced), or why it can't run. The limit of 128
// characters is for the path as written, without the protocol.
func preprocessorCommand(value string) (executable string, problem string) {
	if strings.HasPrefix(value, invalidPreprocessorMark) {
		return "", "invalid turbo.config entry"
	}
	protocol, path, hasProtocol := strings.Cut(value, ">")
	if !hasProtocol {
		protocol, path = "cgi", value
	}
	if pathLen := len(path); pathLen < 1 || pathLen > 128 {
		return "", "Preprocessor path too long or too short"
	}
	if strings.ToLower(protocol) != "cgi" { // "dx>" isn't implemented
		return "", "Invalid preprocessor protocol."
	}
	return strings.Replace(path, "{"+currentDirPlaceholder+"}", currentDir(), 1), ""
}

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

// certbotEmailProblem says why an e-mail can't be given to Certbot (cfgE, and z of cfgC), or "": 5 to 40 bytes,
// one "@" with something before it and a domain with a dot after it, and no spaces, "#", "--", a leading "-" or
// control characters.
func certbotEmailProblem(email string) string {
	local, domain, found := strings.Cut(email, "@")
	if !found || local == "" || strings.IndexByte(domain, '@') != -1 || strings.IndexByte(domain, '.') == -1 || !textAllowed(email, false) ||
		strings.ContainsAny(email, "# ") || strings.Contains(email, "--") || email[0] == '-' {
		return "Invalid e-mail value"
	}
	if len(email) < 5 || len(email) > 40 {
		return "Invalid e-mail length"
	}
	return ""
}

// loadingConfig is set while the global settings of turbo.config are applied: their keys come in any order, so
// the conditions between settings are checked once all are in (enforceSettingInvariants), not one by one.
// Guarded by globalMutex.
var loadingConfig bool

// rateLimitProblem says why CIS (in milliseconds) and CII can't go together, or "": at most CIS requests per
// window (one per millisecond), and windows of at most 66 times CII milliseconds, which the panel needs to work
// (2000 ms for 30 requests of the GUI). Compared by multiplying, so 66.5 is not taken for 66.
func rateLimitProblem(cisMillis int64, cii int64) string {
	if cii > cisMillis {
		return "More than " + strconv.FormatInt(cisMillis, 10)
	}
	if cisMillis > 66*cii {
		return "Value incompatible with the panel"
	}
	return ""
}

// readTimeProblem reports whether RHT is more than half of RT. RHT at 0 uses RT, and RT at 0 has no limit to be
// half of.
func readTimeProblem(rt time.Duration, rht time.Duration) bool {
	return rt > 0 && rht > 0 && 2*rht > rt
}

// warnUnlimitedTimeouts logs the timeouts without a limit (0): RT and WT, and RHT and IT while RT is 0 too (0 makes
// them use RT). A client could then hold a connection, or keep a CGI running, as long as it wanted. Turbo warns at the
// start and when the panel saves a 0; the defaults have limits.
func warnUnlimitedTimeouts() {
	limits := serverTimeLimits.Load()
	var unlimited []string
	for _, timeout := range []struct {
		key  string
		zero bool
	}{{"RT", limits.RT == 0}, {"RHT", limits.RHT == 0 && limits.RT == 0}, {"WT", limits.WT == 0}, {"IT", limits.IT == 0 && limits.RT == 0}} {
		if timeout.zero {
			unlimited = append(unlimited, timeout.key)
		}
	}
	if len(unlimited) > 0 {
		slog.Warn("Timeouts without a limit (0): a client can hold a connection, or keep a CGI running, as long as it wants", "settings", strings.Join(unlimited, ","))
	}
}

// enforceSettingInvariants puts back the defaults of the settings that don't meet their conditions with the ones
// they depend on, once turbo.config is applied: CII (and CIS, if the default CII still doesn't fit it) and RHT
// (or 0, which uses RT, if the default doesn't fit RT either). Callers hold the global lock.
func enforceSettingInvariants() {
	cisMillis := func() int64 { return serverRequestLimits.CIS.Load() / int64(time.Millisecond) }
	if problem := rateLimitProblem(cisMillis(), serverRequestLimits.CII.Load()); problem != "" {
		slog.Warn("CII of turbo.config is not compatible with CIS: the default value is used", "CIS", cisMillis(), "CII", serverRequestLimits.CII.Load(), "reason", problem)
		defaultSettingsResetFallbacks["."]["CII"]()
		if rateLimitProblem(cisMillis(), serverRequestLimits.CII.Load()) != "" {
			slog.Warn("CIS of turbo.config is not compatible with the default CII: the default value is used", "CIS", cisMillis())
			defaultSettingsResetFallbacks["."]["CIS"]()
		}
	}
	if limits := serverTimeLimits.Load(); readTimeProblem(limits.RT, limits.RHT) {
		slog.Warn("RHT of turbo.config is more than half of RT: the default value is used", "RT", limits.RT.String(), "RHT", limits.RHT.String())
		defaultSettingsResetFallbacks["."]["RHT"]()
		if limits = serverTimeLimits.Load(); readTimeProblem(limits.RT, limits.RHT) {
			setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.RHT = 0 }) // Uses RT
		}
	}
}
