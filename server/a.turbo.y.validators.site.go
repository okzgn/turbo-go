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

package server

// The validators of the settings of a site (its "!", cfg<KEY> in the API): HTTPS, its certificate, the redirections
// between the site and its www, the e-mail and the adapter of Certbot, and the precompressed files.

import (
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// msgAnyHostSiteHasNoWWW is why R and W can't be on for the site *: it serves the hosts that no other site does, IP
// addresses included, and "www." before one of those is no host ("http://www.::1/").
const msgAnyHostSiteHasNoWWW = "The site * serves any host, IP addresses included: it has no www to redirect"

// siteSSLSettingOrder is the order of the settings of "!": with R and W both at 1, R comes first and W is
// refused (only one of the two redirections can be on).
var siteSSLSettingOrder = []string{"S", "C", "R", "W", "E", "A", "Z"}

var validCertbotAdapter = regexp.MustCompile(`^dns-[a-z0-9-]{2,30}$`) // Certbot DNS plugins, passed as --<adapter>

var siteSSLSettingCheckers = map[string]func(bool, ...string) (bool, string){
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
		if args[0] != "" {
			if problem := certbotEmailProblem(args[0]); problem != "" {
				return false, problem
			}
		}

		if !siteExists(args[1], args[2]) {
			return false, missingSiteMessage(args[2])
		}
		if args[2] != "" {
			args[2] += "." + args[1]
		} else {
			args[2] = args[1]
		}

		if _, exists := siteSSLConfig[args[2]]; !exists {
			return false, "No configuration defined"
		}
		// An empty one removes it: the certificate stays, and is no longer renewed (renewCertificates renews those
		// of the sites with an e-mail); "Create SSL" asks for one again. No empty e-mail was accepted, so the only
		// way to stop the renewal was to delete the certificate.
		if args[0] == "" {
			if siteSSLConfig[args[2]].email == "" {
				return false, "E-mail unchanged"
			}
			siteSSLConfig[args[2]].email = ""
			return true, "E-mail removed"
		}
		siteSSLConfig[args[2]].email = args[0]
		return true, "E-mail saved"
	},
	"A": func(fromFile bool, args ...string) (bool, string) {
		argCount := len(args)
		if argCount < 3 || argCount > 5 {
			return false, msgMissingData + " for A"
		}

		// From turbo.config, which keeps it URL-encoded (createSiteSettingsList); the API takes it as sent, as every
		// cfg<KEY>.
		adapter := args[0]
		if fromFile {
			decoded, err := url.QueryUnescape(adapter)
			if err != nil {
				return false, "Invalid adapter: dns-<provider> is accepted"
			}
			adapter = decoded
		}
		if adapter != "" && !validCertbotAdapter.MatchString(adapter) { // Empty means webroot
			return false, "Invalid adapter: dns-<provider> is accepted"
		}
		args[0] = adapter

		if !siteExists(args[1], args[2]) {
			return false, missingSiteMessage(args[2])
		}
		if args[2] != "" {
			args[2] += "." + args[1]
		} else {
			args[2] = args[1]
		}

		if _, exists := siteSSLConfig[args[2]]; !exists {
			return false, "No configuration defined"
		}

		siteSSLConfig[args[2]].adapter = args[0]
		return true, "Adapter saved"
	},
	"C": func(fromFile bool, args ...string) (bool, string) {
		argCount := len(args)
		if argCount < 3 || argCount > 6 { // The sixth, of "Delete SSL": "1" also takes the certificate out of use
			return false, msgMissingData + " for C"
		}

		if !siteExists(args[1], args[2]) {
			return false, missingSiteMessage(args[2])
		}

		siteKey := args[1]
		if args[2] != "" {
			siteKey = args[2] + "." + args[1]
		}
		siteDir := sitesDir.Get() + siteFolder(args[1], args[2]) // Where the certificate stays, with the site

		if _, exists := siteSSLConfig[siteKey]; !exists {
			return false, "No configuration defined"
		}
		stopUsing := false
		if argCount == 6 {
			switch args[5] {
			case "", "0":
			case "1":
				stopUsing = true
			default:
				return false, "Invalid value for x: 0 or 1"
			}
		}
		if argCount >= 5 {
			// Both checked before either is saved: with a valid e-mail and an invalid adapter, the e-mail was saved
			// and the answer was the adapter's error, so the panel couldn't know what was saved.
			if args[3] != "" {
				if problem := certbotEmailProblem(args[3]); problem != "" {
					return false, problem
				}
			}
			if args[4] != "" && !validCertbotAdapter.MatchString(args[4]) {
				return false, "Invalid adapter: dns-<provider> is accepted"
			}
			if args[3] != "" {
				siteSSLConfig[siteKey].email = args[3]
			}
			if args[4] != "" {
				siteSSLConfig[siteKey].adapter = args[4]
			}
		}

		filesExist, anyFile := true, false
		fileInfo, statErr := diskStat(siteDir + certFileName)
		if statErr != nil || fileInfo.IsDir() {
			filesExist = false
		} else {
			anyFile = true
		}
		fileInfo, statErr = diskStat(siteDir + keyFileName)
		if statErr != nil || fileInfo.IsDir() {
			filesExist = false
		} else {
			anyFile = true
		}

		// "Delete SSL", also for a certificate older than certificateStaleAfter, and for what a deletion that failed
		// halfway left: with only one of the files there (the key, which another program held open), the answer was
		// "No certificate", and it could no longer be deleted from the panel. The certificate in use stays until
		// another one is installed or Turbo restarts, so that replacing a certificate doesn't leave the site
		// without HTTPS meanwhile, unless the administrator asks to stop using it too (stopUsing; the panel asks):
		// the site is then left as a restart would leave it, with no HTTPS of its own, and no redirection to it,
		// until another certificate is installed. Asked for without files, it takes out of use the one that an
		// earlier deletion left there.
		_, inUse := siteCertificates[siteKey]
		// While Certbot issues or renews it (or waits to), its files would come back, or be put in use without files
		if !fromFile && args[0] == "0" && (currentCertDomain == siteKey || certPending[siteKey]) {
			return false, certificateBeingIssued
		}
		if !fromFile && args[0] == "0" && (anyFile || (stopUsing && inUse)) {
			// The files are removed once the global lock is released (removeFiles); if one can't be, what changes
			// here goes back, as when it was removed first.
			previousState, previousCertificate := siteSSLConfig[siteKey].certificate, siteCertificates[siteKey]
			undo := func() {
				if settings, kept := siteSSLConfig[siteKey]; kept {
					settings.certificate = previousState
				}
				if _, replaced := siteCertificates[siteKey]; previousCertificate != nil && !replaced {
					setSiteCertificate(siteKey, previousCertificate)
				}
			}
			if removeFiles("Error deleting the SSL files", undo, siteDir+certFileName, siteDir+keyFileName) != nil {
				return false, "Error deleting the SSL files"
			}
			siteSSLConfig[siteKey].certificate = certificateState{}
			if stopUsing && inUse {
				setSiteCertificate(siteKey, nil)
				slog.Info("The certificate of a site was deleted and is no longer in use: the site has no HTTPS until another one is installed", "site", siteKey)
				if !anyFile {
					return true, "SSL certificate no longer in use"
				}
				return true, "SSL certificate deleted, and no longer in use"
			}
			return true, "SSL certificate deleted"
		}

		if filesExist && time.Since(fileInfo.ModTime()) > certificateStaleAfter {
			filesExist = false
		}

		if filesExist {
			siteSSLConfig[siteKey].certificate = certificateState{active: true}
			return true, "SSL certificate active"
		}

		// Without valid certificate files, Certbot only runs when the administrator asks for it (a=1):
		if fromFile { // Read from the config file or found with the site folder: only record the state
			siteSSLConfig[siteKey].certificate = certificateState{}
			return false, "No certificate"
		}
		if args[0] != "1" {
			return false, "No certificate"
		}

		if state := siteSSLConfig[siteKey].certificate; state.failed { // The error of the last attempt is answered once
			siteSSLConfig[siteKey].certificate = certificateState{}
			return false, state.failure
		}

		if siteSSLConfig[siteKey].email == "" {
			return false, "E-mail required to create the certificate"
		}

		siteSSLConfig[siteKey].certificate = certificateState{}

		certificatesDir := sitesDir.Get() + putSlash(certificatesDirName)
		fileInfo, statErr = diskStat(certificatesDir)
		if statErr != nil || !fileInfo.IsDir() {
			slog.Info("Creating the certificates directory", "directory", certificatesDir)
			if diskMakeDir(certificatesDir, 0700) != nil { // Made before the lock, by the action that asks for it
				return false, "Error creating the certificates directory"
			}
		}
		certDir := certificatesDir + changeWildcards(siteKey) // One Certbot folder per site: runCertbot removes the previous certificate before each attempt, and keeps the ACME account

		if currentCertDomain == siteKey {
			return false, certificateWait("Please wait, certificate being processed")
		}

		obtainCertificate(siteKey, certDir, siteDir) // Creates a loop of attempts to get a certificate

		if currentCertDomain != siteKey {
			return false, certificateWait("Please wait, certificate busy on " + currentCertDomain)
		}
		return false, certificateWait("Please wait, certificate in process")
	},
	"S": func(fromFile bool, args ...string) (bool, string) {
		argCount := len(args)
		if argCount < 3 || argCount > 5 {
			return false, msgMissingData + " for S"
		}
		// From the panel, 0 or 1 exactly: the action needs the current password when a is "0", and reads it as it is
		// sent. turbo.config keeps any integer: older versions saved there the index of a certificate.
		if !fromFile && args[0] != "0" && args[0] != "1" {
			return false, "Invalid value: 0 or 1"
		}
		value, err := strconv.Atoi(args[0])
		if err != nil {
			return false, "Invalid value"
		}

		if !siteExists(args[1], args[2]) {
			return false, missingSiteMessage(args[2])
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
				siteSSLConfig[configKey].https = true
				if certificatesBeforeApply[configKey] == nil { // Else the one in use stays, and keepCertificatesInUseLocked says so
					slog.Warn("HTTPS is on, but the site's certificate can't be loaded: it is tried again every 30 s", "site", configKey)
				}
				return true, "HTTPS redirect enabled, certificate pending"
			}
			siteSSLConfig[configKey].https = true
			if servers[0] != nil && !httpsListening.Load() {
				safeServerStart(servers[0], tlsConfig) // Opens httpsAddr (:443) with the first certificate
			}

			slog.Info("HTTPS enabled", "site", configKey)
			return true, "HTTPS redirect enabled"
		}

		// If the setting values is 0:
		setSiteCertificate(configKey, nil)
		siteSSLConfig[configKey].https = false
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
			siteSSLConfig[siteKey].wwwToRoot = false
			return true, "Redirect to root disabled"
		}
		if siteSSLConfig[siteKey].rootToWWW {
			return false, "Redirect to www enabled"
		}
		if siteKey == "*" {
			return false, msgAnyHostSiteHasNoWWW
		}
		siteSSLConfig[siteKey].wwwToRoot = true
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
			siteSSLConfig[siteKey].rootToWWW = false
			return true, "Redirect to WWW disabled"
		}
		if siteSSLConfig[siteKey].wwwToRoot {
			return false, "Redirect to root enabled"
		}
		if siteKey == "*" {
			return false, msgAnyHostSiteHasNoWWW
		}
		siteSSLConfig[siteKey].rootToWWW = true
		return true, "Redirect to WWW enabled"
	},
	"Z": func(fromFile bool, args ...string) (bool, string) { // Precompressed files: of the site or the subdomain named
		argCount := len(args)
		if argCount < 3 || argCount > 5 {
			return false, msgMissingData + " for Z"
		}
		if args[0] != "0" && args[0] != "1" {
			return false, "Invalid value"
		}
		if !siteExists(args[1], args[2]) {
			return false, missingSiteMessage(args[2])
		}
		siteKey := joinedSite(args[2], args[1])
		if _, exists := siteSSLConfig[siteKey]; !exists {
			return false, "No configuration defined"
		}
		if siteSSLConfig[siteKey].precompressed = args[0] == "1"; args[0] == "1" {
			return true, "Precompressed files enabled"
		}
		return true, "Precompressed files disabled"
	},
}

// certificateStaleAfter is the age of a site's certificate files from which they don't count as a certificate in
// use (Certbot's last 90 days): "Create SSL" issues a new one, and "Delete SSL" deletes them.
const certificateStaleAfter = 75 * 24 * time.Hour

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
