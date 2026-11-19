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

// The validators of what a site has: its settings section, its rewrites, MIME types, headers, preprocessors, indexes and
// aliases, as turbo.config and the panel add them and delete them.

import (
	"log/slog"
	"mime"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"turbo/customNetHttp"
	"turbo/internal/expr"
)

// indexPosition reads the position saved for an index, as text ("1", "2"...) or as a JSON number (1, 2...);
// anything else goes last.
var indexPosition = func(value interface{}) int {
	if text, isValue := configNumberOrString(value); isValue {
		if number, err := strconv.Atoi(text); err == nil && number > 0 {
			return number
		}
	}
	return int(^uint(0) >> 1)
}

var subdomainContentCheckers = map[string]func(bool, interface{}, bool, ...string) (bool, string){ // Subdomains content check
	"!": func(printErrors bool, configData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // SSLs check
		if len(siteKeys) != 2 {
			return false, msgMissingData + " for configurations"
		}
		mapData, isMap := configData.(map[string]interface{})
		if !isMap {
			return false, "Invalid configuration data"
		}

		if isFromFile { // A setting written with another name ("s" for "S") was lost without a word, the site's HTTPS with it
			for _, key := range sortedKeys(mapData) {
				if _, known := siteSSLSettingCheckers[key]; !known {
					slog.Warn("turbo.config site setting ignored: no setting of a site has that name", "site", siteKeys[0], "subdomain", siteKeys[1], "setting", key)
				}
			}
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
			return false, missingSiteMessage(siteKeys[1])
		}

		for _, targetURI := range sortedKeys(mapData) {
			rawTarget := mapData[targetURI]
			strVal, isString := rawTarget.(string)
			if !isString {
				if printErrors {
					return false, "Invalid rewrite value"
				}
				discardedFromFile(isFromFile, "rewrite", joinedSite(siteKeys[1], siteKeys[0]), targetURI, "the target is not a text")
				continue
			}

			if !isFromFile { // turbo.config keeps the values decoded
				targetURI = replaceURIChars(targetURI)
			}
			current, isExisting := sitesMap[siteKeys[0]][siteKeys[1]][targetURI]
			valueLen := len(targetURI)
			if valueLen < 1 || strings.Contains(targetURI, "//") || strings.Contains(targetURI, "..") || targetURI[0] != '/' {
				if printErrors {
					return false, "Invalid relative address"
				}
				discardedFromFile(isFromFile, "rewrite", joinedSite(siteKeys[1], siteKeys[0]), targetURI, `the path it takes must start with "/", without "//" nor ".."`)
				continue
			}
			if valueLen > 128 {
				if printErrors {
					return false, "Relative address too long"
				}
				discardedFromFile(isFromFile, "rewrite", joinedSite(siteKeys[1], siteKeys[0]), targetURI, "the path it takes is longer than 128 bytes")
				continue
			}
			if !isFromFile {
				strVal = replaceURIChars(strVal)
			}
			if source, isExpression := expressionSource(normalizedExpression(strVal)); isExpression {
				// Kept with the mode X. Compiled now, and what it gives is checked as it is placed (choose). One of
				// turbo.config that doesn't compile is kept as it is, and the paths it takes answer 500 until it is
				// fixed: dropped, they would be served as they were named.
				program, err := compileExpression(expr.RewriteTarget, "", source)
				if err != nil {
					if printErrors {
						return false, err.Error()
					}
					if !isFromFile {
						continue
					}
					slog.Warn("turbo.config rewrite whose expression doesn't compile: the paths it takes answer 500", "site", siteKeys[0], "subdomain", siteKeys[1], "source", targetURI, "reason", err.Error())
				} else if program.LabelsBeforeOneLabel() && !(isExisting && current == "X"+source) { // As for a target written as a text
					slog.Warn("Rewrite whose host is SUBDOMAIN and one label: under a wildcard subdomain, the visitor chooses the whole domain of the redirection. Write the rest of the host as a domain of the site", "site", joinedSite(siteKeys[1], siteKeys[0]), "source", targetURI)
				}
				if isExisting && current == "X"+source {
					if printErrors {
						return false, "Rewrite unchanged"
					}
					continue
				}
				sitesMap[siteKeys[0]][siteKeys[1]][targetURI] = "X" + source
				if printErrors {
					if !isExisting {
						return true, "Rewrite created"
					}
					return true, "Rewrite changed"
				}
				continue
			}
			valueLen = len(strVal)
			if valueLen < 1 || strings.Contains(strVal, "..") {
				if printErrors {
					return false, "Invalid rewrite"
				}
				discardedFromFile(isFromFile, "rewrite", joinedSite(siteKeys[1], siteKeys[0]), targetURI, `the target is empty or has ".."`)
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
			if schemeMode != "N" && (strVal == "" || strings.IndexByte(redirectHostStarters, strVal[0]) != -1) { // "https://" alone, or with "/" or "\" after it, would redirect anywhere
				if printErrors {
					return false, "The target needs a host"
				}
				if isFromFile {
					slog.Warn("Rewrite discarded: the target has no host", "site", siteKeys[0], "subdomain", siteKeys[1], "source", targetURI)
				}
				continue
			}
			if problem := textTargetProblem(schemeMode + strVal); problem != "" { // As an expression's, and before unknownPlaceholder: {TURBO_CURRENT_DIR} is no keyword of a rewrite
				if printErrors {
					return false, problem
				}
				if isFromFile {
					slog.Warn("Rewrite discarded: "+problem, "site", siteKeys[0], "subdomain", siteKeys[1], "source", targetURI)
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
				discardedFromFile(isFromFile, "rewrite", joinedSite(siteKeys[1], siteKeys[0]), targetURI, `the target has "//"`)
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
				discardedFromFile(isFromFile, "rewrite", joinedSite(siteKeys[1], siteKeys[0]), targetURI, "the target is longer than 512 bytes")
				continue
			}
			if labelsBeforeOneLabel(schemeMode + strVal) {
				slog.Warn("Rewrite whose host is {SUBDOMAIN} and one label: under a wildcard subdomain, the visitor chooses the whole domain of the redirection. Write the rest of the host as a domain of the site", "site", joinedSite(siteKeys[1], siteKeys[0]), "source", targetURI)
			}
			if labelsBeforeAnAliasKeyword(schemeMode + strVal) {
				slog.Warn("Rewrite whose host is {SUBDOMAIN} and {FIRST_DOMAIN} or {FIRST_SITE}: these give nothing for a request that comes through no alias and no wildcard domain, and such a request answers 500", "site", joinedSite(siteKeys[1], siteKeys[0]), "source", targetURI)
			}
			// Compared as it is kept: decoded, and with its scheme in a letter. It was compared as written, so the
			// same target answered "Rewrite changed", and a target without its scheme "Rewrite unchanged".
			if isExisting && current == schemeMode+strVal {
				if printErrors {
					return false, "Rewrite unchanged"
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
			return false, missingSiteMessage(siteKeys[1])
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
			// ".HTML" and "html" are the same extension: the first one is kept, as with the headers. The second
			// replaced it without a word.
			if _, repeated := mimeTypes[siteKeys[1]][strings.TrimPrefix(ext, ".")]; isFromFile && repeated {
				slog.Warn("MIME repeated in turbo.config (with a dot or in other case): the first one is kept", "site", siteKeys[1], "extension", writtenExt)
				continue
			}
			mimeType, isString := rawMIME.(string)
			if !isString {
				if printErrors {
					return false, "Invalid MIME value"
				}
				discardedFromFile(isFromFile, "MIME type", siteKeys[1], writtenExt, "the type is not a text")
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
				discardedFromFile(isFromFile, "MIME type", siteKeys[1], writtenExt, "the extension is longer than 12 bytes")
				continue
			}
			if extLen > 0 && !extChars(ext) {
				if printErrors {
					return false, "Invalid extension"
				}
				discardedFromFile(isFromFile, "MIME type", siteKeys[1], writtenExt, `the extension is what follows the last dot of a name, with letters, digits and "-"`)
				continue
			}
			if extLen > 0 && ext[0] == '.' {
				ext = ext[1:]
			}
			if mimeLen := len(mimeType); mimeLen < 4 || mimeLen > 128 {
				if printErrors {
					return false, "MIME too long or too short"
				}
				discardedFromFile(isFromFile, "MIME type", siteKeys[1], writtenExt, "the type has less than 4 bytes or more than 128")
				continue
			}
			_, _, parseErr := mime.ParseMediaType(mimeType)
			if parseErr != nil {
				if printErrors {
					return false, "Invalid MIME"
				}
				discardedFromFile(isFromFile, "MIME type", siteKeys[1], writtenExt, "the type isn't a media type: "+parseErr.Error())
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
			return false, missingSiteMessage(siteKeys[1])
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
				discardedFromFile(isFromFile, "header", siteKeys[1], header, "the value is not a text")
				continue
			}

			var existed bool
			if !isFromFile {
				value = replaceURIChars(value)
			}
			value = normalizedExpression(value)
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
				discardedFromFile(isFromFile, "header", siteKeys[1], header, "the name has characters a header can't have")
				continue
			}
			if nameLen := len(header); nameLen < 1 || nameLen > maxHeaderKeyLength {
				if printErrors {
					return false, "Header too long or too short"
				}
				discardedFromFile(isFromFile, "header", siteKeys[1], header, "the name is empty or too long")
				continue
			}
			if source, isExpression := expressionSource(value); isExpression {
				// An expression is compiled now: what it gives is checked for each request. One of turbo.config that
				// doesn't compile is kept as it is, and what the site serves answers 500 until it is fixed: dropped, the
				// site would go out without a header that may be what keeps its pages safe.
				if _, err := compileExpression(expr.HeaderValue, header, source); err != nil {
					if printErrors {
						return false, err.Error()
					}
					if !isFromFile {
						continue
					}
					slog.Warn("turbo.config header whose expression doesn't compile: what the site serves answers 500. A value that starts with = is an expression: a text that starts with it is written as one, between quotes", "site", siteKeys[1], "header", header, "reason", err.Error())
				}
			} else if valueLen := len(value); valueLen < 1 || valueLen > maxHeaderValueLength {
				if printErrors {
					return false, "Content too long or too short"
				}
				discardedFromFile(isFromFile, "header", siteKeys[1], header, "the value is empty or longer than "+strconv.Itoa(maxHeaderValueLength)+" bytes")
				continue
			}
			if reservedResponseHeaders[customNetHttp.CanonicalHeaderKey(header)] {
				if printErrors {
					return false, "Header reserved"
				}
				if isFromFile {
					slog.Warn("turbo.config header discarded: Header reserved, HTTP sets it", "site", siteKeys[1], "header", header)
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
			return false, missingSiteMessage(siteKeys[1])
		}
		if siteKeys[1] != "" {
			siteKeys[1] += "." + siteKeys[0]
		} else {
			siteKeys[1] = siteKeys[0]
		}

		if _, exists := preprocessors[siteKeys[1]]; !exists {
			return false, "No preprocessors defined"
		}

		defer closeIntendedExtensions(siteKeys[1]) // Once every entry is read: one that can be used wins, in any order
		for _, writtenExt := range sortedKeys(entries) {
			rawValue := entries[writtenExt]
			ext := strings.ToLower(writtenExt) // Looked up in lower case (ext): ".PHP" is also preprocessed
			site := siteKeys[1]
			if _, repeated := preprocessors[site][strings.TrimPrefix(ext, ".")]; repeated && isFromFile {
				slog.Warn("Preprocessor repeated in turbo.config (in upper or lower case): the first one is kept", "site", site, "extension", writtenExt)
				continue
			}
			// From turbo.config, an entry that can't be used is kept, so that saving doesn't lose it, and the extension
			// it was meant for answers 500: never the source of the files it should run. Kept under its own key, an
			// entry such as "php " or "blade.php" matched no file, and the files of php were served as text.
			keepFailing := func(value string, reason string) {
				if value == "" { // An empty value would mean no preprocessor
					value = invalidPreprocessorMark
				}
				key := failingPreprocessorKey(ext)
				preprocessors[site][key] = value
				closed, closes := key, true // The extension whose files answer 500: its own, if its key is one
				if !preprocessorKeyIsExtension(key) {
					closed = intendedExtension(key)
					closes = closed != ""
				}
				if !closes {
					slog.Warn("turbo.config preprocessor that can't be used, and whose key is no extension: it matches no file", "site", site, "entry", writtenExt, "reason", reason)
					return
				}
				slog.Warn("turbo.config preprocessor that can't be used: the files of its extension answer 500 until it is fixed", "site", site, "entry", writtenExt, "extension", closed, "reason", reason)
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
				dotInside := strings.IndexByte(strings.TrimPrefix(ext, "."), '.') != -1
				switch {
				case extLen > 12:
					reason = "Extension too long"
				case dotInside:
					reason = "Invalid extension: it is what follows the last dot of a name (php, not blade.php)"
				}
				if printErrors {
					return false, reason
				}
				keepFailing(invalidPreprocessorMark+value, reason)
				continue
			}
			ext = strings.TrimPrefix(ext, ".")

			var existed bool
			if current, exists := preprocessors[site][ext]; exists && current != closedExtensionMark { // Closed by another entry: this one opens it
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
			return false, missingSiteMessage(siteKeys[1])
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
				discardedFromFile(isFromFile, "index", siteKeys[1], name, "the name is empty or longer than 48 bytes")
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
			return false, missingSiteMessage(siteKeys[1])
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
				discardedFromFile(isFromFile, "alias", siteKeys[1], alias, "an alias is a host, without wildcards")
				continue
			}
			validHost, hostMsg := hostOk(alias, false)
			if !validHost {
				if printErrors {
					return false, hostMsg
				}
				discardedFromFile(isFromFile, "alias", siteKeys[1], alias, "it isn't a host name in lower case ("+hostMsg+")")
				continue
			}
			if siteNamedAsIP(alias) { // Only the site * serves an IP address (host), and then the alias is its host
				if printErrors {
					return false, "Only the site * serves an IP address: an alias " + alias + " would never be reached"
				}
				discardedFromFile(isFromFile, "alias", siteKeys[1], alias, "only the site * serves an IP address")
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

var subdomainContentDeleters = map[string]func(bool, interface{}, ...string) (bool, string){ // Subdomains content deletion check
	"=": func(printErrors bool, rewriteData interface{}, siteKeys ...string) (bool, string) {
		if len(siteKeys) != 2 {
			return false, msgMissingData + " for deleting rewrites"
		}
		entries, isMap := rewriteData.(map[string]interface{})
		if !isMap {
			return false, "Invalid rewrites content"
		}

		if !siteExists(siteKeys[0], siteKeys[1]) {
			return false, missingSiteMessage(siteKeys[1])
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
			return false, missingSiteMessage(siteKeys[1])
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
			return false, missingSiteMessage(siteKeys[1])
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
			// In any case, as addHeader replaces a header written in other capitals: "x-test" deletes "X-Test"
			deleted := false
			for existing := range customHeaders[siteKeys[1]] {
				if strings.EqualFold(existing, header) {
					delete(customHeaders[siteKeys[1]], existing)
					deleted = true
				}
			}
			if !deleted {
				if printErrors {
					return false, "Header not found"
				}
				continue
			}
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
			return false, missingSiteMessage(siteKeys[1])
		}

		if siteKeys[1] != "" {
			siteKeys[1] += "." + siteKeys[0]
		} else {
			siteKeys[1] = siteKeys[0]
		}

		if _, exists := preprocessors[siteKeys[1]]; !exists {
			return false, "No preprocessors defined"
		}

		// What an entry of turbo.config that can't be used closed opens again when that entry is deleted: the mark stayed,
		// and the files of the extension answered 500 for an entry that was nowhere, until Turbo started again.
		defer closeIntendedExtensions(siteKeys[1])
		for ext := range entries {
			ext = strings.ToLower(ext)
			if _, asKept := preprocessors[siteKeys[1]][ext]; !asKept { // An entry that can't be used may be kept with its dot (".")
				ext = strings.TrimPrefix(ext, ".")
			}
			if value, exists := preprocessors[siteKeys[1]][ext]; !exists || value == closedExtensionMark { // Closed by another entry: that one is deleted
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
			return false, missingSiteMessage(siteKeys[1])
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
			return false, missingSiteMessage(siteKeys[1])
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

// reservedResponseHeaders are the headers that HTTP sets for the connection and the length of a body, by their
// canonical names: set by a site, they could cut a response or join it with the next one. A CGI can't set those of
// the connection either (cgiHopByHopHeaders).
var reservedResponseHeaders = map[string]bool{"Content-Length": true, "Transfer-Encoding": true, "Connection": true, "Keep-Alive": true, "Proxy-Connection": true, "Te": true, "Trailer": true, "Upgrade": true}

// headerSetCaseInsensitive reports whether headers has name, in any case.
func headerSetCaseInsensitive(headers map[string]string, name string) bool {
	for header := range headers {
		if strings.EqualFold(header, name) {
			return true
		}
	}
	return false
}

// discardedFromFile logs an entry of turbo.config (or of a site kept without its folder, which comes back) that is
// dropped because it can't be used: never without a word, as a rewrite that kept a folder private, or a header that
// kept a site's pages safe, was. From the panel (isFromFile false), the action answers the reason instead.
func discardedFromFile(isFromFile bool, list string, site string, entry string, reason string) {
	if !isFromFile {
		return
	}
	if len(entry) > 128 {
		entry = entry[:128] + "…"
	}
	slog.Warn("turbo.config entry discarded: "+reason, "list", list, "site", site, "entry", entry)
}

// invalidPreprocessorMark starts the value of a preprocessor of turbo.config whose extension or type is wrong: no
// value written can have a NUL, so it only marks it (the rest is the value as written, kept for saving).
const invalidPreprocessorMark = "\x00"

// closedExtensionMark is the value of the extension that an entry of turbo.config that can't be used was meant for,
// when no entry of that extension can be used: its files answer 500. It isn't written: it comes from that entry, which
// is, each time the site is read (createSubdomainData leaves it out).
const closedExtensionMark = invalidPreprocessorMark + invalidPreprocessorMark

// intendedExtension is the extension that the key of a preprocessor of turbo.config that can't be used was meant for:
// what follows its last dot, in lower case, once what isn't a letter or a digit is taken from its ends ("php ", "php.",
// "php,", "*.PHP", "blade.php" and a php with an invisible character after it are php), or "" if that is no extension
// either (a space or a letter outside ASCII inside it).
func intendedExtension(written string) string {
	edges := func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }
	ext := strings.TrimFunc(strings.ToLower(written), edges)
	if dot := strings.LastIndexByte(ext, '.'); dot != -1 {
		ext = strings.TrimFunc(ext[dot+1:], edges)
	}
	if len(ext) > 12 || !extChars(ext) {
		return ""
	}
	return ext
}

// preprocessorKeyIsExtension reports whether the key of a preprocessor, as it is kept, is an extension that files
// have: the empty one, of the files without an extension, among them.
func preprocessorKeyIsExtension(key string) bool {
	return key == "" || len(key) <= 12 && key[0] != '.' && extChars(key)
}

// failingPreprocessorKey is the key under which an entry of turbo.config that can't be used is kept, from its key as
// written in lower case: without its first dot, as the extensions are kept, unless nothing else is left ("." alone
// isn't the empty extension: kept as such, it closed the files without an extension, and was saved as "", which the
// next start took for a preprocessor of all of them).
func failingPreprocessorKey(ext string) string {
	if key := strings.TrimPrefix(ext, "."); key != "" || ext == "" {
		return key
	}
	return ext
}

// closeIntendedExtensions marks, among the preprocessors of site, the extensions that its entries that can't be used
// were meant for (intendedExtension), when their keys are no extension and no other entry has that extension, and takes
// the mark from those that no entry closes any more. Callers hold the global lock.
func closeIntendedExtensions(site string) {
	entries := preprocessors[site]
	closing := map[string]bool{}
	for key, value := range entries {
		if value == closedExtensionMark {
			delete(entries, key)
		} else if !preprocessorKeyIsExtension(key) {
			if intended := intendedExtension(key); intended != "" {
				closing[intended] = true
			}
		}
	}
	for intended := range closing {
		if _, kept := entries[intended]; !kept {
			entries[intended] = closedExtensionMark
		}
	}
}

// preprocessorCommand returns the executable a preprocessor value runs ("[<mode>>]<path>", as written in
// turbo.config or addPreprocessor, with {TURBO_CURRENT_DIR} replaced), or why it can't run. The limit of 128
// characters is for the path as written, without the mode.
func preprocessorCommand(value string) (executable string, problem string) {
	_, executable, problem = preprocessorParts(value)
	return executable, problem
}

// preprocessorParts returns the mode a preprocessor value runs its scripts with ("cgi" without one, in any case), and
// its executable, as preprocessorCommand; or why it can't run, a mode this binary doesn't have among the reasons.
func preprocessorParts(value string) (mode preprocessorMode, executable string, problem string) {
	if value == closedExtensionMark {
		return nil, "", "an entry of turbo.config meant for this extension can't be used"
	}
	if strings.HasPrefix(value, invalidPreprocessorMark) {
		return nil, "", "invalid turbo.config entry"
	}
	name, path, hasMode := strings.Cut(value, ">")
	if !hasMode {
		name, path = "cgi", value
	}
	if pathLen := len(path); pathLen < 1 || pathLen > 128 {
		return nil, "", "Preprocessor path too long or too short"
	}
	if mode = preprocessorModes[strings.ToLower(name)]; mode == nil {
		return nil, "", "Invalid preprocessor protocol."
	}
	placeholder := "{" + currentDirPlaceholder + "}"
	if !strings.Contains(path, placeholder) {
		return mode, path, "" // Most values: the working directory isn't asked for on each request to a CGI
	}
	return mode, strings.Replace(path, placeholder, currentDir(), 1), ""
}
