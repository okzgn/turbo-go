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
	"encoding/json"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// configSchema is the turbo.config schema this version writes, as "^": {"v": "<schema>"}. A file without
// "^" has schema 1 (before the version key).
//
//	2: CIL and CIS in milliseconds (were units of 10 ms); "U" and "PH" (password hash) saved in "."; each
//	   index of "-" saved with its position ("1", "2"...) instead of ""; "PA" (where the panel answers) in "."
const configSchema = 2

// configSchemaRead is the schema of the turbo.config last read; guarded by globalMutex.
var configSchemaRead = configSchema

// migrateConfig converts in memory a turbo.config read with an older schema to the current one and returns
// the schema it had. It never rewrites the file. A later schema is left as is: what is understood loads.
func migrateConfig(raw map[string]map[string]interface{}, configBytes []byte) (from int) {
	from = 1
	if version, isString := raw["^"]["v"].(string); isString {
		if number, err := strconv.Atoi(version); err == nil && number > 0 {
			from = number
		}
	}
	if from < 2 {
		for _, key := range []string{"CIL", "CIS"} {
			if value, isString := raw["."][key].(string); isString {
				if units, err := strconv.ParseInt(value, 10, 64); err == nil { // units of 10 ms
					raw["."][key] = strconv.FormatInt(units*10, 10)
				}
			}
		}
		// Indexes are tried in the order they were added: the order of the file, which a Go map loses.
		for siteAndSubdomain, names := range indexOrder(configBytes) {
			site, subdomain, _ := strings.Cut(siteAndSubdomain, "\x00")
			subdomainData, isMap := raw[site][subdomain].(map[string]interface{})
			if !isMap {
				continue
			}
			if indexes, isMap := subdomainData["-"].(map[string]interface{}); isMap {
				for position, name := range names {
					indexes[name] = strconv.Itoa(position + 1)
				}
			}
		}
	}
	return from
}

// configSchemaOf returns the schema of a turbo.config file (1 without "^", or when it can't be read).
func configSchemaOf(configBytes []byte) int {
	var raw map[string]map[string]interface{}
	if json.Unmarshal(configBytes, &raw) != nil {
		return 1
	}
	return max(migrateConfig(raw, configBytes), 1)
}

// isSitesDirPointer reports whether a turbo.config only points to another sites directory (just "^" and "M"),
// as saveDefaultConfig leaves it in startDir.
func isSitesDirPointer(configBytes []byte) bool {
	var raw map[string]map[string]interface{}
	if json.Unmarshal(configBytes, &raw) != nil {
		return false
	}
	for key, values := range raw {
		if key != "^" && key != "." {
			return false
		}
		for setting := range values {
			if key == "." && setting != "M" {
				return false
			}
		}
	}
	return true
}

// indexOrder returns the index names of each "<site>\x00<subdomain>" in the order they appear in turbo.config.
func indexOrder(configBytes []byte) map[string][]string {
	order := make(map[string][]string)
	decoder := json.NewDecoder(bytes.NewReader(configBytes))
	var walk func(keys []string) error
	walk = func(keys []string) error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		switch {
		case isDelimiter && delimiter == '{':
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, _ := keyToken.(string)
				if len(keys) == 3 && keys[2] == "-" {
					order[keys[0]+"\x00"+keys[1]] = append(order[keys[0]+"\x00"+keys[1]], key)
				}
				if err = walk(append(keys[:len(keys):len(keys)], key)); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case isDelimiter && delimiter == '[':
			for decoder.More() {
				if err = walk(keys); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		}
		return nil
	}
	walk(nil)
	return order
}

// saveDefaultConfig writes turbo.config. The first time a migrated file is saved, the original is copied to
// turbo.config.v<schema>.bak. Callers hold the global lock.
func saveDefaultConfig() bool {
	configPath := sitesDir.Get() + configFileName
	if configSchemaRead < configSchema {
		backupPath := configPath + ".v" + strconv.Itoa(configSchemaRead) + ".bak"
		if original, err := os.ReadFile(configPath); err == nil && !fileExists(backupPath) { // #nosec G304 -- path under the sites directory chosen by the administrator (TURBO_DIR or M)
			if err = os.WriteFile(backupPath, original, 0600); err != nil { // #nosec G703 -- turbo.config backup next to the original, path under the sites directory chosen by the administrator (TURBO_DIR or M)
				slog.Error("No se puede guardar la copia de turbo.config", "archivo", backupPath, "error", err)
				return false
			}
		}
	}
	config := createDefaultConfig(true, false, true)
	err := os.WriteFile(configPath, []byte("{\"^\":{\"v\":\""+strconv.Itoa(configSchema)+"\"},"+config[1:]), 0600)
	if err != nil {
		slog.Error("No se puede guardar turbo.config", "archivo", configPath, "error", err)
		return false
	}
	configSchemaRead = configSchema
	if dir := sitesDir.Get(); dir != startDir { // Turbo starts reading startDir: leave there where the sites are
		pointerPath := startDir + configFileName
		if original, err := os.ReadFile(pointerPath); err == nil && !isSitesDirPointer(original) {
			backupPath := pointerPath + ".v" + strconv.Itoa(configSchemaOf(original)) + ".bak"
			if !fileExists(backupPath) {
				if err = os.WriteFile(backupPath, original, 0600); err != nil { // #nosec G703 -- turbo.config backup next to the original, path under the sites directory chosen by the administrator (TURBO_DIR or M)
					slog.Error("No se puede guardar la copia de turbo.config", "archivo", backupPath, "error", err)
					return false
				}
			}
		}
		pointer := "{\"^\":{\"v\":\"" + strconv.Itoa(configSchema) + "\"},\".\":{\"M\":\"" + changeChars(true, dir, charEscapeLists['J']) + "\"}}"
		if err = os.WriteFile(pointerPath, []byte(pointer), 0600); err != nil {
			slog.Error("No se puede guardar turbo.config", "archivo", pointerPath, "error", err)
			return false
		}
	}
	return true
}

func createDefaultConfig(excludeSubdomains bool, includeFixedKeys bool, includeCredentials bool) string {
	// a: to not include subdomains list on response
	// b: to set as objects fixed keys on charReplacements and httpResponses
	// c: to include the username and the password hash (only when saving)
	credentials := ""
	if includeCredentials {
		credentials = ",\"U\":\"" + changeChars(true, panelUser.Get(), charEscapeLists['J']) + "\",\"PH\":\"" + panelPasswordHash.Get() + "\""
	}
	jsonBuilder := ""
	delimiter := "\""
	for siteKey := range sitesMap {
		jsonBuilder += delimiter + siteKey + "\":"
		if !excludeSubdomains {
			jsonBuilder += "{" + createSiteSettingsList(siteKey) + "}"
		} else {
			jsonBuilder += createSubdomainsList(true, siteKey)
		}
		delimiter = ",\""
	}

	jsonBuilder += delimiter + "_\":{" // Chars to encode list
	delimiter = "\""
	for mapKey, replacement := range charReplacements {
		jsonBuilder += delimiter + changeChars(true, mapKey, charEscapeLists['J']) + "\":"
		if _, fixed := fixedCharReplacements[mapKey]; fixed && includeFixedKeys {
			jsonBuilder += "{\"f\":\"" + changeChars(true, replacement, charEscapeLists['J']) + "\"}"
		} else {
			jsonBuilder += "\"" + changeChars(true, replacement, charEscapeLists['J']) + "\""
		}
		delimiter = ",\""
	}

	jsonBuilder += "},\"@\":{" // Denied IPs list
	delimiter = "\""
	for mapKey, until := range deniedIPList() {
		jsonBuilder += delimiter + changeChars(true, mapKey, charEscapeLists['J']) + "\":\"" + changeChars(true, strconv.FormatInt(until, 10), charEscapeLists['J']) + "\""
		delimiter = ",\""
	}

	jsonBuilder += "},\"#\":{" // Http codes responses list
	delimiter = "\""
	for mapKey, template := range *httpResponses.Load() {
		jsonBuilder += delimiter + changeChars(true, strconv.Itoa(mapKey), charEscapeLists['J']) + "\":"
		if _, fixed := fixedHTTPResponses[mapKey]; fixed && includeFixedKeys {
			jsonBuilder += "{\"f\":\"" + changeChars(true, template, charEscapeLists['J']) + "\"}"
		} else {
			jsonBuilder += "\"" + changeChars(true, template, charEscapeLists['J']) + "\""
		}
		delimiter = ",\""
	}

	return "{" + jsonBuilder + "},\".\":{\"M\":\"" + changeChars(true, sitesDir.Get(), charEscapeLists['J']) + "\",\"PA\":\"" + changeChars(true, panelAccess.Load().setting, charEscapeLists['J']) + "\",\"RT\":\"" + serverTimeLimits.Load().RT.String() + "\",\"RHT\":\"" + serverTimeLimits.Load().RHT.String() + "\",\"WT\":\"" + serverTimeLimits.Load().WT.String() + "\",\"IT\":\"" + serverTimeLimits.Load().IT.String() + "\",\"MUB\":\"" + strconv.FormatInt(maxURILength.Load(), 10) + "\",\"MHB\":\"" + strconv.FormatInt(maxHeaderBytes.Load(), 10) + "\",\"MBB\":\"" + strconv.FormatInt(maxBodySize.Load(), 10) + "\",\"CIL\":\"" + strconv.FormatInt(serverRequestLimits[0]/int64(time.Millisecond), 10) + "\",\"CIS\":\"" + strconv.FormatInt(serverRequestLimits[1]/int64(time.Millisecond), 10) + "\",\"CII\":\"" + strconv.FormatInt(serverRequestLimits[2], 10) + "\"" + credentials + "}}"
}

func createSubdomainsList(excludeSettings bool, domain string) string {
	jsonBuilder := ""
	delimiter := "\""
	for subdomain := range sitesMap[domain] {
		jsonBuilder += delimiter + subdomain + "\":"
		if !excludeSettings {
			if subdomain != "" {
				subdomain += "." + domain
				jsonBuilder += "{" + createSiteSettingsList(subdomain) + "}" // All subdomains & domains in the frontend need to show if SSL is on
			} else {
				subdomain = domain
				jsonBuilder += "{" + createSiteAliasList(subdomain) + "," + createSiteSettingsList(subdomain) + "}"
			}
		} else {
			jsonBuilder += createSubdomainData(domain, subdomain)
		}
		delimiter = ",\""
	}
	return "{" + jsonBuilder + "}"
}

func createSubdomainData(domain string, subdomain string) string {
	var extKey string
	var siteKey string
	var delimiter string
	var routeKey string
	if subdomain != "" {
		siteKey = subdomain + "." + domain
	} else {
		siteKey = domain
	}

	jsonBuilder := "\"=\":{"
	delimiter = "\""
	for routeKey = range sitesMap[domain][subdomain] {
		switch sitesMap[domain][subdomain][routeKey][0] {
		case 'H':
			extKey = "http://"
		case 'S':
			extKey = "https://"
		default:
			extKey = ""
		}
		jsonBuilder += delimiter + changeChars(true, routeKey, charEscapeLists['J']) + "\":\"" + extKey + changeChars(true, sitesMap[domain][subdomain][routeKey][1:], charEscapeLists['J']) + "\""
		delimiter = ",\""
	}

	jsonBuilder += "},\"$\":{"
	delimiter = "\""
	for extKey = range mimeTypes[siteKey] {
		jsonBuilder += delimiter + extKey + "\":\"" + changeChars(true, mimeTypes[siteKey][extKey], charEscapeLists['J']) + "\""
		delimiter = ",\""
	}
	jsonBuilder += "},\".\":{"
	delimiter = "\""
	for extKey = range customHeaders[siteKey] {
		jsonBuilder += delimiter + extKey + "\":\"" + changeChars(true, customHeaders[siteKey][extKey], charEscapeLists['J']) + "\""
		delimiter = ",\""
	}
	jsonBuilder += "},\"?\":{"
	delimiter = "\""
	for extKey = range preprocessors[siteKey] {
		jsonBuilder += delimiter + extKey + "\":\"" + changeChars(true, preprocessors[siteKey][extKey], charEscapeLists['J']) + "\""
		delimiter = ",\""
	}
	jsonBuilder += "},\"-\":{"
	delimiter = "\""
	for position, indexName := range orderedIndexes(siteKey) {
		jsonBuilder += delimiter + changeChars(true, indexName, charEscapeLists['J']) + "\":\"" + strconv.Itoa(position+1) + "\""
		delimiter = ",\""
	}
	jsonBuilder += "}," + createSiteAliasList(siteKey)
	jsonBuilder += "," + createSiteSettingsList(siteKey)
	return "{" + jsonBuilder + "}"
}

func createSiteAliasList(siteKey string) string {
	jsonBuilder := "{"
	delimiter := "\""
	for aliasName, mappedSite := range domainAliases {
		if siteKey == mappedSite {
			jsonBuilder += delimiter + aliasName + "\":\"\""
			delimiter = ",\""
		}
	}
	jsonBuilder += "}"
	return "\"&\":" + jsonBuilder
}

func createSiteSettingsList(siteKey string) string {
	jsonBuilder := "{"
	delimiter := "\""
	//var settingName string
	var encodedValue string
	for settingName, settingVal := range siteSSLConfig[siteKey] {
		boolVal, isBool := settingVal.(bool)
		if !isBool {
			intVal, isInt := settingVal.(int)
			if !isInt {
				stringVal, isString := settingVal.(string)
				if !isString {
					continue
				}
				encodedValue = url.QueryEscape(stringVal)
			} else {
				encodedValue = strconv.Itoa(intVal)
			}
		} else {
			if boolVal {
				encodedValue = "1"
			} else {
				encodedValue = "0"
			}
		}
		jsonBuilder += delimiter + settingName + "\":\"" + encodedValue + "\""
		delimiter = ",\""
	}
	jsonBuilder += "}"
	return "\"!\":" + jsonBuilder
}
