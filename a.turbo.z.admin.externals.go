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
	"errors"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
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
	_ = walk(nil) // configBytes was already read as valid JSON
	return order
}

// saveDefaultConfig writes turbo.config, replacing it atomically. A file on disk that isn't valid JSON is
// first copied to turbo.config.invalido.<date>.bak, and the first time a migrated file is saved, the original
// is copied to turbo.config.v<schema>.bak. Callers hold the global lock.
func saveDefaultConfig() bool {
	configPath := sitesDir.Get() + configFileName
	if !backupBeforeSave(configPath, configSchemaRead) {
		return false
	}
	config := createDefaultConfig(true, false, true)
	if err := writeFileAtomic(configPath, []byte("{\"^\":{\"v\":\""+strconv.Itoa(configSchema)+"\"},"+config[1:])); err != nil {
		slog.Error("No se puede guardar turbo.config", "archivo", configPath, "error", err)
		return false
	}
	configSchemaRead = configSchema
	if dir := sitesDir.Get(); dir != startDir { // Turbo starts reading startDir: leave there where the sites are
		pointerPath := startDir + configFileName
		if original, err := os.ReadFile(pointerPath); err == nil && !isSitesDirPointer(original) && !backupBeforeSave(pointerPath, configSchemaOf(original)) { // #nosec G304 -- turbo.config of the start directory
			return false
		}
		pointer := "{\"^\":{\"v\":\"" + strconv.Itoa(configSchema) + "\"},\".\":{\"M\":" + jsonString(dir) + "}}"
		if err := writeFileAtomic(pointerPath, []byte(pointer)); err != nil {
			slog.Error("No se puede guardar turbo.config", "archivo", pointerPath, "error", err)
			return false
		}
	}
	return true
}

// backupBeforeSave copies the turbo.config at configPath before it is overwritten: to
// turbo.config.invalido.<date>.bak if it isn't valid JSON, or to turbo.config.v<schema>.bak (once) if its
// schema is older than the current one. It reports false if a needed copy couldn't be written.
func backupBeforeSave(configPath string, schema int) bool {
	original, err := os.ReadFile(configPath) // #nosec G304 -- path under the sites directory chosen by the administrator (TURBO_DIR or M)
	if err != nil {
		return true // Nothing to keep
	}
	var backupPath string
	switch {
	case !json.Valid(original):
		backupPath = configPath + ".invalido." + time.Now().Format("20060102-150405") + ".bak"
		slog.Warn("turbo.config no es JSON válido: se copia antes de guardar", "copia", backupPath)
	case schema < configSchema:
		backupPath = configPath + ".v" + strconv.Itoa(schema) + ".bak"
		if fileExists(backupPath) {
			return true
		}
	default:
		return true
	}
	if err = os.WriteFile(backupPath, original, 0600); err != nil { // #nosec G703 -- turbo.config backup next to the original, path under the sites directory chosen by the administrator (TURBO_DIR or M)
		slog.Error("No se puede guardar la copia de turbo.config", "archivo", backupPath, "error", err)
		return false
	}
	return true
}

// writeFileAtomic replaces path with data (permissions 0600): it writes a temporary file next to it, syncs it
// and renames it over path, so a failure or a power cut leaves either the old file or the new one. If path is a
// symbolic link, its target is replaced and the link stays (H62).
func writeFileAtomic(path string, data []byte) error {
	if target, err := filepath.EvalSymlinks(path); err == nil {
		path = target
	}
	tempPath := path + ".tmp"
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) // #nosec G304 -- next to turbo.config, under the sites directory chosen by the administrator
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if syncErr := file.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tempPath, path)
	}
	if err != nil {
		os.Remove(tempPath) // #nosec G104 -- best effort: the error that matters is err
	}
	return err
}

// jsonString returns s as a JSON string, quotes included. Unlike json.Marshal, it leaves <, > and & as they
// are, so turbo.config stays readable.
func jsonString(s string) string {
	plain := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == '"' || c == '\\' || c >= 0x7f {
			plain = false
			break
		}
	}
	if plain {
		return "\"" + s + "\""
	}
	var builder strings.Builder
	encoder := json.NewEncoder(&builder)
	encoder.SetEscapeHTML(false)
	encoder.Encode(s) // #nosec G104 -- a string always encodes
	return strings.TrimSuffix(builder.String(), "\n")
}

func createDefaultConfig(excludeSubdomains bool, includeFixedKeys bool, includeCredentials bool) string {
	// a: to not include subdomains list on response
	// b: to set as objects fixed keys on charReplacements and httpResponses
	// c: to include the username and the password hash (only when saving)
	credentials := ""
	if includeCredentials {
		credentials = ",\"U\":" + jsonString(panelUser.Get()) + ",\"PH\":" + jsonString(panelPasswordHash.Get())
	}
	var jsonBuilder strings.Builder
	delimiter := ""
	for siteKey := range sitesMap {
		jsonBuilder.WriteString(delimiter + jsonString(siteKey) + ":")
		if !excludeSubdomains {
			jsonBuilder.WriteString("{" + createSiteSettingsList(siteKey) + "}")
		} else {
			jsonBuilder.WriteString(createSubdomainsList(true, siteKey))
		}
		delimiter = ","
	}

	jsonBuilder.WriteString(delimiter + "\"_\":{") // Chars to encode list
	delimiter = ""
	for mapKey, replacement := range charReplacements {
		jsonBuilder.WriteString(delimiter + jsonString(mapKey) + ":")
		if _, fixed := fixedCharReplacements[mapKey]; fixed && includeFixedKeys {
			jsonBuilder.WriteString("{\"f\":" + jsonString(replacement) + "}")
		} else {
			jsonBuilder.WriteString(jsonString(replacement))
		}
		delimiter = ","
	}

	jsonBuilder.WriteString("},\"@\":{") // Denied IPs list
	delimiter = ""
	for mapKey, until := range deniedIPList() {
		jsonBuilder.WriteString(delimiter + jsonString(mapKey) + ":\"" + strconv.FormatInt(until, 10) + "\"")
		delimiter = ","
	}

	jsonBuilder.WriteString("},\"#\":{") // Http codes responses list
	delimiter = ""
	for mapKey, template := range *httpResponses.Load() {
		jsonBuilder.WriteString(delimiter + "\"" + strconv.Itoa(mapKey) + "\":")
		if _, fixed := fixedHTTPResponses[mapKey]; fixed && includeFixedKeys {
			jsonBuilder.WriteString("{\"f\":" + jsonString(template) + "}")
		} else {
			jsonBuilder.WriteString(jsonString(template))
		}
		delimiter = ","
	}

	return "{" + jsonBuilder.String() + "},\".\":{\"M\":" + jsonString(sitesDir.Get()) + ",\"PA\":" + jsonString(panelAccess.Load().setting) + ",\"RT\":\"" + serverTimeLimits.Load().RT.String() + "\",\"RHT\":\"" + serverTimeLimits.Load().RHT.String() + "\",\"WT\":\"" + serverTimeLimits.Load().WT.String() + "\",\"IT\":\"" + serverTimeLimits.Load().IT.String() + "\",\"MUB\":\"" + strconv.FormatInt(maxURILength.Load(), 10) + "\",\"MHB\":\"" + strconv.FormatInt(maxHeaderBytes.Load(), 10) + "\",\"MBB\":\"" + strconv.FormatInt(maxBodySize.Load(), 10) + "\",\"CIL\":\"" + strconv.FormatInt(serverRequestLimits[0]/int64(time.Millisecond), 10) + "\",\"CIS\":\"" + strconv.FormatInt(serverRequestLimits[1]/int64(time.Millisecond), 10) + "\",\"CII\":\"" + strconv.FormatInt(serverRequestLimits[2], 10) + "\",\"CGL\":\"" + strconv.FormatInt(globalRequestLimit.Load(), 10) + "\"" + credentials + "}}"
}

func createSubdomainsList(excludeSettings bool, domain string) string {
	var jsonBuilder strings.Builder
	delimiter := ""
	for subdomain := range sitesMap[domain] {
		jsonBuilder.WriteString(delimiter + jsonString(subdomain) + ":")
		if !excludeSettings {
			if subdomain != "" {
				subdomain += "." + domain
				jsonBuilder.WriteString("{" + createSiteSettingsList(subdomain) + "}") // All subdomains & domains in the frontend need to show if SSL is on
			} else {
				subdomain = domain
				jsonBuilder.WriteString("{" + createSiteAliasList(subdomain) + "," + createSiteSettingsList(subdomain) + "}")
			}
		} else {
			jsonBuilder.WriteString(createSubdomainData(domain, subdomain))
		}
		delimiter = ","
	}
	return "{" + jsonBuilder.String() + "}"
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

	var jsonBuilder strings.Builder
	jsonBuilder.WriteString("\"=\":{")
	delimiter = ""
	for routeKey = range sitesMap[domain][subdomain] {
		switch sitesMap[domain][subdomain][routeKey][0] {
		case 'H':
			extKey = "http://"
		case 'S':
			extKey = "https://"
		default:
			extKey = ""
		}
		jsonBuilder.WriteString(delimiter + jsonString(routeKey) + ":" + jsonString(extKey+sitesMap[domain][subdomain][routeKey][1:]))
		delimiter = ","
	}

	jsonBuilder.WriteString("},\"$\":{")
	delimiter = ""
	for extKey = range mimeTypes[siteKey] {
		jsonBuilder.WriteString(delimiter + jsonString(extKey) + ":" + jsonString(mimeTypes[siteKey][extKey]))
		delimiter = ","
	}
	jsonBuilder.WriteString("},\".\":{")
	delimiter = ""
	for extKey = range customHeaders[siteKey] {
		jsonBuilder.WriteString(delimiter + jsonString(extKey) + ":" + jsonString(customHeaders[siteKey][extKey]))
		delimiter = ","
	}
	jsonBuilder.WriteString("},\"?\":{")
	delimiter = ""
	for extKey = range preprocessors[siteKey] {
		jsonBuilder.WriteString(delimiter + jsonString(extKey) + ":" + jsonString(preprocessors[siteKey][extKey]))
		delimiter = ","
	}
	jsonBuilder.WriteString("},\"-\":{")
	delimiter = ""
	for position, indexName := range orderedIndexes(siteKey) {
		jsonBuilder.WriteString(delimiter + jsonString(indexName) + ":\"" + strconv.Itoa(position+1) + "\"")
		delimiter = ","
	}
	jsonBuilder.WriteString("}," + createSiteAliasList(siteKey))
	jsonBuilder.WriteString("," + createSiteSettingsList(siteKey))
	return "{" + jsonBuilder.String() + "}"
}

func createSiteAliasList(siteKey string) string {
	var jsonBuilder strings.Builder
	jsonBuilder.WriteString("{")
	delimiter := ""
	for aliasName, mappedSite := range domainAliases {
		if siteKey == mappedSite {
			jsonBuilder.WriteString(delimiter + jsonString(aliasName) + ":\"\"")
			delimiter = ","
		}
	}
	jsonBuilder.WriteString("}")
	return "\"&\":" + jsonBuilder.String()
}

func createSiteSettingsList(siteKey string) string {
	var jsonBuilder strings.Builder
	jsonBuilder.WriteString("{")
	delimiter := ""
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
		jsonBuilder.WriteString(delimiter + jsonString(settingName) + ":" + jsonString(encodedValue))
		delimiter = ","
	}
	jsonBuilder.WriteString("}")
	return "\"!\":" + jsonBuilder.String()
}

// configFileError is a turbo.config that can't be read (data is nil) or isn't valid JSON. It is never applied:
// Turbo doesn't start with it, and a reload keeps the configuration in use (D11).
type configFileError struct {
	path string
	data []byte
	err  error
}

func (e *configFileError) Error() string { return describeConfigError(e.path, e.data, e.err) }

// configErrorMessage is the message for an error of updateSettings, with a first line that says what Turbo
// does about it: not start (starting), or keep the configuration in use.
func configErrorMessage(err error, starting bool) string {
	var fileErr *configFileError
	if !errors.As(err, &fileErr) {
		return err.Error()
	}
	headline := "turbo.config no es JSON válido"
	if fileErr.data == nil {
		headline = "No se puede leer turbo.config"
	}
	if starting {
		headline += " y Turbo no arranca para no perder la configuración."
	} else {
		headline += ": se mantiene la configuración en uso hasta que se corrija."
	}
	return headline + "\n" + err.Error()
}

// logConfigError logs an error of a periodic updateSettings, if any.
func logConfigError(err error) {
	if err != nil {
		slog.Error(configErrorMessage(err, false))
	}
}

// parseConfig decodes turbo.config into raw. Anything but an object of objects at the top level is an error, as
// a section that couldn't be read would get its defaults (the password among them).
func parseConfig(configBytes []byte, raw *map[string]map[string]interface{}) error {
	*raw = make(map[string]map[string]interface{})
	return json.Unmarshal(configBytes, raw)
}

// configFileProblem returns the error of the turbo.config in dir, if there is one that can't be read or isn't
// valid JSON.
func configFileProblem(dir string) error {
	configPath := dir + configFileName
	if !fileExists(configPath) {
		return nil
	}
	configBytes, err := os.ReadFile(configPath) // #nosec G304 -- turbo.config of a sites directory chosen by the administrator
	if err != nil {
		return &configFileError{path: configPath, err: err}
	}
	var raw map[string]map[string]interface{}
	if err = parseConfig(configBytes, &raw); err != nil {
		return &configFileError{path: configPath, data: configBytes, err: err}
	}
	return nil
}

// dropControlChars removes from a turbo.config read from disk the keys and values with control characters or
// invalid UTF-8 (H4), which the panel doesn't accept, logging where they were. Response templates ("#") may
// have tabs and line breaks.
func dropControlChars(raw map[string]map[string]interface{}) {
	var walk func(values map[string]interface{}, where string, whitespace bool)
	walk = func(values map[string]interface{}, where string, whitespace bool) {
		for key, value := range values {
			text, isString := value.(string)
			if !textAllowed(key, false) || (isString && !textAllowed(text, whitespace)) {
				slog.Warn("Valor de turbo.config descartado: caracteres de control o UTF-8 incorrecto", "dónde", strconv.Quote(where+key))
				delete(values, key)
				continue
			}
			if nested, isMap := value.(map[string]interface{}); isMap {
				walk(nested, where+key+" > ", whitespace)
			}
		}
	}
	for section, values := range raw {
		if !textAllowed(section, false) {
			slog.Warn("Sección de turbo.config descartada: caracteres de control o UTF-8 incorrecto", "dónde", strconv.Quote(section))
			delete(raw, section)
			continue
		}
		walk(values, section+" > ", section == "#")
	}
}

// describeConfigError explains where a turbo.config is wrong, so that it can be fixed by hand: the path, the
// line and column of the error with that line and a mark under the column, the cause, and the backups next to
// it (newest first). data is nil if the file couldn't be read.
func describeConfigError(path string, data []byte, err error) string {
	var message strings.Builder
	message.WriteString("  Archivo: " + path + "\n")
	if data == nil {
		message.WriteString("  Error: " + err.Error() + "\n  Compruebe que Turbo tiene permiso para leer el archivo.\n")
		return message.String()
	}
	offset, cause := int64(len(data)), "JSON incorrecto ("+err.Error()+")"
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) {
		offset, cause = syntaxErr.Offset, jsonSyntaxCause(syntaxErr.Error())
	} else if errors.As(err, &typeErr) {
		offset, cause = typeErr.Offset, "se esperaba un objeto {...} y hay un valor de tipo "+typeErr.Value
	}
	position := max(0, min(int(offset)-1, len(data)-1)) // The offset counts the byte that failed
	lineStart := bytes.LastIndexByte(data[:position], '\n') + 1
	lineEnd := len(data)
	if next := bytes.IndexByte(data[position:], '\n'); next != -1 {
		lineEnd = position + next
	}
	line := data[lineStart:lineEnd]
	if position < lineEnd-1 {
		line = bytes.TrimSuffix(line, []byte("\r"))
	}
	lineNumber := bytes.Count(data[:lineStart], []byte("\n")) + 1
	fragment, mark := configLineFragment(line, position-lineStart)
	message.WriteString("  Línea " + strconv.Itoa(lineNumber) + ", columna " + strconv.Itoa(position-lineStart+1) + ": " + cause + "\n")
	message.WriteString("    " + fragment + "\n    " + strings.Repeat(" ", mark) + "^\n")
	backups := configBackups(path)
	if len(backups) == 0 {
		message.WriteString("  Corrija el archivo.\n")
		return message.String()
	}
	message.WriteString("  Corrija el archivo o restaure una copia:\n")
	for _, backup := range backups {
		message.WriteString("    " + backup + "\n")
	}
	return message.String()
}

// configLineFragment returns the line of a turbo.config error with control characters and invalid UTF-8
// escaped, cut to about 120 characters around column (a byte index), and where the mark goes under it.
func configLineFragment(line []byte, column int) (fragment string, mark int) {
	const width = 120
	var pieces []string // One per character of the line, escaped
	errorPiece := -1
	for i := 0; i < len(line); {
		if i >= column && errorPiece == -1 {
			errorPiece = len(pieces)
		}
		r, size := utf8.DecodeRune(line[i:])
		switch {
		case r == '\t':
			pieces = append(pieces, `\t`)
		case r == utf8.RuneError && size == 1, r < 0x20, r == 0x7f:
			pieces = append(pieces, `\x`+strconv.FormatUint(uint64(line[i])|0x100, 16)[1:])
		default:
			pieces = append(pieces, string(r))
		}
		i += size
	}
	if errorPiece == -1 { // After the last character
		errorPiece = len(pieces)
	}
	length := 0
	for _, piece := range pieces {
		length += utf8.RuneCountInString(piece)
	}
	first, last := 0, len(pieces)
	if length > width { // Keep the error near the middle
		first = errorPiece
		for shown := 0; first > 0 && shown < width/2; first-- {
			shown += utf8.RuneCountInString(pieces[first-1])
		}
		last = first
		for shown := 0; last < len(pieces) && shown < width; last++ {
			shown += utf8.RuneCountInString(pieces[last])
		}
	}
	var builder strings.Builder
	if first > 0 {
		builder.WriteString("...")
		mark = 3
	}
	for i := first; i < last; i++ {
		if i < errorPiece {
			mark += utf8.RuneCountInString(pieces[i])
		}
		builder.WriteString(pieces[i])
	}
	if last < len(pieces) {
		builder.WriteString("...")
	}
	return builder.String(), mark
}

// jsonSyntaxCause translates the cause of a JSON syntax error.
func jsonSyntaxCause(message string) string {
	if message == "unexpected end of JSON input" {
		return `el archivo termina antes de cerrar el JSON (falta '}', ']' o '"')`
	}
	causes := []struct{ suffix, cause string }{
		{" in string literal", "carácter no válido %s dentro de una cadena"},
		{" in string escape code", "secuencia de escape no válida (%s) dentro de una cadena"},
		{" looking for beginning of value", "carácter no válido %s donde se esperaba un valor"},
		{" looking for beginning of object key string", "carácter no válido %s donde se esperaba una clave entre comillas"},
		{" after object key:value pair", "carácter no válido %s después de un valor (falta ',' o '}')"},
		{" after object key", "carácter no válido %s después de una clave (falta ':')"},
		{" after array element", "carácter no válido %s después de un elemento (falta ',' o ']')"},
		{" after top-level value", "contenido sobrante (%s) después del final del JSON"},
	}
	if character, found := strings.CutPrefix(message, "invalid character "); found {
		for _, known := range causes {
			if quoted, isKnown := strings.CutSuffix(character, known.suffix); isKnown {
				return strings.Replace(known.cause, "%s", quoted, 1)
			}
		}
	}
	return "JSON incorrecto (" + message + ")"
}

// configBackups lists the turbo.config*.bak next to configPath, newest first, with their date.
func configBackups(configPath string) []string {
	dir, name := filepath.Split(configPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	type backup struct {
		path     string
		modified time.Time
	}
	var found []backup
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), name) || !strings.HasSuffix(entry.Name(), ".bak") {
			continue
		}
		if info, err := entry.Info(); err == nil {
			found = append(found, backup{dir + entry.Name(), info.ModTime()})
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].modified.After(found[j].modified) })
	list := make([]string, len(found))
	for i, b := range found {
		list[i] = b.path + " (" + b.modified.Format("2006-01-02 15:04") + ")"
	}
	return list
}
