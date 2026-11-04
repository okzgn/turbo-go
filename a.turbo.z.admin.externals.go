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
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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

// configFileDigest is the SHA-256 of the turbo.config last applied or saved, so that saving can tell an edit made
// by hand since then (not reloaded yet, rejected, or written by a later Turbo) and copy it first; guarded by
// globalMutex.
var configFileDigest [sha256.Size]byte

// configSchemaError is a turbo.config whose "^" doesn't say a schema this version understands. Such a file is
// not applied, like one that isn't valid JSON: guessing schema 1 would migrate it again.
type configSchemaError struct{}

func (configSchemaError) Error() string {
	return `"^" does not give a valid schema: it must be {"v":"<positive integer>"}`
}

// migrateConfig converts in memory a turbo.config read with an older schema to the current one and returns
// the schema it had. It never rewrites the file. A later schema is left as is: what is understood loads. "v"
// may be a string or a JSON number, but a positive integer; without "^" the schema is 1.
func migrateConfig(raw map[string]map[string]interface{}, configBytes []byte) (from int, err error) {
	from = 1
	if versionSection, hasVersion := raw["^"]; hasVersion {
		switch version := versionSection["v"].(type) {
		case string:
			number, convErr := strconv.Atoi(version)
			if convErr != nil || number < 1 {
				return 0, configSchemaError{}
			}
			from = number
		case float64:
			if version < 1 || version != float64(int(version)) {
				return 0, configSchemaError{}
			}
			from = int(version)
		default:
			return 0, configSchemaError{}
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
					if _, kept := indexes[name]; kept { // Not one that dropControlChars removed
						indexes[name] = strconv.Itoa(position + 1)
					}
				}
			}
		}
		decodeV1RewriteSources(raw)
	}
	return from, nil
}

// decodeV1RewriteSources decodes the "%" escapes of the rewrite sources of a schema 1 file, which were compared
// with the request path as it came and now are compared with the decoded one. A source that can't be decoded, or
// whose escapes hide a "/" or a backslash (no request path can match them now), is dropped with a warning.
func decodeV1RewriteSources(raw map[string]map[string]interface{}) {
	for site, subdomains := range raw {
		for subdomain, data := range subdomains {
			subdomainData, isMap := data.(map[string]interface{})
			if !isMap {
				continue
			}
			rewrites, isMap := subdomainData["="].(map[string]interface{})
			if !isMap {
				continue
			}
			for _, source := range sortedKeys(rewrites) { // A copy of the sources: a decoded one added below isn't decoded again
				target := rewrites[source]
				if strings.IndexByte(source, '%') == -1 {
					continue
				}
				delete(rewrites, source)
				lower := strings.ToLower(source)
				decoded, err := url.PathUnescape(source)
				if err != nil || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || !textAllowed(decoded, false) {
					slog.Warn("turbo.config rewrite discarded: the source can't be decoded", "site", site, "subdomain", subdomain, "source", source)
					continue
				}
				if _, taken := rewrites[decoded]; !taken {
					rewrites[decoded] = target
				}
			}
		}
	}
}

// configSchemaOf returns the schema of a turbo.config file (1 without "^", or when it can't be read).
func configSchemaOf(configBytes []byte) int {
	var raw map[string]map[string]interface{}
	if json.Unmarshal(configBytes, &raw) != nil {
		return 1
	}
	from, err := migrateConfig(raw, configBytes)
	if err != nil {
		return 1
	}
	return from
}

// isSitesDirPointer reports whether a turbo.config only points to another sites directory (just "^" and "M"),
// as saveDefaultConfig leaves it in startDir.
func isSitesDirPointer(configBytes []byte) bool {
	var raw map[string]map[string]interface{}
	if json.Unmarshal(configBytes, &raw) != nil {
		return false
	}
	return isSitesDirPointerMap(raw)
}

// isSitesDirPointerMap is isSitesDirPointer for a turbo.config already decoded.
func isSitesDirPointerMap(raw map[string]map[string]interface{}) bool {
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

// pointsToItself reports whether the turbo.config read from configPath is a pointer (see isSitesDirPointer)
// whose "M" names its own folder. Saving left one like that, instead of the whole configuration, when "M" named
// the start directory written another way; applying it would bring back the defaults.
func pointsToItself(raw map[string]map[string]interface{}, configPath string) bool {
	value, _ := configSitesDir(raw)
	return value != "" && isSitesDirPointerMap(raw) && sameDir(value, filepath.Dir(configPath))
}

// configSitesDir is the "M" of a decoded turbo.config as its setting reads it (configNumberOrString: a string, or
// an integer as its digits), and whether "M" is there at all. Every reader of "M" uses it: reading only strings in
// some of them, a numeric "M" was applied without checking where it led.
func configSitesDir(raw map[string]map[string]interface{}) (value string, present bool) {
	setting, present := raw["."]["M"]
	value, _ = configNumberOrString(setting)
	return value, present
}

// unusableSitesDirProblem says why the "M" of a turbo.config that only points to another directory
// (isSitesDirPointerMap) can't be followed when it is there but isn't a directory name ("", null, true, 1.5, an
// object): applied as it is, such a pointer would leave the default configuration. Without "M" ({} or only "^"),
// it is an empty configuration, loaded as such.
func unusableSitesDirProblem(raw map[string]map[string]interface{}) (shown string, unusable bool) {
	value, present := configSitesDir(raw)
	if !present || value != "" || !isSitesDirPointerMap(raw) {
		return "", false
	}
	encoded, err := json.Marshal(raw["."]["M"])
	if err != nil {
		return `"M"`, true
	}
	return string(encoded), true
}

// configSelfPointerError is a turbo.config that points to itself (see pointsToItself).
type configSelfPointerError struct{}

func (configSelfPointerError) Error() string {
	return `only has "M" and points to its own directory: it is what saving left instead of the whole configuration when "M" named the start directory another way`
}

// configPointerError is a turbo.config that only points to another sites directory that can't be followed, or
// (whole) a whole one whose "M" names a sites directory with a turbo.config that can't be followed.
type configPointerError struct {
	target, reason string
	whole          bool
}

func (e configPointerError) Error() string {
	if e.whole {
		return `"M" names ` + e.target + ", " + e.reason + ": following it would leave the sites without their settings (their scripts served as text) and empty the configuration in use. Make that directory available, with a usable turbo.config if it has one, or change \"M\""
	}
	return `only has "M", which points to ` + e.target + ", " + e.reason + ": applying it would leave the default configuration (the default user and password, and the panel on any host). Make that directory available again with its turbo.config, or restore the whole configuration here (a .bak copy)"
}

// sitesDirChainProblem says, before anything is applied, why the sites directories that a turbo.config read in
// baseDir leads to can't be followed: through the "M" of a pointer (isSitesDirPointerMap), or the "M" of a whole one
// that names another directory, whose turbo.config then applies whole or, without one, in which this one applies
// (reloadOptions.carried). Every directory on the way must exist and be listable, and every turbo.config on it be
// usable; a pointer must lead to a configuration, unless withoutConfigKept (setM keeps the settings in use for a
// directory without turbo.config); and the chain can't come back to a directory on it, nor go further than the reload
// follows (counting the redirects already followed). Followed, it emptied the configuration in use (resetSettings)
// before finding that out, and left the sites with the defaults, their scripts served as text.
func sitesDirChainProblem(raw map[string]map[string]interface{}, baseDir string, redirects int, withoutConfigKept bool) error {
	first, _ := configSitesDir(raw)
	whole := !isSitesDirPointerMap(raw)
	if shown, unusable := unusableSitesDirProblem(raw); unusable {
		return configPointerError{target: shown, reason: `which is not a directory: "M" must be a non-empty string`}
	}
	current, currentDir, value, via := raw, baseDir, first, ""
	visited := []string{baseDir}
	for ; value != ""; redirects++ { // Without "M" (a pointer without it is an empty configuration), nothing to follow
		reason := func(what string) error {
			if via != "" {
				what = "and from there it leads to " + via + ", " + what
			}
			return configPointerError{target: first, reason: what, whole: whole}
		}
		resolved, err := resolveSitesDir(value)
		if err != nil {
			return reason("which does not exist")
		}
		if sameDir(resolved, currentDir) { // A whole turbo.config that names its own directory (a pointer can't: pointsToItself)
			return nil
		}
		for _, seen := range visited {
			if sameDir(resolved, seen) {
				return reason("whose turbo.config leads back to a directory on the way")
			}
		}
		if redirects >= 2 {
			return configPointerError{target: first, reason: "and the turbo.config files point to each other", whole: whole}
		}
		if _, err := os.ReadDir(resolved); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return reason("which does not exist")
			}
			return reason("which can't be listed")
		}
		target, err := parseSiteConfig(resolved + configFileName)
		switch {
		case err != nil:
			return reason("whose turbo.config can't be used")
		case target.raw == nil && isSitesDirPointerMap(current) && !withoutConfigKept:
			return reason("which has no turbo.config")
		case target.raw == nil:
			return nil // A whole turbo.config applies there (carried); setM keeps the settings in use there
		}
		visited = append(visited, resolved)
		current, currentDir = target.raw, resolved
		if shown, unusable := unusableSitesDirProblem(current); unusable {
			via = shown
			return reason(`which is not a directory: "M" must be a non-empty string`)
		}
		value, _ = configSitesDir(current)
		via = value
	}
	return nil
}

// resolveSitesDir turns a sites directory as written (TURBO_DIR, "M" or setM) into the one Turbo uses:
// {TURBO_CURRENT_DIR} replaced by the working directory, absolute, clean, with "/" as separator and a single
// final "/". It is idempotent.
func resolveSitesDir(value string) (string, error) {
	if value == "" {
		return "", errors.New("empty directory")
	}
	if strings.Contains(value, "{"+currentDirPlaceholder+"}") {
		workingDir, err := os.Getwd()
		if err != nil {
			return "", err
		}
		value = strings.ReplaceAll(value, "{"+currentDirPlaceholder+"}", workingDir+string(filepath.Separator))
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimRight(filepath.ToSlash(absolute), "/") // A root keeps its separator (C:\, \\server\share\)
	if trimmed == "" {
		if runtime.GOOS == "windows" { // Only separators: no folder on this system
			return "", errors.New("invalid path")
		}
		return "/", nil
	}
	return trimmed + "/", nil
}

// sameDir reports whether two sites directories, as written or resolved, are the same folder: the same one for
// the system if both exist (also through a link, or in other case where the file system ignores it), or else the
// same resolved path, ignoring case on Windows and macOS.
func sameDir(a string, b string) bool {
	return sameDirWith(a, b, os.Stat)
}

// sameDirWith is sameDir looking at the folders with stat.
func sameDirWith(a string, b string, stat func(string) (os.FileInfo, error)) bool {
	resolvedA, errA := resolveSitesDir(a)
	resolvedB, errB := resolveSitesDir(b)
	if errA != nil || errB != nil {
		return a == b
	}
	infoA, errA := stat(resolvedA)
	infoB, errB := stat(resolvedB)
	if errA == nil && errB == nil {
		return os.SameFile(infoA, infoB)
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(resolvedA, resolvedB)
	}
	return resolvedA == resolvedB
}

// sameFile reports whether two paths name the same file, following symbolic links (two turbo.config files that are
// links to one), and false if either can't be looked at.
func sameFile(a string, b string) bool {
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(infoA, infoB)
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
// first copied to turbo.config.invalid.<date>.bak, and the first time a migrated file is saved, the original
// is copied to turbo.config.v<schema>.bak. The configuration is read with the global read lock and the files are
// written without it, holding settingsUpdateMutex instead: two saves don't mix, and no reload runs in between.
// Callers don't hold the global lock.
func saveDefaultConfig() bool {
	settingsUpdateMutex.Lock()
	defer settingsUpdateMutex.Unlock()
	baseDir, pointerValue := sitesDir.Get(), sitesDirValue.Get()
	var schemaRead int
	var config string
	var knownDigest [sha256.Size]byte
	withReadLock(func() {
		schemaRead = configSchemaRead
		config = createDefaultConfig(true, false, true)
		knownDigest = configFileDigest
	})

	configPath := baseDir + configFileName
	editedByHand := false
	if original, err := os.ReadFile(configPath); err == nil && sha256.Sum256(original) != knownDigest { // #nosec G304 -- turbo.config of the sites directory in use
		slog.Warn("turbo.config has changed since Turbo read or saved it (a hand edit not applied): it is copied before saving", "file", configPath)
		editedByHand = true
	}
	if !backupBeforeSave(configPath, schemaRead, editedByHand) {
		return false
	}
	saved := []byte("{\"^\":{\"v\":\"" + strconv.Itoa(configSchema) + "\"}," + config[1:])
	if err := writeFileAtomic(configPath, saved); err != nil {
		slog.Error("Can't save turbo.config", "file", configPath, "error", err)
		return false
	}
	// The periodic check must not take this save for an edit and apply it again over what changes next. The file
	// now holds the configuration in use: if it disappears, that configuration stays, as with one read at start.
	savedStamp := configStampOf(configPath)
	withGlobalLock(func() {
		configSchemaRead = configSchema
		configFileDigest = sha256.Sum256(saved)
		configFileLoaded = true
		if savedStamp.kind == stampFile {
			configFileStamp = savedStamp
		}
	})
	if !sameDir(baseDir, startDir) && !sameFile(startDir+configFileName, configPath) { // Turbo starts reading startDir: leave there where the sites are
		pointerPath := startDir + configFileName
		if original, err := os.ReadFile(pointerPath); err == nil && !isSitesDirPointer(original) { // #nosec G304 -- turbo.config of the start directory
			// A whole configuration is about to become a pointer: keep it, whatever its schema
			if !backupBeforeSave(pointerPath, configSchemaOf(original), true) {
				return false
			}
		}
		pointer := "{\"^\":{\"v\":\"" + strconv.Itoa(configSchema) + "\"},\".\":{\"M\":" + jsonString(pointerValue) + "}}"
		if err := writeFileAtomic(pointerPath, []byte(pointer)); err != nil {
			slog.Error("Can't save turbo.config", "file", pointerPath, "error", err)
			return false
		}
	}
	return true
}

// backupBeforeSave copies the turbo.config at configPath before it is overwritten: to
// turbo.config.invalid.<date>.bak if it isn't valid JSON, to turbo.config.v<schema>.bak if its schema is
// older or later than the current one and, with always, to turbo.config.<date>.bak otherwise. It reports false if a needed
// copy couldn't be written.
func backupBeforeSave(configPath string, schema int, always bool) bool {
	original, err := os.ReadFile(configPath) // #nosec G304 -- path under the sites directory chosen by the administrator (TURBO_DIR or M)
	if err != nil {
		return true // Nothing to keep
	}
	var backupPath, message string
	level := slog.LevelInfo
	switch {
	case !json.Valid(original):
		backupPath = configPath + ".invalid." + time.Now().Format("20060102-150405") + ".bak"
		message, level = "turbo.config is not valid JSON: it is copied before saving", slog.LevelWarn
	case schema != configSchema: // Older, or later and saving was confirmed: its settings would be lost
		backupPath = configPath + ".v" + strconv.Itoa(schema) + ".bak"
		if _, err := os.Lstat(backupPath); err == nil { // #nosec G703 -- turbo.config backup next to the original. A copy from an earlier upgrade: keep it too
			backupPath = configPath + ".v" + strconv.Itoa(schema) + "." + time.Now().Format("20060102-150405") + ".bak"
		}
	case always:
		backupPath = configPath + "." + time.Now().Format("20060102-150405") + ".bak"
		message = "turbo.config copied before replacing it"
	default:
		return true
	}
	if backupPath, err = writeBackup(backupPath, original); err != nil {
		slog.Error("Can't save the copy of turbo.config", "file", backupPath, "error", err)
		return false
	}
	if message != "" {
		slog.Log(context.Background(), level, message, "backup", backupPath)
	}
	return true
}

// writeBackup writes a copy of turbo.config at path or, if a file is already there (two saves within the same
// second), at path with "-2", "-3"… before ".bak": a copy never replaces another. It returns where it wrote it.
func writeBackup(path string, data []byte) (string, error) {
	base := strings.TrimSuffix(path, ".bak")
	for attempt := 1; ; attempt++ {
		candidate := path
		if attempt > 1 {
			candidate = base + "-" + strconv.Itoa(attempt) + ".bak"
		}
		file, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) // #nosec G304 G703 -- turbo.config backup next to the original, path under the sites directory chosen by the administrator (TURBO_DIR or M)
		if errors.Is(err, os.ErrExist) && attempt < 100 {
			continue
		}
		if err != nil {
			return candidate, err
		}
		_, err = file.Write(data)
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			os.Remove(candidate) // #nosec G104 G703 -- the partial copy just written next to turbo.config; the error that matters is the write's
		}
		return candidate, err
	}
}

// createTempFile creates the temporary file of writeFileAtomic (a variable so that tests can make it fail).
var createTempFile = os.CreateTemp

// writeFileAtomic replaces path with data (permissions 0600): it writes a new temporary file next to it, with a
// name of its own, syncs it and renames it over path, so a failure or a power cut leaves either the old file or
// the new one. On Unix, the directory is synced too, so the rename itself survives a power cut. If path is a
// symbolic link, its target is replaced and the link stays.
func writeFileAtomic(path string, data []byte) error {
	if target, err := filepath.EvalSymlinks(path); err == nil {
		path = target
	}
	dir, name := filepath.Split(path)
	file, err := createTempFile(dir, name+".*.tmp") // Created anew (O_EXCL, 0600): an existing file or link is never used
	if err != nil {
		return err
	}
	tempPath := file.Name()
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
		return err
	}
	if runtime.GOOS != "windows" { // Windows can't sync a directory
		if dirFile, openErr := os.Open(filepath.Clean(dir + ".")); openErr == nil { // #nosec G304 -- the directory of turbo.config
			if syncErr := dirFile.Sync(); syncErr != nil { // The file is already replaced: only its durability is in doubt
				slog.Warn("Can't sync the directory of turbo.config", "directory", dir, "error", syncErr)
			}
			dirFile.Close() // #nosec G104 -- read-only handle
		}
	}
	return nil
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

// createDefaultConfig is the JSON of the configuration in use: for turbo.config (withSubdomains, each site with
// its subdomains and everything of them, also the sites whose folder isn't there, with the settings kept for
// them; includeCredentials, the username and the password hash) or for the panel (the active sites with their
// settings only; includeFixedKeys marks the fixed character replacements and responses as {"f": value}). Every
// list goes in a fixed order, so the file doesn't change from one save to the next without a change in it.
func createDefaultConfig(withSubdomains bool, includeFixedKeys bool, includeCredentials bool) string {
	credentials := ""
	if includeCredentials {
		credentials = ",\"U\":" + jsonString(panelUser.Get()) + ",\"PH\":" + jsonString(panelPasswordHash.Get())
	}
	var jsonBuilder strings.Builder
	delimiter := ""
	sites := sortedKeys(sitesMap)
	if withSubdomains {
		sites = sortedKeyUnion(sitesMap, dormantSites)
	}
	for _, siteKey := range sites {
		jsonBuilder.WriteString(delimiter + jsonString(siteKey) + ":")
		if !withSubdomains {
			jsonBuilder.WriteString("{" + createSiteSettingsList(siteKey) + "}")
		} else {
			jsonBuilder.WriteString(createSubdomainsList(true, siteKey))
		}
		delimiter = ","
	}
	if !withSubdomains { // The panel's list also has the sites kept without their folder, which it can delete
		jsonBuilder.WriteString(delimiter + dormantSitesList())
		delimiter = ","
	}

	jsonBuilder.WriteString(delimiter + "\"_\":{") // Chars to encode list
	delimiter = ""
	for _, mapKey := range sortedKeys(charReplacements) {
		jsonBuilder.WriteString(delimiter + jsonString(mapKey) + ":")
		if _, fixed := fixedCharReplacements[mapKey]; fixed && includeFixedKeys {
			jsonBuilder.WriteString("{\"f\":" + jsonString(charReplacements[mapKey]) + "}")
		} else {
			jsonBuilder.WriteString(jsonString(charReplacements[mapKey]))
		}
		delimiter = ","
	}

	jsonBuilder.WriteString("},\"@\":{") // Denied IPs list
	delimiter = ""
	denied := deniedIPList()
	for _, mapKey := range sortedKeys(denied) {
		jsonBuilder.WriteString(delimiter + jsonString(mapKey) + ":\"" + strconv.FormatInt(denied[mapKey], 10) + "\"")
		delimiter = ","
	}

	jsonBuilder.WriteString("},\"#\":{") // Http codes responses list
	delimiter = ""
	responses := *httpResponses.Load()
	codes := make([]int, 0, len(responses))
	for code := range responses {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	for _, code := range codes {
		jsonBuilder.WriteString(delimiter + "\"" + strconv.Itoa(code) + "\":")
		if _, fixed := fixedHTTPResponses[code]; fixed && includeFixedKeys {
			jsonBuilder.WriteString("{\"f\":" + jsonString(responses[code]) + "}")
		} else {
			jsonBuilder.WriteString(jsonString(responses[code]))
		}
		delimiter = ","
	}

	return "{" + jsonBuilder.String() + "},\".\":{\"M\":" + jsonString(sitesDirValue.Get()) + ",\"PA\":" + jsonString(panelAccess.Load().setting) + ",\"RT\":\"" + serverTimeLimits.Load().RT.String() + "\",\"RHT\":\"" + serverTimeLimits.Load().RHT.String() + "\",\"WT\":\"" + serverTimeLimits.Load().WT.String() + "\",\"IT\":\"" + serverTimeLimits.Load().IT.String() + "\",\"MUB\":\"" + strconv.FormatInt(maxURILength.Load(), 10) + "\",\"MHB\":\"" + strconv.FormatInt(maxHeaderBytes.Load(), 10) + "\",\"MBB\":\"" + strconv.FormatInt(maxBodySize.Load(), 10) + "\",\"CIL\":\"" + strconv.FormatInt(serverRequestLimits.CIL.Load()/int64(time.Millisecond), 10) + "\",\"CIS\":\"" + strconv.FormatInt(serverRequestLimits.CIS.Load()/int64(time.Millisecond), 10) + "\",\"CII\":\"" + strconv.FormatInt(serverRequestLimits.CII.Load(), 10) + "\",\"CGL\":\"" + strconv.FormatInt(globalRequestLimit.Load(), 10) + "\",\"CGP\":\"" + strconv.FormatInt(cgiProcesses.Load(), 10) + "\"" + panelCertSettingsJSON(!includeCredentials) + credentials + "}}"
}

// dormantSitesList is the "~" entry of the panel's list of sites: the sites and subdomains whose folder isn't there
// (dormantSites), whose settings turbo.config keeps until they are deleted, as {"site": ["", "subdomain"…]} in
// byte order. Callers hold the global lock.
func dormantSitesList() string {
	var jsonBuilder strings.Builder
	jsonBuilder.WriteString(`"~":{`)
	for siteIndex, domain := range sortedKeys(dormantSites) {
		if siteIndex > 0 {
			jsonBuilder.WriteString(",")
		}
		jsonBuilder.WriteString(jsonString(domain) + ":[")
		for subdomainIndex, subdomain := range sortedKeys(dormantSites[domain]) {
			if subdomainIndex > 0 {
				jsonBuilder.WriteString(",")
			}
			jsonBuilder.WriteString(jsonString(subdomain))
		}
		jsonBuilder.WriteString("]")
	}
	jsonBuilder.WriteString("}")
	return jsonBuilder.String()
}

// createSubdomainsList is the JSON of the subdomains of a site (the root is ""): everything of each one (withData,
// for turbo.config, also of those whose folder isn't there) or, for the panel, the active ones' settings and the
// root's aliases.
func createSubdomainsList(withData bool, domain string) string {
	var jsonBuilder strings.Builder
	delimiter := ""
	subdomains := sortedKeys(sitesMap[domain])
	if withData {
		subdomains = sortedKeyUnion(sitesMap[domain], dormantSites[domain])
	}
	for _, subdomain := range subdomains {
		jsonBuilder.WriteString(delimiter + jsonString(subdomain) + ":")
		_, active := sitesMap[domain][subdomain]
		switch {
		case withData && !active:
			jsonBuilder.WriteString(dormantSites[domain][subdomain]) // Its folder isn't there: the settings kept for it
		case withData:
			jsonBuilder.WriteString(createSubdomainData(domain, subdomain))
		case subdomain != "":
			jsonBuilder.WriteString("{" + createSiteSettingsList(subdomain+"."+domain) + "}") // Every subdomain and site shows in the panel whether HTTPS is on
		default:
			jsonBuilder.WriteString("{" + createSiteAliasList(domain) + "," + createSiteSettingsList(domain) + "}")
		}
		delimiter = ","
	}
	return "{" + jsonBuilder.String() + "}"
}

// createSubdomainData is the JSON of everything of a subdomain of a site (the root is ""): rewrites, MIME types,
// headers, preprocessors, indexes, aliases and settings.
func createSubdomainData(domain string, subdomain string) string {
	siteKey := domain
	if subdomain != "" {
		siteKey = subdomain + "." + domain
	}
	var jsonBuilder strings.Builder
	jsonBuilder.WriteString("\"=\":{")
	delimiter := ""
	rewrites := sitesMap[domain][subdomain]
	for _, routeKey := range sortedKeys(rewrites) {
		scheme := ""
		switch rewrites[routeKey][0] {
		case 'H':
			scheme = "http://"
		case 'S':
			scheme = "https://"
		}
		jsonBuilder.WriteString(delimiter + jsonString(routeKey) + ":" + jsonString(scheme+rewrites[routeKey][1:]))
		delimiter = ","
	}

	jsonBuilder.WriteString("},\"$\":{")
	delimiter = ""
	for _, extension := range sortedKeys(mimeTypes[siteKey]) {
		jsonBuilder.WriteString(delimiter + jsonString(extension) + ":" + jsonString(mimeTypes[siteKey][extension]))
		delimiter = ","
	}
	jsonBuilder.WriteString("},\".\":{")
	delimiter = ""
	for _, name := range sortedKeys(customHeaders[siteKey]) {
		jsonBuilder.WriteString(delimiter + jsonString(name) + ":" + jsonString(customHeaders[siteKey][name]))
		delimiter = ","
	}
	jsonBuilder.WriteString("},\"?\":{")
	delimiter = ""
	for _, extension := range sortedKeys(preprocessors[siteKey]) {
		jsonBuilder.WriteString(delimiter + jsonString(extension) + ":" + jsonString(strings.TrimPrefix(preprocessors[siteKey][extension], invalidPreprocessorMark)))
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

// createSiteAliasList is the "&" member of a site's JSON: its aliases.
func createSiteAliasList(siteKey string) string {
	var jsonBuilder strings.Builder
	jsonBuilder.WriteString("{")
	delimiter := ""
	for _, aliasName := range sortedKeys(domainAliases) {
		if domainAliases[aliasName] == siteKey {
			jsonBuilder.WriteString(delimiter + jsonString(aliasName) + ":\"\"")
			delimiter = ","
		}
	}
	jsonBuilder.WriteString("}")
	return "\"&\":" + jsonBuilder.String()
}

// createSiteSettingsList is the "!" member of a site's JSON: its settings (S, C, R, W, E, A), each as text.
func createSiteSettingsList(siteKey string) string {
	var jsonBuilder strings.Builder
	jsonBuilder.WriteString("{")
	delimiter := ""
	settings := siteSSLConfig[siteKey]
	for _, settingName := range sortedKeys(settings) {
		var encodedValue string
		switch value := settings[settingName].(type) {
		case bool:
			encodedValue = "0"
			if value {
				encodedValue = "1"
			}
		case int:
			encodedValue = strconv.Itoa(value)
		case string:
			encodedValue = url.QueryEscape(value)
		default:
			continue
		}
		jsonBuilder.WriteString(delimiter + jsonString(settingName) + ":" + jsonString(encodedValue))
		delimiter = ","
	}
	jsonBuilder.WriteString("}")
	return "\"!\":" + jsonBuilder.String()
}

// configFileError is a turbo.config that can't be read (data is nil) or isn't valid JSON. It is never applied:
// Turbo doesn't start with it, and a reload keeps the configuration in use.
type configFileError struct {
	path string
	data []byte
	err  error
}

func (e *configFileError) Error() string { return describeConfigError(e.path, e.data, e.err) }

// Unwrap gives the error of the file, so that configErrorMessage can tell what kind it is.
func (e *configFileError) Unwrap() error { return e.err }

// configErrorMessage is the message for an error of updateSettings, with a first line that says what Turbo
// does about it: not start (starting), or keep the configuration in use.
func configErrorMessage(err error, starting bool) string {
	var fileErr *configFileError
	if !errors.As(err, &fileErr) {
		if starting {
			return "Turbo does not start: " + err.Error()
		}
		return err.Error() + " The configuration in use is kept."
	}
	headline := "turbo.config is not valid JSON"
	if errors.As(err, &configSchemaError{}) {
		headline = "turbo.config does not give a valid schema"
	} else if errors.As(err, &configSelfPointerError{}) {
		headline = "turbo.config only points to its own directory (the configuration is missing)"
	} else if pointerErr := (configPointerError{}); errors.As(err, &pointerErr) {
		headline = "turbo.config only points to another sites directory that can't be used"
		if pointerErr.whole {
			headline = `The "M" of turbo.config names a sites directory whose turbo.config can't be used`
		}
	} else if errors.As(err, &configSettingError{}) {
		headline = "turbo.config has a panel setting that can't be used"
	} else if errors.As(err, &configSiteError{}) {
		headline = "turbo.config has a site section that can't be used"
	}
	if fileErr.data == nil {
		headline = "Can't read turbo.config"
	}
	if starting {
		headline += " and Turbo does not start, so as not to lose the configuration."
	} else {
		headline += ": the configuration in use is kept until it is fixed."
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
	if err := json.Unmarshal(configBytes, raw); err != nil {
		return err
	}
	if *raw == nil { // "null": no configuration at all, not an empty one
		return errors.New("turbo.config is not a JSON object ({...})")
	}
	return nil
}

// configFileProblem returns, for setM, the error of the turbo.config in dir, if there is one that can't be used, or
// of the sites directories it leads to (sitesDirChainProblem), as the reload of setM would follow them; with
// ignorePointer, a pointer there isn't followed.
func configFileProblem(dir string, ignorePointer bool) error {
	config, err := parseSiteConfig(dir + configFileName)
	if err != nil || config.raw == nil || (ignorePointer && isSitesDirPointerMap(config.raw)) {
		return err
	}
	if problem := sitesDirChainProblem(config.raw, dir, 0, true); problem != nil {
		data, _ := os.ReadFile(dir + configFileName) // #nosec G304 -- turbo.config of the sites directory chosen by the administrator, for the message
		return &configFileError{path: dir + configFileName, data: data, err: problem}
	}
	return nil
}

// configSettingError is a turbo.config whose "PA", "U", "PH" or "P" can't be used. Like invalid JSON, Turbo
// doesn't start with it and a reload keeps the configuration in use: their defaults would open the panel to
// every host or bring back Turbo/Admin.
type configSettingError struct {
	key    string
	reason string
}

func (e configSettingError) Error() string { return `"` + e.key + `" can't be used: ` + e.reason }

// configSiteError is a site of turbo.config whose section, or one of its lists, isn't a JSON object. Skipped, the
// site would come from the disk without its settings (its preprocessors, its rewrites…), its scripts served as text,
// so the whole file counts as invalid, as with the settings that guard the panel.
type configSiteError struct{ domain, where string }

func (e configSiteError) Error() string {
	return e.where + ` can't be used: a JSON object is expected (a site, and its lists "!", "=", "$", ".", "?", "-" and "&", are objects)`
}

// siteSectionsProblem checks that every site of turbo.config, each of its subdomains and each of their lists is a
// JSON object (configSiteError).
func siteSectionsProblem(raw map[string]map[string]interface{}) error {
	for _, domain := range sortedKeys(raw) {
		switch domain {
		case "_", "@", "#", ".", "^": // Not sites
			continue
		}
		for _, subdomain := range sortedKeys(raw[domain]) {
			where := strconv.Quote(domain) + " > " + strconv.Quote(subdomain)
			section, isMap := raw[domain][subdomain].(map[string]interface{})
			if !isMap {
				return configSiteError{domain, where}
			}
			for _, key := range subdomainContentOrder {
				if value, present := section[key]; present {
					if _, isMap := value.(map[string]interface{}); !isMap {
						return configSiteError{domain, where + " > " + strconv.Quote(key)}
					}
				}
			}
		}
	}
	return nil
}

// panelSettingsProblem checks the settings of "." that guard the panel (see configSettingError). The username
// and the password are not checked when TURBO_USER or TURBO_PASSWORD replace them.
func panelSettingsProblem(settings map[string]interface{}) error {
	if value, present := settings["PA"]; present {
		text, isString := value.(string)
		if !isString {
			return configSettingError{"PA", "a string is expected"}
		}
		if !textAllowed(text, false) { // dropControlChars would drop it later, and the panel would open to any host
			return configSettingError{"PA", "has control characters"}
		}
		if list, problem := parsePanelAccess(text); list == nil {
			return configSettingError{"PA", problem}
		}
	}
	if value, present := settings["U"]; present && !userFromEnv {
		if text, isString := value.(string); !isString || !panelUserValid(text) {
			return configSettingError{"U", "a string of 1 to 24 characters, without control characters, is expected"}
		}
	}
	if passwordFromEnv {
		return nil
	}
	if value, present := settings["PH"]; present {
		if text, isString := value.(string); !isString {
			return configSettingError{"PH", "a string is expected"}
		} else if !textAllowed(text, false) { // Dropped later, the password would go back to the default
			return configSettingError{"PH", "has control characters"}
		} else if _, _, _, ok := parsePasswordHash(text); !ok {
			return configSettingError{"PH", "is not a Turbo password hash"}
		}
	} else if value, present := settings["P"]; present { // Only read without "PH"
		if _, valid := plainPassword(value); !valid {
			return configSettingError{"P", "a string of 1 to " + strconv.Itoa(maxPasswordBytes) + " bytes, without control characters, is expected"}
		}
	}
	return nil
}

// plainPassword is the plain-text "P" of turbo.config when it can be used: one rule for checking the file
// (panelSettingsProblem) and for applying it (loadCredentials). With 24 bytes in one and 64 in the other, a "P" of
// 25 to 64 bytes made a valid file whose password was never applied, and the panel stayed with the default one.
func plainPassword(value interface{}) (string, bool) {
	text, isString := value.(string)
	return text, isString && len(text) >= 1 && len(text) <= maxPasswordBytes && textAllowed(text, false)
}

// dropControlChars removes from a turbo.config read from disk the keys and values with control characters or
// invalid UTF-8, which the panel doesn't accept, logging where they were. Response templates ("#") may
// have tabs and line breaks. The program of a site's preprocessor ("?") is kept, with those characters replaced by
// U+FFFD: a path that doesn't exist makes its extension answer 500, while without the entry its files would be
// served as text, their source included.
func dropControlChars(raw map[string]map[string]interface{}) {
	var walk func(values map[string]interface{}, where string, whitespace bool, depth int, preprocessors bool)
	walk = func(values map[string]interface{}, where string, whitespace bool, depth int, preprocessors bool) {
		for key, value := range values {
			text, isString := value.(string)
			if textAllowed(key, false) && isString && preprocessors && !textAllowed(text, false) {
				slog.Warn("turbo.config preprocessor with control characters or invalid UTF-8: its extension answers 500 until it is fixed", "where", strconv.Quote(where+key))
				values[key] = strings.Map(func(r rune) rune {
					if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
						return utf8.RuneError
					}
					return r
				}, strings.ToValidUTF8(text, string(utf8.RuneError)))
				continue
			}
			if !textAllowed(key, false) || (isString && !textAllowed(text, whitespace)) {
				slog.Warn("turbo.config value discarded: control characters or invalid UTF-8", "where", strconv.Quote(where+key))
				delete(values, key)
				continue
			}
			if nested, isMap := value.(map[string]interface{}); isMap {
				walk(nested, where+key+" > ", whitespace, depth+1, preprocessors || (depth == 2 && key == "?"))
			}
		}
	}
	for section, values := range raw {
		if !textAllowed(section, false) {
			slog.Warn("turbo.config section discarded: control characters or invalid UTF-8", "where", strconv.Quote(section))
			delete(raw, section)
			continue
		}
		depth := 1 // A site: subdomains at depth 1, their lists at 2, the entries of a list at 3
		switch section {
		case "_", "@", "#", ".", "^": // Not sites: no preprocessors in them
			depth = 0
		}
		walk(values, section+" > ", section == "#", depth, false)
	}
}

// describeConfigError explains where a turbo.config is wrong, so that it can be fixed by hand: the path, the
// line and column of the error with that line and a mark under the column, the cause, and the backups next to
// it (newest first). data is nil if the file couldn't be read.
func describeConfigError(path string, data []byte, err error) string {
	var message strings.Builder
	message.WriteString("  File: " + path + "\n")
	if data == nil {
		message.WriteString("  Error: " + err.Error() + "\n  Check that Turbo has permission to read the file.\n")
		return message.String()
	}
	offset, cause := int64(len(data)), "Invalid JSON ("+err.Error()+")"
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) {
		offset, cause = syntaxErr.Offset, jsonSyntaxCause(syntaxErr.Error())
	} else if errors.As(err, &configSchemaError{}) {
		offset, cause = int64(bytes.Index(data, []byte(`"^"`))+1), err.Error()
	} else if errors.As(err, &configSelfPointerError{}) || errors.As(err, &configPointerError{}) {
		offset, cause = int64(bytes.Index(data, []byte(`"M"`))+1), err.Error()
	} else if settingErr := (configSettingError{}); errors.As(err, &settingErr) {
		offset, cause = int64(bytes.Index(data, []byte(`"`+settingErr.key+`"`))+1), err.Error()
	} else if siteErr := (configSiteError{}); errors.As(err, &siteErr) {
		offset, cause = int64(bytes.Index(data, []byte(jsonString(siteErr.domain)))+1), err.Error()
	} else if errors.As(err, &typeErr) {
		offset, cause = typeErr.Offset, "an object {...} was expected and there is a value of type "+typeErr.Value
	}
	data = hideConfigSecrets(data)
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
	message.WriteString("  Line " + strconv.Itoa(lineNumber) + ", column " + strconv.Itoa(position-lineStart+1) + ": " + cause + "\n")
	message.WriteString("    " + fragment + "\n    " + strings.Repeat(" ", mark) + "^\n")
	backups := configBackups(path)
	if len(backups) == 0 {
		message.WriteString("  Fix the file.\n")
		return message.String()
	}
	message.WriteString("  Fix the file or restore a copy:\n")
	for _, backup := range backups {
		message.WriteString("    " + backup + "\n")
	}
	return message.String()
}

// configSecretValue matches the value of "PH" or "P" in a turbo.config, escaped characters included, also when
// the key is written with escapes ("P").
var configSecretValue = regexp.MustCompile(`"(?:P|\\u0050)(?:H|\\u0048)?"\s*:\s*"((?:[^"\\]|\\.)*)`)

// hideConfigSecrets returns a copy of a turbo.config with the values of "PH" and "P" replaced by asterisks of the
// same length, so the positions of an error stay the same and the message never shows them.
func hideConfigSecrets(data []byte) []byte {
	hidden := bytes.Clone(data)
	for _, match := range configSecretValue.FindAllSubmatchIndex(hidden, -1) {
		for i := match[2]; i < match[3]; i++ {
			hidden[i] = '*'
		}
	}
	return hidden
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
		return `the file ends before the JSON is closed (missing '}', ']' or '"')`
	}
	causes := []struct{ suffix, cause string }{
		{" in string literal", "invalid character %s inside a string"},
		{" in string escape code", "invalid escape sequence (%s) inside a string"},
		{" looking for beginning of value", "invalid character %s where a value was expected"},
		{" looking for beginning of object key string", "invalid character %s where a quoted key was expected"},
		{" after object key:value pair", "invalid character %s after a value (missing ',' or '}')"},
		{" after object key", "invalid character %s after a key (missing ':')"},
		{" after array element", "invalid character %s after an element (missing ',' or ']')"},
		{" after top-level value", "extra content (%s) after the end of the JSON"},
	}
	if character, found := strings.CutPrefix(message, "invalid character "); found {
		for _, known := range causes {
			if quoted, isKnown := strings.CutSuffix(character, known.suffix); isKnown {
				return strings.Replace(known.cause, "%s", quoted, 1)
			}
		}
	}
	return "Invalid JSON (" + message + ")"
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
