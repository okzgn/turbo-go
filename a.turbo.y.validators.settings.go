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

// The validators of the global settings ("." in turbo.config, set<KEY> in the API), and what they keep true between
// one setting and another.

import (
	"log/slog"
	"strconv"
	"strings"
	"time"

	"turbo/customNetHttp"
)

var defaultSettingsResetFallbacks = map[string]map[string]func(){ // Default settings check reset fallback
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
		"WFT": func() { fileWriteTimeout.Store(0) },
		"IT":  func() { setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.IT = 2 * time.Second }) },
	},
}

var defaultSettingKeysGroup = map[string][]string{
	".": {"M", "PA", "MUB", "MHB", "MBB", "CIL", "CIS", "CII", "CGL", "CGP", "RT", "RHT", "WT", "WFT", "IT"}, // Not "C": saving is an action
}

var defaultSettingErrorExceptions = map[string]map[string]map[string]bool{ // Refusals that keep the setting as it is, instead of resetting it to its default
	".": {
		"M":   map[string]bool{msgSitesDirUnchanged: true},
		"PA":  map[string]bool{msgValueUnchanged: true},
		"MUB": map[string]bool{msgValueUnchanged: true},
		"MHB": map[string]bool{msgValueUnchanged: true},
		"MBB": map[string]bool{msgValueUnchanged: true},
		"CIL": map[string]bool{msgValueUnchanged: true},
		"CIS": map[string]bool{msgValueUnchanged: true},
		"CII": map[string]bool{msgValueUnchanged: true},
		"CGL": map[string]bool{msgValueUnchanged: true},
		"CGP": map[string]bool{msgValueUnchanged: true},
		"RT":  map[string]bool{msgValueUnchanged: true},
		"RHT": map[string]bool{msgValueUnchanged: true},
		"WT":  map[string]bool{msgValueUnchanged: true},
		"WFT": map[string]bool{msgValueUnchanged: true},
		"IT":  map[string]bool{msgValueUnchanged: true},
	},
}

var defaultSettingValidators = map[string]map[string]func(...string) (bool, string){ // Default settings check
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

			// setM is setSitesDir, which puts the directory in use with its configuration: this validator only reads
			// the "M" of a turbo.config, whose reload has followed it already (updateSettingsFollowing), or chose not
			// to (setM to the start directory). The sites directory changes only with the reload that applies its
			// configuration, at once. It also changed it here, without reading anything there: only tests did so.
			if !loadingConfig {
				return false, "The sites directory changes with setM"
			}
			resolved, err := resolveSitesDir(args[0])
			if err != nil {
				return false, "Sites directory not found"
			}
			if sameDirWith(resolved, sitesDir.Get(), diskStat) { // The same folder written another way: saved as the file writes it
				sitesDirValue.Set(args[0])
			}
			return false, msgSitesDirUnchanged
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
				return false, msgValueUnchanged
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
				return false, msgValueUnchanged
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
				return false, msgValueUnchanged
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
				return false, msgValueUnchanged
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
			if value < 1000 {
				return false, "Less than 1000 milliseconds"
			}
			if value > 800000 {
				return false, "More than 800000 milliseconds"
			}
			// After the range: 10000 + 2^58 milliseconds overflowed, in nanoseconds, into the 10 s in use
			if value*int64(time.Millisecond) == serverRequestLimits.CIL.Load() {
				return false, msgValueUnchanged
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
				return false, msgValueUnchanged
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
				return false, msgValueUnchanged
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
				return false, msgValueUnchanged
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
				return false, msgValueUnchanged
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
				return false, msgValueUnchanged
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
				return false, msgValueUnchanged
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
				return false, msgValueUnchanged
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
		"WFT": func(args ...string) (bool, string) { // The time to write a site's file, apart from WT; 0 uses WT
			if len(args) != 2 {
				return false, msgMissingData + " for WFT"
			}
			if !passwordMatches(args[1]) {
				return false, "Wrong current password"
			}
			value, err := time.ParseDuration(args[0])
			if err != nil {
				return false, "Invalid value"
			}
			if int64(value) == fileWriteTimeout.Load() {
				return false, msgValueUnchanged
			}
			if value != 0 {
				if value < 100*time.Millisecond {
					return false, "Less than 100 milliseconds"
				}
				if value > 24*time.Hour {
					return false, "More than 24 hours"
				}
			}
			fileWriteTimeout.Store(int64(value))
			return true, "File write timeout saved"
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
				return false, msgValueUnchanged
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
