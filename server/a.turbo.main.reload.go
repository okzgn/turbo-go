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

// Reading turbo.config and the sites directory: at the start, every 30 seconds and when the panel asks for it, with
// what is looked at on disk before taking the lock, and how what was read is applied.

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// resetSettings leaves Turbo without the sites of a sites directory, their certificates published and its logs, as
// at the start (for the tests: a reload that moves to another directory does this with resetSitesLocked, in the same
// section that applies the new one).
func resetSettings() {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	resetSitesLocked()
	certificatesByName.Store(&map[string]*tls.Certificate{})
	logMutex.Lock()
	for _, logFile := range []*os.File{visitsLogFile, denialsLogFile} {
		if logFile != nil {
			closeLog(logFile)
		}
	}
	visitsLogFile = nil
	denialsLogFile = nil
	logsOpenLocked()
	logMutex.Unlock()
}

// resetSitesLocked empties what belongs to a sites directory when another one is put in use: its sites, with their
// settings and certificates, those kept without their folder, its aliases and the panel's certificate. The global
// settings, the credentials and the lists stay: the configuration of the new directory replaces them, or setM keeps
// them for one without turbo.config. The certificates published stay in use until the new ones are published.
// Callers hold the global lock.
func resetSitesLocked() {
	sitesMap = make(map[string]map[string]map[string]string) // Sites map & rewrites
	siteSSLConfig = make(map[string]*siteSettings)           // Settings of the sites
	mimeTypes = make(map[string]map[string]string)           // MIME types
	customHeaders = make(map[string]map[string]string)       // Headers
	preprocessors = make(map[string]map[string]string)       // Preprocessors
	indexFiles = make(map[string]map[string]int)             // Indexes
	domainAliases = make(map[string]string)                  // Domain aliases
	dormantSites = make(map[string]map[string]string)        // Those of the new sites directory come with its configuration
	siteCertificates = make(map[string]*tls.Certificate)
	siteCertificateStamps = make(map[string]string)
	panelCertificate, panelCertificateStamp = nil, "" // Read again from the new sites directory
	warnedDiskSites = make(map[string]bool)
	configFileLoaded = false
	// The attempts of Certbot and their retries have the folders of the directory left: none applies here (a site of
	// the same name of the new one got the certificate of the old one, and the retry its files there)
	certSitesEpoch++
	clear(certPending)
}

// configFileLoaded is set when the configuration in use came from a turbo.config of the sites directory (or setM
// kept it for a directory without one), so that the file missing later keeps it instead of bringing back the
// defaults. Guarded by globalMutex.
var configFileLoaded bool

// sitesDirError is a sites directory that can't be read. Turbo doesn't start with it (its sites and their settings
// would be missing), and a reload keeps the configuration in use.
type sitesDirError struct {
	dir string
	err error
}

func (e *sitesDirError) Error() string {
	permissions := ""
	if info, err := os.Stat(e.dir); err == nil {
		permissions = " (permissions " + info.Mode().Perm().String() + ")"
	}
	return "Can't read the sites directory " + e.dir + permissions + ": " + e.err.Error() + "\n  Check that it exists and that the user running Turbo can read it."
}

// updateSettings reads turbo.config if it changed and activates the site folders found on disk. If turbo.config
// can't be read or isn't valid JSON, the configuration in use is kept and the error (a *configFileError) is
// returned; it isn't read again until the file changes.
func updateSettings(checkSitesFlag bool) error {
	settingsUpdateMutex.Lock()
	defer settingsUpdateMutex.Unlock()
	return updateSettingsFollowing(checkSitesFlag, sitesDirHops, reloadOptions{})
}

// settingsUpdateMutex keeps reloads of the configuration from overlapping: the periodic one and setM's, which
// changes the sites directory in between. It is taken before globalMutex.
var settingsUpdateMutex sync.Mutex

// beforeSitesScan runs when a reload has read turbo.config and is about to activate the sites it finds on disk
// (a hook for tests).
var beforeSitesScan = func() {}

// beforeFollowing runs when a reload has checked where "M" leads and is about to read the sites directory target
// (a hook for tests).
var beforeFollowing = func(target string) {}

// reloadOptions are how the reload of setM reads the turbo.config of the sites directory it chose, and how a reload
// reads the one that "M" names.
type reloadOptions struct {
	keepWithoutConfig bool          // Without a turbo.config there, the settings in use stay instead of the defaults
	ignorePointer     bool          // The start directory chosen with setM: its turbo.config's "M" isn't followed, and a pointer counts as none
	keepSession       string        // If the credentials change, the session that stays (the one of setM); the others end
	carried           *parsedConfig // A whole turbo.config whose "M" names that directory, without turbo.config: applied there
	// The sites directory to read instead of the one in use, as "M" (or setM) writes it: it becomes the one in use only
	// when its configuration applies, all at once, and nothing changes otherwise.
	target, targetValue string
	inherited           []inheritedSettings // The global settings of the whole turbo.config files followed on the way
}

// inheritedSettings are the global settings (".") of a whole turbo.config that was followed like a pointer, its "M"
// naming a directory with a turbo.config of its own, with the hash of its plain "P": its credentials apply before
// that one's, which keeps them where it has none of its own (as when the first was applied and the second after).
type inheritedSettings struct {
	settings map[string]interface{}
	password preparedPassword
}

// sitesDirHops is how many times "M" was followed from the start directory to the sites directory in use: a reload
// counts from there, as the next start will, so that a chain that a reload accepts is one that the start accepts too.
// Guarded by settingsUpdateMutex.
var sitesDirHops int

// maxSitesDirHops is how many times Turbo follows "M" from the start directory.
const maxSitesDirHops = 2

// configStamp is what a turbo.config was when it was read: missing, impossible to look at, or a file with its
// modification time and size. The zero value is "unknown", and the file is read whatever it is: with a date as the
// marker, a file dated at the Unix epoch (as some reproducible builds and image layers leave them) was taken for
// one already read, and never applied at start.
type configStamp struct {
	kind    configStampKind
	modTime int64
	size    int64
}

type configStampKind uint8

const (
	stampUnknown    configStampKind = iota // Not read yet, or to be read again
	stampMissing                           // No turbo.config: the defaults
	stampUnreadable                        // Something is there, but it can't even be looked at
	stampFile                              // A file (or a broken link, or a folder) with its date and size
)

// configStampOf looks at the turbo.config at path. Anything there counts as turbo.config, also a broken link or a
// folder: only a missing one means none. The size also tells a rewrite within the same tick of the clock.
func configStampOf(path string) configStamp {
	if info, err := os.Stat(path); err == nil {
		return configStamp{kind: stampFile, modTime: info.ModTime().UnixNano(), size: info.Size()}
	} else if linkInfo, lerr := os.Lstat(path); lerr == nil {
		return configStamp{kind: stampFile, modTime: linkInfo.ModTime().UnixNano(), size: linkInfo.Size()}
	} else if !os.IsNotExist(lerr) {
		return configStamp{kind: stampUnreadable} // parseSiteConfig says why
	}
	return configStamp{kind: stampMissing}
}

// changedSince says whether a turbo.config with this stamp has to be read, after one read with last.
func (stamp configStamp) changedSince(last configStamp) bool {
	return last.kind == stampUnknown || stamp != last
}

// updateSettingsFollowing is updateSettings counting how many times "M" was followed from the start directory
// (redirects). A turbo.config whose "M" leads to another sites directory (a pointer, or a whole one whose "M" names
// another directory) changes nothing where it is: the directory it leads to is read (options.target), and its
// configuration applies there together with the move, in a single section, or nothing changes. Before, the
// configuration in use was emptied first and the target read again: a change of its turbo.config in between (an
// editor that truncates and then writes) left the defaults in use, and requests saw no sites meanwhile. Callers
// hold settingsUpdateMutex.
func updateSettingsFollowing(checkSitesFlag bool, redirects int, options reloadOptions) error {
	following := options.target != "" // A directory that "M" (or setM) leads to: read, and in use only if it applies
	baseDir := sitesDir.Get()
	var lastStamp configStamp // Unknown: a directory that "M" leads to is read whatever its date
	if following {
		baseDir = options.target
	} else {
		withReadLock(func() { lastStamp = configFileStamp })
		refreshLogFiles(baseDir)
	}

	dirEntries, err := os.ReadDir(baseDir)
	if err != nil { // Without the sites, the defaults would leave every site and its settings out
		return &sitesDirError{dir: baseDir, err: err}
	}
	if checkSitesFlag && !following { // Only with the sites directory readable: a disk that doesn't answer deactivates no site
		checkSites()
	}

	stamp := configStampOf(baseDir + configFileName)
	if !following && stamp.kind == stampMissing && configFileLoaded && lastStamp.kind != stampMissing { // It was there: keep what it said
		withGlobalLock(func() { configFileStamp = stamp })
		slog.Warn("turbo.config has disappeared: the configuration in use stays until it exists again", "file", baseDir+configFileName)
		lastStamp = stamp
	}
	withoutConfig := stamp.kind == stampMissing
	changed := stamp.changedSince(lastStamp)
	if options.ignorePointer && !withoutConfig && changed {
		if data, err := os.ReadFile(baseDir + configFileName); err == nil && isSitesDirPointer(data) { // #nosec G304 -- turbo.config of the sites directory chosen by the administrator
			slog.Info("The turbo.config of the sites directory only points to another directory: it is not followed, and saving will write the whole configuration there", "file", baseDir+configFileName)
			withoutConfig = true
		}
	}

	var configErr error
	configRead := false
	sitesActivated := false // Sites found on disk, also checked against PA
	// Without a turbo.config here, setM keeps the settings in use, and the whole turbo.config that named this directory
	// (carried) applies here: its sites are these. Applied in the section below, with the rest.
	keptInUse := changed && withoutConfig && options.keepWithoutConfig
	carried := keptInUse && options.carried != nil
	readConfig := changed && !keptInUse
	var config parsedConfig
	if readConfig { // Read and checked before taking the lock
		config, configErr = parseSiteConfig(baseDir + configFileName)
	}
	// Every sites directory that this turbo.config leads to, through a pointer or the "M" of a whole one, must be
	// usable before anything is applied (sitesDirChainProblem). Outside setM, a pointer must lead to a configuration:
	// applied on its own, it would leave the defaults, the default credentials and an open panel included. One without
	// "M" ({}, or only "^") points nowhere: it is an empty configuration, loaded as such.
	// With TURBO_DIR, the "M" of the whole turbo.config of that directory that is {TURBO_CURRENT_DIR} means that
	// directory, where it was saved when Turbo was started from it: followed, it led to the working directory of the
	// service (another one, without a turbo.config), where no site has its folder. Only that value, which a save writes:
	// one with a folder after it ("{TURBO_CURRENT_DIR}/sites") was taken for that directory too, and the folder it names
	// was never followed. It is followed, as without TURBO_DIR.
	ownDirMeant := false
	if readConfig && configErr == nil && config.raw != nil && !following && sitesDirFromEnv && !isSitesDirPointerMap(config.raw) {
		if value, _ := configSitesDir(config.raw); strings.TrimRight(value, `/\`) == "{"+currentDirPlaceholder+"}" {
			if resolved, err := resolveSitesDir(value); err == nil && sameDir(baseDir, startDir) && !sameDir(resolved, baseDir) {
				ownDirMeant = true
				slog.Warn("The \"M\" of turbo.config is written with {"+currentDirPlaceholder+"}, which with TURBO_DIR is another directory: it is not followed, and the sites directory of TURBO_DIR stays. Saving the configuration writes \"M\" as TURBO_DIR says", "directory", baseDir, "working directory", resolved)
			}
		}
	}
	chainPending := false // The chain of "M" can't be followed now: tried again, as what it waits for (a disk) may come
	if readConfig && configErr == nil && config.raw != nil && !options.ignorePointer && !ownDirMeant {
		if problem := sitesDirChainProblem(config.raw, baseDir, redirects, options.keepWithoutConfig); problem != nil {
			data, _ := os.ReadFile(baseDir + configFileName) // #nosec G304 -- turbo.config of the sites directory in use, for the message
			configErr = &configFileError{path: baseDir + configFileName, data: data, err: problem}
			chainPending = true
		}
	}
	// A turbo.config whose "M" names another sites directory is followed without applying it here. A pointer has no
	// settings. A whole one without a turbo.config there applies there, where its sites are (carried); with one there,
	// that one applies, after the credentials of this one (inherited), as when this one was applied first.
	if readConfig && configErr == nil && config.raw != nil && !options.ignorePointer && !ownDirMeant {
		if value, _ := configSitesDir(config.raw); value != "" {
			if resolved, err := resolveSitesDir(value); err == nil && dirExists(resolved) && !sameDir(resolved, baseDir) {
				_, statErr := os.Lstat(resolved + configFileName)
				next := reloadOptions{
					target: resolved, targetValue: value, keepSession: options.keepSession, inherited: options.inherited,
					// Without a turbo.config there, the settings just read stay, as setM keeps them, to be written there
					// with the next save; the defaults would open the panel.
					keepWithoutConfig: options.keepWithoutConfig || os.IsNotExist(statErr),
				}
				if !isSitesDirPointerMap(config.raw) {
					if os.IsNotExist(statErr) {
						next.carried = &config
					} else {
						next.inherited = append(append([]inheritedSettings(nil), options.inherited...), inheritedSettings{config.raw["."], preparePlainPassword(config.raw["."])})
					}
				}
				beforeFollowing(resolved)
				err := updateSettingsFollowing(checkSitesFlag, redirects+1, next)
				if err == nil || following {
					return err
				}
				// It changed since it was checked: the configuration in use stays, as with a chain that can't be
				// followed, and this turbo.config is read again in the next reload
				configErr = err
				chainPending = true
			}
		}
	}
	if following && configErr != nil { // Nothing changes: the directory that led here stays in use
		return configErr
	}

	kept := keptSiteNames()
	var configs []map[string]map[string]interface{} // The turbo.config that applies, whose domains Turbo knows
	switch {
	case readConfig && configErr == nil:
		configs = append(configs, config.raw)
	case carried:
		configs = append(configs, options.carried.raw)
	}
	known := knownSiteDomains(kept, following, configs...)
	if following { // Those of the directory left: none of them is in this one
		kept = nil
	}
	diskSites, mixedCase := scanDiskSites(baseDir, dirEntries, kept, known)
	folds, foldsKnown := probeNameFoldingKnown(baseDir, diskSites)
	var restoring map[diskSite]map[string]interface{}
	if !following {
		restoring = dormantSectionsFound(diskSites)
	}
	var look *diskLook
	switch { // The configuration that applies: what its validators look at, and the hash of a plain "P", without the lock
	case readConfig && configErr == nil:
		config.password = preparePlainPassword(config.raw["."])
		look = lookAheadSettings(config, baseDir, diskSites, restoring)
	case carried:
		options.carried.password = preparePlainPassword(options.carried.raw["."])
		look = lookAheadSettings(*options.carried, baseDir, diskSites, restoring)
	default:
		look = lookAheadSettings(parsedConfig{}, baseDir, diskSites, restoring)
	}
	var panelLook panelCertificateLook
	if following {
		panelLook = lookAtPanelCertificate(baseDir, "") // The panel's certificate of the new directory, read without the lock
	}

	// In a single section: what came from the file is replaced and the sites found on disk are activated, so no
	// request sees a half-loaded configuration; the certificates are published once, at the end, so TLS keeps
	// answering meanwhile. What the validators look at on the disk was looked at before taking the lock. Moving to
	// another directory empties what belonged to the one left in the same section.
	beforeSitesScan()
	withDiskLook(look, func() {
		// A panic while the file is applied (a bug of a validator) is recovered by whoever runs the reload, with what
		// came from the file already emptied: the file isn't noted as read, so the next reload applies it again, whole.
		// Noted, the sites stayed with the defaults, without their preprocessors, until the file changed.
		defer func() {
			if failure := recover(); failure != nil {
				configFileStamp = configStamp{}
				certificatePublishPaused, loadingConfig = false, false
				panic(failure)
			}
		}()
		credentials := panelUser.Get() + "\x00" + panelPasswordHash.Get()
		if following {
			certificatePublishPaused = true
			resetSitesLocked()
			sitesDir.Set(baseDir)
			sitesDirValue.Set(options.targetValue)
			sitesDirHops = redirects
			if sameDir(baseDir, startDir) { // Back in the start directory, however it got there: the next start counts from it
				sitesDirHops = 0
			}
			for _, inherited := range options.inherited {
				loadCredentials(inherited.settings, inherited.password)
			}
		}
		switch {
		case readConfig && chainPending:
			// Not noted as read: the directory that its "M" waits for may appear without this file changing (a disk
			// mounted later), and it was followed only at the next start. The error is logged when it changes
			// (logConfigError).
		case readConfig:
			configFileStamp = stamp // Not read again until it changes, also if it is invalid
			if configErr == nil {
				certificatePublishPaused = true
				inUse := siteCertificates // applySiteConfig makes the map anew
				if !following {
					// What keepCertificatesInUseLocked keeps, as the validator S applies the file
					certificatesBeforeApply = inUse
					defer func() { certificatesBeforeApply = nil }() // Also after a panic, with the lock still held
				}
				applySiteConfig(config)
				if !following {
					keepCertificatesInUseLocked(inUse)
				}
				configFileLoaded = stamp.kind != stampMissing
				configFileDigest = config.digest
			}
		case keptInUse:
			configFileStamp = stamp
			configFileLoaded = true // Kept as if it came from a file there
			if carried {
				certificatePublishPaused = true
				applySiteConfig(*options.carried) // Its "M" names this directory: unchanged
			}
		}
		if panelUser.Get()+"\x00"+panelPasswordHash.Get() != credentials { // As with setU and setP
			closeOtherSessions(options.keepSession)
		}
		if sitesDir.Get() == baseDir { // Not the folders of a directory that "M" leaves: they aren't its sites
			// Where it couldn't be looked at (no site with letters in its name was found: a share that didn't answer),
			// what was known of this directory stays: taken as false, the rewrites that close a folder and the names
			// of Windows stopped applying until the next reload.
			if !foldsKnown && !following {
				folds = sitesDirFolds.Load()
			}
			if sitesDirFolds.Swap(folds) != folds && !namesIgnoreCase {
				if folds {
					slog.Info("The sites directory takes names in other capitals for the same file: paths and rewrites are treated as on a system that ignores case", "directory", baseDir)
				} else {
					slog.Info("The sites directory no longer takes names in other capitals for the same file: paths and rewrites are treated as the system does", "directory", baseDir)
				}
			}
			sitesActivated = activateDiskSites(diskSites, checkSitesFlag)
			dropAliasesOfSites() // Once all the sites are in: a site wins over an alias of its host
			warnMixedCaseLocked(mixedCase)
		}
		if following { // Once the sites' certificates are in: it publishes them all
			applyPanelCertificate(baseDir, panelLook)
		}
		if certificatePublishPaused {
			certificatePublishPaused = false
			publishCertificates()
		}
	})
	if following {
		refreshLogFiles(baseDir)
		slog.Info("Sites directory", "directory", baseDir)
	}
	switch {
	case readConfig && configErr == nil:
		configRead = true
		if stamp.kind == stampMissing {
			slog.Info("No turbo.config: default configuration")
		} else {
			slog.Info("turbo.config read and applied")
		}
	case carried:
		configRead = true
		slog.Info("Sites directory without turbo.config: the turbo.config that names it applies here, and saving writes it here", "directory", baseDir)
	case keptInUse:
		slog.Info("Sites directory without turbo.config: the global settings, the credentials and the lists in use are kept", "directory", baseDir)
	}

	var knownStamp string
	withReadLock(func() { knownStamp = panelCertificateStamp })
	panelLook = lookAtPanelCertificate(baseDir, knownStamp) // Read without the lock
	withGlobalLock(func() { applyPanelCertificate(baseDir, panelLook) })
	loadPendingCertificates() // Sites with HTTPS on whose certificate couldn't be loaded yet
	refreshSiteCertificates() // And those whose files changed on disk

	if configRead || sitesActivated { // After the sites on disk are activated, which PA is checked against
		withReadLock(warnPanelOrigin)
	}
	return configErr
}

// lookAheadSettings looks at the disk, before the reload takes the global lock, for what the validators will look
// at under it: the sites directory of M, the folders of each site of config, the certificate files of each site
// of config (also of a site without a "" section, which gets the state of its certificate as a new site), of the
// disk and of restoring (the settings kept for the sites of the disk that come back; loaded when the site has
// HTTPS on) and the executables of their preprocessors.
func lookAheadSettings(config parsedConfig, baseDir string, disk []diskSite, restoring map[diskSite]map[string]interface{}) *diskLook {
	look := newDiskLook()
	if value, present := configSitesDir(config.raw); present {
		if resolved, err := resolveSitesDir(value); err == nil {
			look.stat(resolved)
		}
		if inUse, err := resolveSitesDir(sitesDir.Get()); err == nil {
			look.stat(inUse)
		}
	}
	for domain, subdomains := range config.raw {
		switch domain {
		case "_", "@", "#", ".", "^": // Not sites
			continue
		}
		look.siteFolders(baseDir, domain, "")
		if _, described := subdomains[""]; !described { // It gets the state of its certificate, as a new site
			look.siteFiles(baseDir+siteFolder(domain, ""), false)
		}
		for subdomain, content := range subdomains {
			if subdomain != "" {
				look.siteFolders(baseDir, domain, subdomain)
			}
			settings, _ := content.(map[string]interface{})
			look.siteSection(baseDir, domain, subdomain, settings)
		}
	}
	for _, site := range disk {
		look.siteFiles(baseDir+siteFolder(site.site, site.subdomain), false)
	}
	for site, settings := range restoring {
		look.siteSection(baseDir, site.site, site.subdomain, settings)
	}
	return look
}

// httpsSetting says whether an "S" of turbo.config turns HTTPS on, as its validator reads it: anything but 0.
func httpsSetting(value interface{}) bool {
	switch typed := value.(type) {
	case string:
		return typed != "" && typed != "0"
	case float64:
		return typed != 0
	case bool:
		return typed
	}
	return false
}

// parsedConfig is a turbo.config read and checked but not applied: its content (nil without a file) and schema.
type parsedConfig struct {
	raw      map[string]map[string]interface{}
	schema   int
	digest   [sha256.Size]byte // Of the file read, for configFileDigest
	password preparedPassword  // The hash of its plain "P", made before the global lock (preparePlainPassword)
}

// parseSiteConfig reads and checks the turbo.config at configPath without changing anything in use, so it runs
// without the global lock. A file that can't be read or isn't valid gives a *configFileError; a missing
// one, a parsedConfig without content (the defaults).
func parseSiteConfig(configPath string) (parsedConfig, error) {
	if _, statErr := os.Lstat(configPath); statErr != nil && os.IsNotExist(statErr) {
		return parsedConfig{}, nil
	}
	configBytes, err := os.ReadFile(configPath) // #nosec G304 -- path under the sites directory chosen by the administrator (TURBO_DIR or M)
	if err != nil {
		return parsedConfig{}, &configFileError{path: configPath, err: err}
	}
	var raw map[string]map[string]interface{}
	if err = parseConfig(configBytes, &raw); err != nil {
		return parsedConfig{}, &configFileError{path: configPath, data: configBytes, err: err}
	}
	if err = panelSettingsProblem(raw["."]); err != nil {
		return parsedConfig{}, &configFileError{path: configPath, data: configBytes, err: err}
	}
	if err = siteSectionsProblem(raw); err != nil { // Before dropControlChars, which would drop a section that is a string
		return parsedConfig{}, &configFileError{path: configPath, data: configBytes, err: err}
	}
	dropControlChars(raw)
	schemaRead, err := migrateConfig(raw, configBytes)
	if err != nil {
		return parsedConfig{}, &configFileError{path: configPath, data: configBytes, err: err}
	}
	if pointsToItself(raw, configPath) {
		return parsedConfig{}, &configFileError{path: configPath, data: configBytes, err: configSelfPointerError{}}
	}
	return parsedConfig{raw: raw, schema: schemaRead, digest: sha256.Sum256(configBytes)}, nil
}

// applySiteConfig puts in use a turbo.config from parseSiteConfig, or the defaults without one. The file is the
// source of truth: all that came from it before is emptied first, and what isn't in it stops applying;
// sites, keys and entries are applied in a fixed order, so the result never depends on the order of a map.
// Callers hold the global lock.
func applySiteConfig(config parsedConfig) {
	if config.raw == nil {
		configSchemaRead = configSchema
		setDefaultSettings()
		return
	}
	clearFileSettings()
	defer publishLoadedDeniedIPs() // The file's denied IPs replace the ones in use at once, when all is applied
	rawConfigMap = config.raw
	configSchemaRead = config.schema
	if configSchemaRead < configSchema {
		slog.Warn("Configuration in schema " + strconv.Itoa(configSchemaRead) + ": the migration will apply when saving")
	} else if configSchemaRead > configSchema {
		slog.Warn("Configuration in schema " + strconv.Itoa(configSchemaRead) + ", later than this version's (" + strconv.Itoa(configSchema) + "): what is understood is loaded, and it will not be saved without confirmation")
	}
	loadCredentials(rawConfigMap["."], config.password)
	loadPanelCertSettings(rawConfigMap["."])
	var keyExists bool
	var stringValue string
	var configKey string
	for _, configKey = range []string{"_", "@", "#"} { // Replacements first: they don't depend on the rest
		if _, keyExists = rawConfigMap[configKey]; keyExists { // This is for another kind of lists in config file
			for _, subKey := range sortedKeys(rawConfigMap[configKey]) {
				subValue := rawConfigMap[configKey][subKey]
				stringValue, keyExists = configNumberOrString(subValue) // A string, or a JSON integer (the date of a denied IP)
				if !keyExists {
					slog.Warn("turbo.config entry discarded: wrong type (a string or an integer is expected)", "list", configKey, "key", subKey)
					continue
				}
				applied, problem := adminAddHandlers[configKey](subKey, stringValue)
				if applied || listEntryUnchanged(problem) {
					continue
				}
				switch {
				case configKey == "_" && problem != msgFixedReplacement:
					slog.Warn("turbo.config character replacement discarded", "character", subKey, "replacement", stringValue, "reason", problem)
				case configKey == "@" && problem != msgExpiredDate: // An expired denial is no mistake: it ended
					slog.Warn("turbo.config denied IP discarded", "ip", subKey, "date", stringValue, "reason", problem)
				case configKey == "#":
					slog.Warn("turbo.config response discarded", "code", subKey, "reason", problem)
				}
			}
			continue
		}
	}
	if _, keyExists = rawConfigMap["@"]; keyExists {
		slog.Info("Denied IPs active", "total", len(deniedIPsInUse()))
	}
	// The conditions between settings are checked once all of them are in
	loadingConfig = true
	for configKey = range defaultSettingValidators { // Default settings check
		if _, keyExists = rawConfigMap[configKey]; keyExists {
			if _, keyExists = rawConfigMap[configKey]["C"]; keyExists { // "Save" is an action, not a setting: never run while loading
				slog.Warn("turbo.config key ignored: saving is a panel action (setC), not a setting", "key", "C")
			}
			// A setting written with another name ("pa" for "PA") was lost without a word, and its default applied. Only
			// its name is logged: what was meant may be a password.
			for _, key := range sortedKeys(rawConfigMap[configKey]) {
				if !slices.Contains(defaultSettingKeysGroup[configKey], key) && !otherGlobalSettingKeys[key] {
					slog.Warn("turbo.config setting ignored: no setting has that name", "key", key)
				}
			}
			for _, subValue := range defaultSettingKeysGroup[configKey] {
				if rawValue, present := rawConfigMap[configKey][subValue]; present {
					var reason string
					if stringValue, keyExists = configNumberOrString(rawValue); keyExists {
						var applied bool
						if applied, reason = defaultSettingValidators[configKey][subValue](stringValue, internalAuth); applied {
							continue
						}
						if _, keyExists = defaultSettingErrorExceptions[configKey][subValue][reason]; keyExists { // A refusal that keeps the setting as it is ("Value unchanged")
							continue
						}
					} else {
						reason = "wrong type (a string or an integer is expected)"
					}
					if subValue == "M" { // It has no default to go back to
						slog.Warn("turbo.config setting discarded: the sites directory in use stays", "key", subValue, "value", configValueForLog(subValue, rawValue), "reason", reason)
					} else {
						slog.Warn("turbo.config setting discarded: the default value is used", "key", subValue, "value", configValueForLog(subValue, rawValue), "reason", reason)
					}
				}
				defaultSettingsResetFallbacks[configKey][subValue]()
			}
		} else {
			for subMap := range defaultSettingsResetFallbacks[configKey] {
				defaultSettingsResetFallbacks[configKey][subMap]()
			} // Reset specific defaults if doesn't exists
		}
	}
	loadingConfig = false
	enforceSettingInvariants()
	for _, domain := range sortedKeys(rawConfigMap) { // Site & subdomains existence check, in a fixed order
		if _, keyExists = defaultSettingValidators[domain]; keyExists {
			continue
		}
		// The root and each subdomain on their own: a root without its @ (a deploy that replaces it) left its subdomains
		// out, with their folders there
		rootActive := siteExistenceCheck(domain, "")
		if !rootActive {
			keepDormantFromFile(domain, "") // Its folder or its @ may appear later
		} else if _, described := rawConfigMap[domain][""]; !described {
			// Built just now, empty (the file's sites were emptied first). Without a "" section the file doesn't describe
			// it: it is a site whose folder is there, as one found on disk. A "" section says all it has, no index included.
			newSiteContentLocked(domain, "")
		}
		for _, subKey := range sortedKeys(rawConfigMap[domain]) {
			if _, keyExists = subdomainContentCheckers[subKey]; keyExists || subKey == "" && !rootActive {
				continue
			}
			if subKey != "" && !siteExistenceCheck(domain, subKey) {
				keepDormantFromFile(domain, subKey)
				continue
			}
			subdomainData, keyExists := rawConfigMap[domain][subKey].(map[string]interface{})
			if !keyExists {
				continue
			}
			for _, settingKey := range subdomainContentOrder { // Subdomains content check
				if _, keyExists = subdomainData[settingKey]; keyExists {
					subdomainContentCheckers[settingKey](false, subdomainData[settingKey], true, domain, subKey)
				}
			}
		}
	}
	rawConfigMap = make(map[string]map[string]interface{})
}

// keepCertificatesInUseLocked puts back, after a turbo.config was applied over the same sites directory, the
// certificate that each site with HTTPS had in use (inUse) and that its files didn't give again: a pair that can't
// be loaded now (a chain renewed whose key hasn't come yet, a key that can't be read), or files that "Delete SSL"
// removed while the certificate stayed in use. Applying the file emptied every certificate and read them from the
// disk, so an edit of turbo.config left such a site with HTTPS on and without a certificate: its handshakes failed. Its
// stamp says that its files couldn't be loaded, so the look of every 30 s reads them again (refreshSiteCertificates).
// Callers hold the global lock.
func keepCertificatesInUseLocked(inUse map[string]*tls.Certificate) {
	// It warns of each, and nothing else does: the validator S doesn't say that HTTPS waits for the pair
	// (certificatesBeforeApply), nor does the look that follows (refreshSiteCertificates). Three warnings were written,
	// and the first said that HTTPS waited, while the certificate in use went on.
	for siteKey, cert := range inUse {
		if _, loaded := siteCertificates[siteKey]; loaded || cert == nil || !httpsEnabled(siteKey) {
			continue
		}
		siteCertificates[siteKey] = cert
		siteCertificateStamps[siteKey] = unloadableStampMark
		slog.Warn("The certificate files of a site can't be loaded: the certificate in use stays", "site", siteKey)
	}
}

// certificatesBeforeApply are the certificates that the sites had in use while a turbo.config is applied over the
// same sites directory, nil otherwise: keepCertificatesInUseLocked keeps those whose pair the validator S can't load,
// so S doesn't say then that HTTPS waits for it. Guarded by the global lock.
var certificatesBeforeApply map[string]*tls.Certificate

// subdomainContentOrder is the order in which the content of a site of turbo.config is applied.
var subdomainContentOrder = []string{"!", "=", "$", ".", "?", "-", "&"}

// clearFileSettings empties, before a turbo.config is applied, everything that comes from it: the sites with
// their settings and certificates (also those kept for sites without their folder), the denied IPs, and the
// character replacements and responses that aren't fixed. Callers hold the global lock, and pause the publication
// of certificates (certificatePublishPaused) until the new ones are loaded.
func clearFileSettings() {
	sitesMap = make(map[string]map[string]map[string]string)
	dormantSites = make(map[string]map[string]string)
	siteSSLConfig = make(map[string]*siteSettings)
	mimeTypes = make(map[string]map[string]string)
	customHeaders = make(map[string]map[string]string)
	preprocessors = make(map[string]map[string]string)
	indexFiles = make(map[string]map[string]int)
	domainAliases = make(map[string]string)
	siteCertificates = make(map[string]*tls.Certificate)
	siteCertificateStamps = make(map[string]string)
	deniedIPsLoading = make(map[string]int64) // Published whole when applySiteConfig ends: the list in use stays meanwhile
	for char := range charReplacements {
		if !fixedCharReplacements[char] {
			delete(charReplacements, char)
		}
	}
	responses := make(map[int]string)
	for code, response := range *httpResponses.Load() {
		if fixedHTTPResponses[code] {
			responses[code] = response
		}
	}
	httpResponses.Store(&responses)
}

// certificatePublishPaused, while a turbo.config is applied, keeps setSiteCertificate from publishing each
// certificate: the ones in use stay published until all are loaded. Guarded by globalMutex.
var certificatePublishPaused bool

// diskSite is a site folder found on disk with its public folder: a site, or a subdomain of one.
type diskSite struct {
	site      string
	subdomain string
}

// scanDiskSites lists the site folders of baseDir that have a public folder (@) that can be listed, the ones a reload
// activates. A folder whose name has capital letters isn't a site's, as no host has them. On a file system that
// ignores case (Windows, macOS), though, the folder of a site kept without its folder (kept, from keptSiteNames) that
// comes back with other capitals is that site's, and brings it back; the other site folders with capitals are listed
// in mixedCase, to be logged once. The subdomains of a domain whose own @ isn't there, or can't be listed, are looked
// at only for the domains that Turbo knows (known, from knownSiteDomains): any folder of the sites directory, a copy
// of one ("backup/example.com/@") among them, became a host with the defaults, its scripts served as text. It reads
// the disk, so it runs without the global lock.
func scanDiskSites(baseDir string, dirEntries []os.DirEntry, kept map[string]map[string]bool, known map[string]bool) (found []diskSite, mixedCase []string) {
	for _, entry := range dirEntries { // This is used when input is like: #.domain.com
		entryName := entry.Name()
		if entryName == panelCertDirName { // Never a site: nothing of it is served
			continue
		}
		wildcardName := putWildcards(entryName)
		if lower := strings.ToLower(wildcardName); lower != wildcardName {
			if hostValid, _ := hostOk(lower, false); !hostValid || !publicFolderThere(baseDir+entryName) {
				continue // Not a site's folder
			}
			if len(kept[lower]) == 0 || !sameFolder(baseDir+entryName, baseDir+changeWildcards(lower)) {
				mixedCase = append(mixedCase, entryName)
				continue
			}
			wildcardName = lower
		}
		if hostValid, _ := hostOk(wildcardName, false); !hostValid {
			continue
		}
		rootReadable := publicFolderReadable(baseDir + entryName)
		if !rootReadable && !known[wildcardName] {
			continue
		}
		subdirEntries, err := os.ReadDir(baseDir + entryName)
		if err != nil {
			continue
		}
		if rootReadable {
			found = append(found, diskSite{wildcardName, ""})
		}
		for _, subEntry := range subdirEntries {
			subFolder := baseDir + entryName + "/" + subEntry.Name()
			subWildcardName := putWildcards(subEntry.Name())
			if lower := strings.ToLower(subWildcardName); lower != subWildcardName {
				if hostValid, _ := hostOk(lower+"."+changeWildcards(wildcardName, "x"), false); !hostValid || !publicFolderThere(subFolder) {
					continue
				}
				if !kept[wildcardName][lower] || !sameFolder(subFolder, baseDir+entryName+"/"+changeWildcards(lower)) {
					mixedCase = append(mixedCase, entryName+"/"+subEntry.Name())
					continue
				}
				subWildcardName = lower
			}
			if hostValid, _ := hostOk(subWildcardName+"."+changeWildcards(wildcardName, "x"), false); !hostValid {
				continue
			}
			if !publicFolderReadable(subFolder) { // As for the root: one that can't be listed was activated, and a root wasn't
				continue
			}
			found = append(found, diskSite{wildcardName, subWildcardName})
		}
	}
	return found, mixedCase
}

// publicFolderReadable reports whether the public folder (@) of folder is a folder that can be listed, asking for
// one of its entries. Listed whole, and sorted, every site's was read every 30 s only to learn this.
func publicFolderReadable(folder string) bool {
	public, err := os.Open(folder + "/" + publicDirName) // #nosec G304 -- the public folder of a site folder of the sites directory
	if err != nil {
		return false
	}
	defer public.Close()
	_, err = public.Readdirnames(1)
	return err == nil || err == io.EOF
}

// publicFolderThere reports whether folder has a public folder (@).
func publicFolderThere(folder string) bool {
	info, err := os.Stat(folder + "/" + publicDirName)
	return err == nil && info.IsDir()
}

// sameFolder reports whether a and b are the same folder: on a file system that ignores case, two names that differ
// only in their capitals.
func sameFolder(a string, b string) bool {
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(infoA, infoB)
}

// knownSiteDomains are the domains whose folder scanDiskSites looks into without a readable @ of their own: those of
// the sites active or kept without their folder (kept), unless the reload follows to another directory, which has none
// of them, and those of the turbo.config that applies (configs).
func knownSiteDomains(kept map[string]map[string]bool, following bool, configs ...map[string]map[string]interface{}) map[string]bool {
	known := make(map[string]bool)
	if !following {
		for domain := range kept {
			known[domain] = true
		}
		withReadLock(func() {
			for domain := range sitesMap {
				known[domain] = true
			}
		})
	}
	for _, raw := range configs {
		for domain := range raw {
			known[domain] = true
		}
	}
	return known
}

// keptSiteNames are the names of the sites kept without their folder (dormantSites), for scanDiskSites.
func keptSiteNames() map[string]map[string]bool {
	kept := make(map[string]map[string]bool)
	withReadLock(func() {
		for domain, subdomains := range dormantSites {
			kept[domain] = make(map[string]bool, len(subdomains))
			for subdomain := range subdomains {
				kept[domain][subdomain] = true
			}
		}
	})
	return kept
}

// warnMixedCaseLocked logs, once each, the site folders with capital letters that scanDiskSites found: no site is
// served from them. Callers hold the global lock.
func warnMixedCaseLocked(folders []string) {
	for _, folder := range folders {
		if key := "capitals:" + folder; !warnedDiskSites[key] {
			warnedDiskSites[key] = true
			slog.Warn("Site folder with capital letters, which no host has: it isn't served; rename it in lower case", "folder", folder)
		}
	}
}

// activateDiskSites activates the sites found on disk that aren't active yet, and reports whether there was any:
// with the settings kept for them if their folder had gone or turbo.config has them (dormantSites), or else with
// the defaults. Callers hold the global lock.
func activateDiskSites(found []diskSite, logThem bool) bool {
	activated := false
	for _, disk := range found {
		if siteExists(disk.site, disk.subdomain) {
			continue
		}
		if problem := siteNameProblem(disk.site, disk.subdomain); problem != "" {
			if name := disk.subdomain + "/" + disk.site; !warnedDiskSites[name] {
				warnedDiskSites[name] = true
				slog.Warn("Site folder on disk that is not activated", "site", disk.site, "subdomain", disk.subdomain, "reason", problem)
			}
			continue
		}
		siteKey := disk.site
		if disk.subdomain != "" {
			siteKey = disk.subdomain + "." + disk.site
		}
		warnSiteNamedAsIPLocked(siteKey)
		activated = true
		if kept, dormant := dormantSites[disk.site][disk.subdomain]; dormant {
			restoreDormantLocked(disk.site, disk.subdomain, kept)
			slog.Info("Site folder back: the site is activated with its settings", "site", siteKey)
			continue
		}
		constructSiteWithoutIndex(disk.site, disk.subdomain)
		newSiteContentLocked(disk.site, disk.subdomain) // With index.html, as a new site
		if logThem {
			slog.Info("Site created on disk and activated", "site", siteKey)
		}
	}
	return activated
}

// configNumberOrString returns a value of turbo.config as the text its validator takes: a string as it is, and a
// JSON number only if it is an integer ("MBB": 5242880 is "5242880"). ok is false for anything else.
func configNumberOrString(value interface{}) (text string, ok bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case float64:
		if typed == math.Trunc(typed) && math.Abs(typed) < 1<<53 {
			return strconv.FormatInt(int64(typed), 10), true
		}
	}
	return "", false
}

// configValueForLog is a value of turbo.config to show in the log: the password and its hash never are.
func configValueForLog(key string, value interface{}) string {
	if key == "P" || key == "PH" {
		return "(hidden)"
	}
	text := fmt.Sprint(value)
	if len(text) > 120 {
		text = text[:120] + "..."
	}
	return text
}

func setDefaultSettings() {
	for group := range defaultSettingsResetFallbacks {
		for setting := range defaultSettingsResetFallbacks[group] {
			defaultSettingsResetFallbacks[group][setting]()
		}
	}
}

func siteExistenceCheck(domain string, subdomain string) bool {
	var passed bool
	var checker string
	for checker = range siteExistenceCheckers {
		if passed, _ = siteExistenceCheckers[checker](true, domain, subdomain); !passed {
			return false
		}
	}
	return true
}
