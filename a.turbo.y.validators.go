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
	"sync/atomic"
	"time"
	"turbo/customNetHttp"
)

var (
	currentDirPlaceholder = "TURBO_CURRENT_DIR"
	rawConfigMap          map[string]map[string]interface{}

	siteExistenceResetFallbacks = map[string]func(string, string){ // Site & subdomains existence check reset fallback
		"/": func(domain string, subdomain string) {},
	}

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
				return false, "Nombre incorrecto de directorio de sitio"
			}
			domainDir = changeWildcards(domainDir)
			pathSeparator := ""
			if subdomainDir != "" {
				pathSeparator = "/"
				subdomainDir = changeWildcards(subdomainDir)
			}
			_, readErr := os.ReadDir(sitesDir.Get() + domainDir + pathSeparator + subdomainDir)
			if readErr != nil {
				return false, "Directorio de sitio inexistente: " + domainDir + pathSeparator + subdomainDir
			}
			_, readErr = os.ReadDir(sitesDir.Get() + domainDir + pathSeparator + subdomainDir + "/" + publicDirName)
			if readErr != nil {
				return false, "Directorio de contenido de sitio inexistente: " + domainDir + pathSeparator + subdomainDir + "/" + publicDirName
			}
			if checkExists && !siteExists(origDomain, origSubdomain) {
				_constructSite(origDomain, origSubdomain)
			}
			return true, "Directorio de sitio procesado"
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
			"MHB": func() { maxHeaderBytes.Store(5000) }, // Need to be set first.
			"MBB": func() { maxBodySize.Store(1048576) }, // 1 Mb
			"CIL": func() { atomic.StoreInt64(&serverRequestLimits[0], 10000*int64(time.Millisecond)) },
			"CIS": func() { atomic.StoreInt64(&serverRequestLimits[1], 1000*int64(time.Millisecond)) }, // Need to be first to be set
			"CII": func() { atomic.StoreInt64(&serverRequestLimits[2], 100) },
			"RT":  func() { setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.RT = 5 * time.Second }) }, // Need to be first to be set
			"RHT": func() { setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.RHT = 1 * time.Second }) },
			"WT":  func() { setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.WT = 10 * time.Second }) },
			"IT":  func() { setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.IT = 2 * time.Second }) },
		},
	}

	adminDeleteHandlers = map[string]func(string) (bool, string){
		"@": func(ip string) (bool, string) {
			if _, exists := deniedIPList()[ip]; !exists {
				return false, "IP inexistente"
			}
			setDeniedIPs(func(list map[string]int64) { delete(list, ip) })
			return true, "IP denegado eliminado"
		},
		"#": func(httpCode string) (bool, string) {
			code, err := strconv.Atoi(httpCode)
			if err != nil {
				return false, "Código HTTP inválido"
			}
			var exists bool
			if _, exists = (*httpResponses.Load())[code]; !exists {
				return false, "Respuesta inexistente"
			}
			if _, exists = fixedHTTPResponses[code]; exists {
				return false, "Respuesta inmutable"
			}
			setHTTPResponses(func(responses map[int]string) { delete(responses, code) })
			return true, "Respuesta a código HTTP eliminada"
		},
		"_": func(char string) (bool, string) {
			unescaped := char
			unescaped = replaceURIChars(unescaped)
			var exists bool
			if _, exists = charReplacements[unescaped]; !exists {
				return false, "Reemplazo inexistente"
			}
			if _, exists = fixedCharReplacements[unescaped]; exists {
				return false, "Reemplazo inmutable"
			}
			delete(charReplacements, unescaped)
			return true, "Reemplazo a caracter(es) eliminado"
		},
	}

	adminAddHandlers = map[string]func(string, string) (bool, string){
		"@": func(ip string, unixDate string) (bool, string) {
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil || parsedIP.IsUnspecified() {
				return false, "IP incorrecto"
			}
			if parsedIP.IsLoopback() {
				return false, "IP localhost"
			}
			address := ipAddr(ip)
			dateText := strings.TrimSpace(unixDate)
			parsedUnix, parseErr := strconv.ParseInt(dateText, 10, 64)
			if parseErr != nil {
				return false, "Fecha UNIX incorrecta"
			}
			existingUnix, exists := deniedIPList()[address]
			if parsedUnix == 0 || time.Now().Unix() > parsedUnix {
				if exists {
					setDeniedIPs(func(list map[string]int64) { delete(list, address) })
					return true, "IP denegado eliminado"
				}
				return false, "Fecha UNIX expirada"
			}
			isModified := true
			change := "agregado"
			if strconv.FormatInt(existingUnix, 10) == dateText {
				isModified = false
				change = "sin cambios"
			} else if exists {
				change = "modificado"
			}
			setDeniedIPs(func(list map[string]int64) { list[address] = parsedUnix })
			return isModified, "IP denegado " + change
		},
		"#": func(httpCode string, response string) (bool, string) {
			value := response
			codeInt, parseErr := strconv.Atoi(httpCode)
			if parseErr != nil {
				return false, "Código HTTP inválido"
			}
			if (codeInt < 400 || codeInt > 599) && codeInt != 0 {
				return false, "Código HTTP incorrecto"
			}
			value = strings.TrimSpace(value)
			length := len(value)
			if length < 1 || length > 2048 {
				return false, "Respuesta muy corta o larga"
			}
			current, exists := (*httpResponses.Load())[codeInt]
			if exists && current == value {
				return false, "Respuesta sin cambios"
			}
			setHTTPResponses(func(responses map[int]string) { responses[codeInt] = value })
			return true, "Respuesta guardada"
		},
		"_": func(char string, replacement string) (bool, string) {
			unescapedChar := replaceURIChars(char)
			unescapedRepl := replaceURIChars(replacement)
			for fixedChar := range fixedCharReplacements {
				if (strings.IndexByte(char, fixedChar[0]) != -1 && char != fixedChar) || (strings.IndexByte(unescapedChar, fixedChar[0]) != -1 && unescapedChar != fixedChar) {
					return false, "Caracter de reemplazo inválido"
				}
				if strings.IndexByte(replacement, fixedChar[0]) != -1 || strings.IndexByte(unescapedRepl, fixedChar[0]) != -1 {
					return false, "Reemplazo inválido"
				}
			}
			var length int
			if unescapedChar != " " {
				unescapedChar = strings.TrimSpace(unescapedChar)
				length = len(unescapedChar)
				if length < 1 {
					return false, "Sin caracter"
				}
				if length > 4 {
					return false, "Muchos caracteres"
				}
			}
			if unescapedRepl != " " {
				unescapedRepl = strings.TrimSpace(unescapedRepl)
				length = len(unescapedRepl)
				if length < 1 || length > 16 {
					return false, "Reemplazo muy corto o largo"
				}
			}
			if current, exists := charReplacements[unescapedChar]; exists && current == unescapedRepl {
				return false, "Reemplazo sin cambios"
			}
			charReplacements[unescapedChar] = unescapedRepl
			return true, "Reemplazo de caracter(es) guardado"
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
		".": {"C", "M", "PA", "MUB", "MHB", "MBB", "CIL", "CIS", "CII", "RT", "RHT", "WT", "IT"},
	}

	defaultSettingErrorExceptions = map[string]map[string]map[string]bool{ // ME (E, for exceptions). There are some exceptions on errors, some cause unnecessary resets
		".": {
			"M":   map[string]bool{"Directorio de sitios sin cambios": true},
			"PA":  map[string]bool{"Valor sin cambios": true},
			"MUB": map[string]bool{"Valor sin cambios": true},
			"MHB": map[string]bool{"Valor sin cambios": true},
			"MBB": map[string]bool{"Valor sin cambios": true},
			"CIL": map[string]bool{"Valor sin cambios": true},
			"CIS": map[string]bool{"Valor sin cambios": true},
			"CII": map[string]bool{"Valor sin cambios": true},
			"RT":  map[string]bool{"Valor sin cambios": true},
			"RHT": map[string]bool{"Valor sin cambios": true},
			"WT":  map[string]bool{"Valor sin cambios": true},
			"IT":  map[string]bool{"Valor sin cambios": true},
		},
	}

	defaultSettingValidators = map[string]map[string]func(...string) (bool, string){ // Default settings check
		".": {
			"C": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " en C"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña incorrecta"
				}
				if configSchemaRead > configSchema && args[0] != "sobrescribir" {
					return false, "turbo.config es de una versión posterior de Turbo (esquema " + strconv.Itoa(configSchemaRead) + "): guardar perdería sus ajustes nuevos. Para sobrescribirlo, confírmelo (en la API, a=sobrescribir)"
				}
				if !saveDefaultConfig() {
					return false, "Error al guardar"
				}
				return true, "Configuración guardada"
			},
			"U": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " en U"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña actual incorrecta"
				}
				length := len(args[0])
				if length < 1 || length > 24 {
					return false, "Usuario muy largo o corto"
				}
				if args[0] == panelUser.Get() {
					return false, "Usuario sin cambios"
				}
				panelUser.Set(args[0])
				return true, "Usuario cambiado"
			},
			"P": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " en P"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña actual incorrecta"
				}
				length := len(args[0])
				if length < 1 || length > 24 {
					return false, "Contraseña muy larga o corta"
				}
				if passwordMatches(args[0]) {
					return false, "Contraseña sin cambios"
				}
				setPanelPassword(args[0])
				return true, "Contraseña cambiada"
			},
			"M": func(args ...string) (bool, string) {
				if len(args) < 2 {
					return false, msgMissingData + " en D"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña actual incorrecta"
				}

				args[0] = putSlash(args[0])
				if args[0] == sitesDir.Get() {
					return false, "Directorio de sitios sin cambios"
				}

				args[0] = strings.Replace(args[0], "{"+currentDirPlaceholder+"}", currentDir(), 1)
				info, err := os.Stat(args[0])
				if err != nil || !info.IsDir() { // Doesn't exist or the path isn't valid on this system
					return false, "Directorio de sitios inexistente"
				}
				sitesDir.Set(args[0])
				return true, "Directorio de sitios configurado"
			},
			"PA": func(args ...string) (bool, string) { // Where the panel answers (DP7)
				if len(args) != 2 {
					return false, msgMissingData + " en PA"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña actual incorrecta"
				}
				list, errorMsg := parsePanelAccess(args[0])
				if list == nil {
					return false, errorMsg
				}
				if list.setting == panelAccess.Load().setting {
					return false, "Valor sin cambios"
				}
				panelAccess.Store(list)
				if list.setting == "" {
					return true, "Panel accesible desde cualquier host"
				}
				return true, "Hosts y redes del panel guardados"
			},
			"MUB": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " en MUB"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña actual incorrecta"
				}
				value, err := strconv.Atoi(args[0])
				if err != nil {
					return false, "Valor incorrecto"
				}
				if int64(value) == maxURILength.Load() {
					return false, "Valor sin cambios"
				}
				if value < 40 {
					return false, "Inferior a 40 bytes"
				}
				if value > 10240 {
					return false, "Superior a 10240 bytes"
				}
				maxURILength.Store(int64(value))
				return true, "Longitud máxima de URIs guardada"
			},
			"MHB": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " en MHB"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña actual incorrecta"
				}
				value, err := strconv.Atoi(args[0])
				if err != nil {
					return false, "Valor incorrecto"
				}
				if int64(value) == maxHeaderBytes.Load() {
					return false, "Valor sin cambios"
				}
				if value < 600 {
					return false, "Inferior a 600 bytes"
				}
				if value > 20480 {
					return false, "Superior a 20480 bytes"
				}
				maxHeaderBytes.Store(int64(value))
				return true, "Longitud máxima de cabeceras guardada"
			},
			"MBB": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " en MBB"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña actual incorrecta"
				}
				value, err := strconv.ParseInt(args[0], 10, 64)
				if err != nil {
					return false, "Valor incorrecto"
				}
				if value == maxBodySize.Load() {
					return false, "Valor sin cambios"
				}
				if value < 1 {
					return false, "Inferior a 1 byte"
				}
				if value > 104857600 {
					return false, "Superior a 104857600 bytes (100 Mb)"
				}
				maxBodySize.Store(value)
				return true, "Longitud máxima de contenidos guardada"
			},
			"CIL": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " en CIL"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña actual incorrecta"
				}
				value, err := strconv.ParseInt(args[0], 10, 64)
				if err != nil {
					return false, "Valor incorrecto"
				}
				if value*int64(time.Millisecond) == serverRequestLimits[0] {
					return false, "Valor sin cambios"
				}
				if value < 1000 {
					return false, "Inferior a 1000 milisegundos"
				}
				if value > 800000 {
					return false, "Superior a 800000 milisegundos"
				}
				atomic.StoreInt64(&serverRequestLimits[0], value*int64(time.Millisecond))
				return true, "Límite de intervalo para peticiones guardado"
			},
			"CIS": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " en CIS"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña actual incorrecta"
				}
				value, err := strconv.ParseInt(args[0], 10, 64)
				if err != nil {
					return false, "Valor incorrecto"
				}
				if value*int64(time.Millisecond) == serverRequestLimits[1] {
					return false, "Valor sin cambios"
				}
				if value < 10 {
					return false, "Inferior a 10 milisegundos"
				}
				if value > 50000 {
					return false, "Superior a 50000 milisegundos"
				}
				atomic.StoreInt64(&serverRequestLimits[1], value*int64(time.Millisecond))
				return true, "Intervalo para peticiones guardado"
			},
			"CII": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " en CII"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña actual incorrecta"
				}
				value, err := strconv.ParseInt(args[0], 10, 64)
				if err != nil {
					return false, "Valor incorrecto"
				}
				if value == serverRequestLimits[2] {
					return false, "Valor sin cambios"
				}
				if value < 1 {
					return false, "Inferior a 1"
				}
				cisMillis := serverRequestLimits[1] / int64(time.Millisecond) // CIS in milliseconds
				if value > cisMillis {
					return false, "Superior a " + strconv.FormatInt(cisMillis, 10)
				}
				if cisMillis/value > 66 { // Represent minimum capability for panel, 1000ms => 2000 / 30 reqs = 66
					return false, "Valor incompatible con el panel"
				}
				atomic.StoreInt64(&serverRequestLimits[2], value)
				return true, "Peticiones máximas por intervalo guardado"
			},
			"RT": func(args ...string) (bool, string) {
				settingArgs := args // Need to be the first to be set
				if len(settingArgs) != 2 {
					return false, msgMissingData + " en RT"
				}
				if !passwordMatches(settingArgs[1]) {
					return false, "Contraseña actual incorrecta"
				}
				value, err := time.ParseDuration(settingArgs[0])
				if err != nil {
					return false, "Valor incorrecto"
				}
				if value == serverTimeLimits.Load().RT {
					return false, "Valor sin cambios"
				}
				if value != 0 {
					if value < 100*time.Millisecond {
						return false, "Inferior a 100 milisegundos"
					}
					if value > 900000*time.Millisecond {
						return false, "Superior a 15 minutos"
					}
				}
				setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.RT = value })
				return true, "Valor guardado lectura de peticiones"
			},
			"RHT": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " en RHT"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña actual incorrecta"
				}
				value, err := time.ParseDuration(args[0])
				if err != nil {
					return false, "Valor incorrecto"
				}
				if value == serverTimeLimits.Load().RHT {
					return false, "Valor sin cambios"
				}
				if value != 0 {
					if value < 50*time.Millisecond {
						return false, "Inferior a 50 milisegundos"
					}
					if value > (serverTimeLimits.Load().RT / 2) {
						return false, "Más que la mitad de lectura de peticiones"
					}
					if value > 450000*time.Millisecond {
						return false, "Superior a 7.5 minutos"
					}
				}
				setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.RHT = value })
				return true, "Valor guardado de lectura de cabeceras"
			},
			"WT": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " en WT"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña actual incorrecta"
				}
				value, err := time.ParseDuration(args[0])
				if err != nil {
					return false, "Valor incorrecto"
				}
				if value == serverTimeLimits.Load().WT {
					return false, "Valor sin cambios"
				}
				if value != 0 {
					if value < 100*time.Millisecond {
						return false, "Inferior a 100 milisegundos"
					}
					if value > 1800000*time.Millisecond {
						return false, "Superior a 30 minutos"
					}
				}
				setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.WT = value })
				return true, "Valor guardado de escritura de respuestas"
			},
			"IT": func(args ...string) (bool, string) {
				if len(args) != 2 {
					return false, msgMissingData + " en IT"
				}
				if !passwordMatches(args[1]) {
					return false, "Contraseña actual incorrecta"
				}
				value, err := time.ParseDuration(args[0])
				if err != nil {
					return false, "Valor incorrecto"
				}
				if value == serverTimeLimits.Load().IT {
					return false, "Valor sin cambios"
				}
				if value != 0 {
					if value < 100*time.Millisecond {
						return false, "Inferior a 100 milisegundos"
					}
					if value > 300000*time.Millisecond {
						return false, "Superior a 5 minutos"
					}
				}
				setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.IT = value })
				return true, "Valor guardado de conexiones inactivas"
			},
		},
	}

	subdomainContentCheckers = map[string]func(bool, interface{}, bool, ...string) (bool, string){ // Subdomains content check
		"!": func(printErrors bool, configData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // SSLs check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en configuraciones"
			}
			mapData, isMap := configData.(map[string]interface{})
			if !isMap {
				return false, "Datos de configuraciones incorrectos"
			}

			for setting := range siteSSLSettingCheckers {
				if _, exists := mapData[setting]; !exists {
					continue
				}

				strVal, isValue := mapData[setting].(string) // String is only for config file entries reading
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
						return false, "Valor de configuración incorrecto"
					}
					continue
				}

				if applied, msg := siteSSLSettingCheckers[setting](isFromFile, strVal, siteKeys[0], siteKeys[1]); !applied {
					if printErrors {
						return false, msg
					}
				}
			}
			return true, "Configuraciones procesadas"
		},
		"=": func(printErrors bool, rewriteData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Rewrites check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en reescrituras"
			}
			mapData, isMap := rewriteData.(map[string]interface{})
			if !isMap {
				return false, "Contenido de reescrituras incorrecto"
			}

			if printErrors && !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			for targetURI, rawTarget := range mapData {
				strVal, isString := rawTarget.(string)
				if !isString {
					if printErrors {
						return false, "Valor de reescritura incorrecto"
					}
					continue
				}

				var isExisting bool
				targetURI = replaceURIChars(targetURI)
				if _, isExisting = sitesMap[siteKeys[0]][siteKeys[1]][targetURI]; isExisting {
					if sitesMap[siteKeys[0]][siteKeys[1]][targetURI][1:] == strVal {
						if printErrors {
							return false, "Reescritura sin cambios"
						}
						continue
					}
				}
				valueLen := len(targetURI)
				if valueLen < 1 || strings.Contains(targetURI, "//") || strings.Contains(targetURI, "..") || targetURI[0] != '/' {
					if printErrors {
						return false, "Dirección relativa incorrecta"
					}
					continue
				}
				if valueLen > 128 {
					if printErrors {
						return false, "Dirección relativa excesiva"
					}
					continue
				}
				strVal = replaceURIChars(strVal)
				valueLen = len(strVal)
				if valueLen < 1 || strings.Contains(strVal, "..") {
					if printErrors {
						return false, "Reescritura incorrecta"
					}
					continue
				}
				schemeMode := "N"
				if valueLen > 7 {
					if (strVal[0] == 'h' || strVal[0] == 'H') && (strVal[1] == 't' || strVal[1] == 'T') && (strVal[2] == 't' || strVal[2] == 'T') && (strVal[3] == 'p' || strVal[3] == 'P') {
						if strVal[4] == ':' && strVal[5] == '/' && strVal[6] == '/' {
							schemeMode = "H"
							strVal = strVal[7:]
						} else if strVal[4] == 's' && strVal[5] == ':' && strVal[6] == '/' && strVal[7] == '/' {
							schemeMode = "S"
							strVal = strVal[8:]
						}
					}
				}
				if strings.Contains(strVal, "//") {
					if printErrors {
						return false, "Reescritura incorrecta"
					}
					continue
				}
				if schemeMode == "N" && strVal[0] != '/' {
					if printErrors {
						return false, "La reescritura debe empezar por /, http:// o https://"
					}
					if isFromFile { // Accepted by older versions: say why it disappears from the config
						slog.Warn("Reescritura descartada: el destino debe empezar por /, http:// o https://", "sitio", siteKeys[0], "subdominio", siteKeys[1], "origen", targetURI, "destino", strVal)
					}
					continue
				}
				if valueLen > 512 {
					if printErrors {
						return false, "Reescritura excesiva"
					}
					continue
				}
				sitesMap[siteKeys[0]][siteKeys[1]][targetURI] = schemeMode + strVal
				if printErrors {
					if !isExisting {
						return true, "Reescritura creada"
					} else {
						return true, "Reescritura cambiada"
					}
				}
			}
			return true, "Reescrituras procesadas"
		},
		"$": func(printErrors bool, mimeData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // MIMEs check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en MIMEs"
			}
			entries, isMap := mimeData.(map[string]interface{})
			if !isMap {
				return false, "Contenido de MIMEs incorrecto"
			}

			if printErrors && !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := mimeTypes[siteKeys[1]]; !exists {
				return false, "MIMEs indefinidos"
			}

			for ext, rawMIME := range entries {
				mimeType, isString := rawMIME.(string)
				if !isString {
					if printErrors {
						return false, "Valor de MIME incorrecto"
					}
					continue
				}

				var existed bool
				mimeType = replaceURIChars(mimeType)
				if _, exists := mimeTypes[siteKeys[1]][ext]; exists {
					existed = true
					if mimeTypes[siteKeys[1]][ext] == mimeType {
						if printErrors {
							return false, "MIME sin cambios"
						}
						continue
					}
				} else {
					existed = false
				}
				extLen := len(ext)
				if extLen > 12 {
					if printErrors {
						return false, "Extensión excesiva"
					}
					continue
				}
				if extLen > 0 && !extChars(ext) {
					if printErrors {
						return false, "Extensión incorrecta"
					}
					continue
				}
				if extLen > 0 && ext[0] == '.' {
					ext = ext[1:]
				}
				if mimeLen := len(mimeType); mimeLen < 4 || mimeLen > 128 {
					if printErrors {
						return false, "MIME muy largo o corto"
					}
					continue
				}
				_, _, parseErr := mime.ParseMediaType(mimeType)
				if parseErr != nil {
					if printErrors {
						return false, "MIME incorrecto"
					}
					continue
				}
				mimeTypes[siteKeys[1]][ext] = mimeType
				if printErrors {
					if !existed {
						return true, "MIME creado"
					} else {
						return true, "MIME cambiado"
					}
				}
			}
			return true, "MIMEs procesados"
		},
		".": func(printErrors bool, headerData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Headers check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en cabeceras"
			}
			entries, isMap := headerData.(map[string]interface{})
			if !isMap {
				return false, "Contenido de cabeceras incorrecto"
			}

			if printErrors && !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := customHeaders[siteKeys[1]]; !exists {
				return false, "Cabeceras indefinidas"
			}

			for header, rawValue := range entries {
				value, isString := rawValue.(string)
				if !isString {
					if printErrors {
						return false, "Valor de cabecera incorrecto"
					}
					continue
				}

				var existed bool
				value = replaceURIChars(value)
				if _, exists := customHeaders[siteKeys[1]][header]; exists {
					existed = true
					if customHeaders[siteKeys[1]][header] == value {
						if printErrors {
							return false, "Cabecera sin cambios"
						}
						continue
					}
				} else {
					existed = false
				}
				if !headerChars(header) {
					if printErrors {
						return false, "Cabecera incorrecta"
					}
					continue
				}
				if nameLen := len(header); nameLen < 1 || nameLen > maxHeaderKeyLength {
					if printErrors {
						return false, "Cabecera muy larga o corta"
					}
					continue
				}
				if valueLen := len(value); valueLen < 1 || valueLen > maxHeaderValueLength {
					if printErrors {
						return false, "Contenido muy largo o corto"
					}
					continue
				}
				customHeaders[siteKeys[1]][header] = value
				if printErrors {
					if !existed {
						return true, "Cabecera creada"
					} else {
						return true, "Cabecera cambiada"
					}
				}
			}
			return true, "Cabeceras procesadas"
		},
		"?": func(printErrors bool, preprocessorData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Preprocessors check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en preprocesadores"
			}
			entries, isMap := preprocessorData.(map[string]interface{})
			if !isMap {
				return false, "Contenido de preprocesadores incorrecto"
			}

			if printErrors && !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := preprocessors[siteKeys[1]]; !exists {
				return false, "Preprocesadores no definidos"
			}

			for ext, rawPath := range entries {
				executable, isString := rawPath.(string)
				if !isString {
					if printErrors {
						return false, "Valor de preprocesador incorrecto"
					}
					continue
				}

				var existed bool
				executable = replaceURIChars(executable)
				if _, exists := preprocessors[siteKeys[1]][ext]; exists {
					existed = true
					if preprocessors[siteKeys[1]][ext] == executable {
						if printErrors {
							return false, "Preprocesador sin cambios"
						}
						continue
					}
				} else {
					existed = false
				}
				extLen := len(ext)
				if extLen > 12 {
					if printErrors {
						return false, "Extensión excesiva"
					}
					continue
				}
				if extLen > 0 && !extChars(ext) {
					if printErrors {
						return false, "Extensión incorrecta"
					}
					continue
				}
				if extLen > 0 && ext[0] == '.' {
					ext = ext[1:]
				}
				if pathLen := len(executable); pathLen < 1 || pathLen > 128 {
					if printErrors {
						return false, "Ruta del preprocesador muy larga o corta"
					}
					continue
				}

				protocolEnd := strings.Index(executable, ">")
				_q := "cgi"
				if protocolEnd != -1 {
					_q = strings.ToLower(cutAt(executable, '>'))
					executable = executable[protocolEnd+1:]
				}

				// From turbo.config, a preprocessor that can't run is kept: serving that extension answers 500
				// instead of the file's source, and saving doesn't lose the entry.
				if _q != "cgi" { // "dx>" isn't implemented
					if printErrors {
						return false, "Protocolo de preprocesador incorrecto."
					}
					slog.Warn("Preprocesador \""+_q+">\" no disponible: la extensión responderá 500", "extensión", ext)
					preprocessors[siteKeys[1]][ext] = _q + ">" + executable
					continue
				}

				executable = strings.Replace(executable, "{"+currentDirPlaceholder+"}", currentDir(), 1)

				info, err := os.Stat(executable)
				if err != nil || info.IsDir() { // Doesn't exist, the path isn't valid on this system or it is a folder
					if printErrors {
						if err != nil {
							return false, "Preprocesador inexistente"
						}
						return false, "Preprocesador incorrecto"
					}
					slog.Warn("Preprocesador inexistente: la extensión responderá 500", "extensión", ext, "preprocesador", executable)
				}

				preprocessors[siteKeys[1]][ext] = executable
				if printErrors {
					if !existed {
						return true, "Preprocesador agregado"
					} else {
						return true, "Preprocesador modificado"
					}
				}
			}
			return true, "Preprocesadores procesados"
		},
		"-": func(printErrors bool, indexData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Indexes check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en índices"
			}
			entries, isMap := indexData.(map[string]interface{})
			if !isMap {
				return false, "Contenido de índices incorrecto"
			}

			if printErrors && !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := indexFiles[siteKeys[1]]; !exists {
				return false, "Índices no definidos"
			}

			// From turbo.config, each index comes with its position; from the panel, it goes after the rest.
			names := make([]string, 0, len(entries))
			for name := range entries {
				names = append(names, name)
			}
			sort.SliceStable(names, func(left, right int) bool {
				return indexPosition(entries[names[left]]) < indexPosition(entries[names[right]])
			})
			for _, name := range names {
				name = replaceURIChars(name)
				length := len(name)
				if length < 1 || length > 48 {
					if printErrors {
						return false, "Archivo de índice muy largo o corto"
					}
					continue
				}
				if strings.IndexByte(name, '\\') != -1 || strings.IndexByte(name, '/') != -1 || strings.Contains(name, "..") {
					if printErrors {
						return false, "Archivo de índice incorrecto"
					}
					continue
				}
				addIndex(siteKeys[1], name)
				if printErrors {
					return true, "Índice asignado"
				}
			}
			return true, "Índices procesados"
		},
		"&": func(printErrors bool, aliasData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Alias check
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en alias"
			}
			entries, isMap := aliasData.(map[string]interface{})
			if !isMap {
				return false, "Contenido de alias incorrecto"
			}

			if printErrors && !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			for alias := range entries {
				if strings.IndexByte(alias, '*') != -1 {
					if printErrors {
						return false, "Wildcards inadmitidos"
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
				if target, assigned := domainAliases[alias]; assigned {
					if target == siteKeys[1] && printErrors {
						return false, "Alias sin cambios"
					}
					if printErrors {
						return false, "Alias preasignado"
					}
					continue
				}
				domainAliases[alias] = siteKeys[1]
				if printErrors {
					return true, "Alias asignado"
				}
			}
			return true, "Alias procesados"
		},
	}

	subdomainContentDeleters = map[string]func(bool, interface{}, ...string) (bool, string){ // Subdomains content deletion check
		"!": func(printErrors bool, configData interface{}, siteKeys ...string) (bool, string) {
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en borrado de SSLs"
			}
			return true, "Certificados SSL procesados"
		},
		"=": func(printErrors bool, rewriteData interface{}, siteKeys ...string) (bool, string) {
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en borrado de reescrituras"
			}
			entries, isMap := rewriteData.(map[string]interface{})
			if !isMap {
				return false, "Contenido de reescrituras incorrecto"
			}

			if !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			for rewriteKey := range entries {
				rewriteKey = replaceURIChars(rewriteKey)
				if _, exists := sitesMap[siteKeys[0]][siteKeys[1]][rewriteKey]; !exists {
					if printErrors {
						return false, "Reescritura inexistente"
					}
					continue
				}
				delete(sitesMap[siteKeys[0]][siteKeys[1]], rewriteKey)
				if printErrors {
					return true, "Reescritura borrada"
				}
			}
			return true, "Reescrituras procesadas"
		},
		"$": func(printErrors bool, mimeData interface{}, siteKeys ...string) (bool, string) {
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en borrado de MIMEs"
			}
			entries, isMap := mimeData.(map[string]interface{})
			if !isMap {
				return false, "Contenido de MIMEs incorrecto"
			}

			if !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := mimeTypes[siteKeys[1]]; !exists {
				return false, "MIMEs indefinidos"
			}

			for ext := range entries {
				if len(ext) > 0 && ext[0] == '.' {
					ext = ext[1:]
				}
				if _, exists := mimeTypes[siteKeys[1]][ext]; !exists {
					if printErrors {
						return false, "MIME inexistente"
					}
					continue
				}
				delete(mimeTypes[siteKeys[1]], ext)
				if printErrors {
					return true, "MIME borrado"
				}
			}
			return true, "MIMEs procesados"
		},
		".": func(printErrors bool, headerData interface{}, siteKeys ...string) (bool, string) {
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en borrado de cabeceras"
			}
			entries, isMap := headerData.(map[string]interface{})
			if !isMap {
				return false, "Contenido de cabeceras incorrecto"
			}

			if !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := customHeaders[siteKeys[1]]; !exists {
				return false, "Cabeceras indefinidas"
			}

			for header := range entries {
				if _, exists := customHeaders[siteKeys[1]][header]; !exists {
					if printErrors {
						return false, "Cabecera inexistente"
					}
					continue
				}
				delete(customHeaders[siteKeys[1]], header)
				if printErrors {
					return true, "Cabecera borrada"
				}
			}
			return true, "Cabeceras procesadas"
		},
		"?": func(printErrors bool, preprocessorData interface{}, siteKeys ...string) (bool, string) {
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en borrado de preprocesadores"
			}
			entries, isMap := preprocessorData.(map[string]interface{})
			if !isMap {
				return false, "Contenido de preprocesadores incorrecto"
			}

			if !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := preprocessors[siteKeys[1]]; !exists {
				return false, "Preprocesadores no definidos"
			}

			for ext := range entries {
				if len(ext) > 0 && ext[0] == '.' {
					ext = ext[1:]
				}
				if _, exists := preprocessors[siteKeys[1]][ext]; !exists {
					if printErrors {
						return false, "Preprocesador inexistente"
					}
					continue
				}
				delete(preprocessors[siteKeys[1]], ext)
				if printErrors {
					return true, "Preprocesador borrado"
				}
			}
			return true, "Preprocesadores procesados"
		},
		"-": func(printErrors bool, indexData interface{}, siteKeys ...string) (bool, string) {
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en borrado de índices"
			}
			entries, isMap := indexData.(map[string]interface{})
			if !isMap {
				return false, "Contenido de índices incorrecto"
			}

			if !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			if _, exists := indexFiles[siteKeys[1]]; !exists {
				return false, "Índices no definidos"
			}

			for indexName := range entries {
				indexName = replaceURIChars(indexName)
				if _, exists := indexFiles[siteKeys[1]][indexName]; !exists {
					if printErrors {
						return false, "Índice inexistente"
					}
					continue
				}
				delete(indexFiles[siteKeys[1]], indexName)
				if printErrors {
					return true, "Índice borrado"
				}
			}
			return true, "Índices procesados"
		},
		"&": func(printErrors bool, aliasData interface{}, siteKeys ...string) (bool, string) {
			if len(siteKeys) != 2 {
				return false, msgMissingData + " en borrado de alias"
			}
			entries, isMap := aliasData.(map[string]interface{})
			if !isMap {
				return false, "Contenido de alias incorrecto"
			}

			if !siteExists(siteKeys[0], siteKeys[1]) {
				if siteKeys[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			if siteKeys[1] != "" {
				siteKeys[1] += "." + siteKeys[0]
			} else {
				siteKeys[1] = siteKeys[0]
			}

			for alias := range entries {
				if _, exists := domainAliases[alias]; !exists {
					if printErrors {
						return false, "Alias inexistente"
					}
					continue
				} else if domainAliases[alias] != siteKeys[1] {
					if printErrors {
						return false, "Alias impertinente"
					}
					continue
				}
				delete(domainAliases, alias)
				if printErrors {
					return true, "Alias borrado"
				}
			}
			return true, "Alias procesados"
		},
	}

	serverRestartRequiredSettings = map[string]bool{"M": true} // List of settings that use restartServers

	validDomainRegex       = regexp.MustCompile(`^[a-zA-Z0-9\-\.]+$`)
	validCertbotAdapter    = regexp.MustCompile(`^dns-[a-z0-9-]{2,30}$`) // Certbot DNS plugins, passed as --<adapter>
	siteSSLSettingCheckers = map[string]func(bool, ...string) (bool, string){
		"E": func(printErrors bool, args ...string) (bool, string) {
			argCount := len(args)
			if argCount < 3 || argCount > 5 {
				return false, msgMissingData + " en E"
			}
			email, err := url.QueryUnescape(args[0])
			args[0] = email
			if err != nil || strings.IndexByte(args[0], '#') != -1 || strings.Contains(args[0], "--") || strings.IndexByte(args[0], ' ') != -1 || strings.IndexByte(args[0], '@') == -1 || strings.IndexByte(args[0], '.') == -1 {
				return false, "Valor de e-mail incorrecto"
			}

			args[0] = validDomainRegex.ReplaceAllString(args[0], "")
			if len(args[0]) < 5 || len(args[0]) > 40 {
				return false, "Longitud de e-mail incorrecta"
			}

			if !siteExists(args[1], args[2]) {
				if args[2] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if args[2] != "" {
				args[2] += "." + args[1]
			} else {
				args[2] = args[1]
			}

			if _, exists := siteSSLConfig[args[2]]; !exists {
				return false, "Configuración indefinida"
			}
			siteSSLConfig[args[2]]["E"] = args[0]
			return true, "E-mail guardado"
		},
		"A": func(printErrors bool, args ...string) (bool, string) {
			argCount := len(args)
			if argCount < 3 || argCount > 5 {
				return false, msgMissingData + " en A"
			}

			adapter, err := url.QueryUnescape(args[0])
			if err != nil || (adapter != "" && !validCertbotAdapter.MatchString(adapter)) { // Empty means webroot
				return false, "Adaptador incorrecto: se admite dns-<proveedor>"
			}
			args[0] = adapter

			if !siteExists(args[1], args[2]) {
				if args[2] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if args[2] != "" {
				args[2] += "." + args[1]
			} else {
				args[2] = args[1]
			}

			if _, exists := siteSSLConfig[args[2]]; !exists {
				return false, "Configuración indefinida"
			}

			siteSSLConfig[args[2]]["A"] = args[0]
			return true, "Adaptador guardado"
		},
		"C": func(printErrors bool, args ...string) (bool, string) {
			argCount := len(args)
			if argCount < 3 || argCount > 5 {
				return false, msgMissingData + " en C"
			}

			if !siteExists(args[1], args[2]) {
				if args[2] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			var siteKey string
			if args[2] != "" {
				siteKey = args[2] + "." + args[1]
				args[1] = changeWildcards(args[1]) + "/" + changeWildcards(args[2]) + "/"
			} else {
				siteKey = args[1]
				args[1] = changeWildcards(args[1]) + "/"
			}

			if argCount == 5 {
				if args[3] != "" {
					if len(args[3]) < 5 || len(args[3]) > 40 || strings.IndexByte(args[3], '#') != -1 || strings.Contains(args[3], "--") || strings.Contains(args[3], "--") || strings.IndexByte(args[3], ' ') != -1 || strings.IndexByte(args[3], '@') == -1 || strings.IndexByte(args[3], '.') == -1 {
						return false, "E-mail incorrecto"
					}
					siteSSLConfig[siteKey]["E"] = args[3]
				}
				if args[4] != "" {
					if !validCertbotAdapter.MatchString(args[4]) {
						return false, "Adaptador incorrecto: se admite dns-<proveedor>"
					}
					siteSSLConfig[siteKey]["A"] = args[4]
				}
			}

			var exists bool
			if _, exists = siteSSLConfig[siteKey]; !exists {
				return false, "Configuración indefinida"
			}

			exists = true
			fileInfo, statErr := os.Stat(sitesDir.Get() + args[1] + certFileName)
			if statErr != nil || fileInfo.IsDir() {
				exists = false
			}
			fileInfo, statErr = os.Stat(sitesDir.Get() + args[1] + keyFileName)
			if statErr != nil || fileInfo.IsDir() {
				exists = false
			}

			if exists && (time.Now().Unix()-fileInfo.ModTime().Unix()) > 6480000 {
				exists = false
			}

			if exists {
				if !printErrors && args[0] == "0" {
					if os.Remove(sitesDir.Get()+args[1]+certFileName) != nil ||
						os.Remove(sitesDir.Get()+args[1]+keyFileName) != nil {
						return false, "Error al borrar archivos SSL"
					}
					siteSSLConfig[siteKey]["C"] = false
					return true, "Certificado SSL borrado"
				}

				siteSSLConfig[siteKey]["C"] = true
				return true, "Certificado SSL activo"
			}

			// If there is no valid cert files, Certbot only runs when the administrator asks for it (a=1):

			if printErrors { // Read from the config file or found with the site folder: only record the state
				siteSSLConfig[siteKey]["C"] = false
				return false, "Sin certificado"
			}
			if args[0] != "1" {
				return false, "Sin certificado"
			}

			_, isBool := siteSSLConfig[siteKey]["C"].(bool)
			if !isBool {
				args[1] = siteKey
				var certificateMsg string
				certificateMsg, isBool = siteSSLConfig[siteKey]["C"].(string)
				if !isBool {
					certificateMsg = "Respuesta incorrecta de certificado"
				}
				siteSSLConfig[args[1]]["C"] = false
				return false, certificateMsg
			}

			if email, _ := siteSSLConfig[siteKey]["E"].(string); email == "" {
				return false, "E-mail obligatorio para crear el certificado"
			}

			siteSSLConfig[siteKey]["C"] = false

			args[0] = sitesDir.Get() + args[1]                       // Dir where the certificate will remain with sites
			args[1] = sitesDir.Get() + putSlash(certificatesDirName) // Dir of certificates
			fileInfo, statErr = os.Stat(args[1])
			if statErr != nil || !fileInfo.IsDir() {
				slog.Info("Creando el directorio de certificados", "directorio", args[1])
				if os.Mkdir(args[1], 0700) != nil {
					return false, "Error al crear directorio de certificados"
				}
			}

			args[1] += changeWildcards(siteKey) // One Certbot folder per site: obtainCertificate empties it before each attempt

			if currentCertDomain == siteKey {
				return false, "{\"message\":\"Espere, certificado procesándose\",\"status\":\"WAIT\"}"
			}

			obtainCertificate(siteKey, args[1], args[0]) // Creates a loop of attempts to get a certificate

			if currentCertDomain != siteKey {
				return false, "{\"message\":\"Espere, certificado ocupado en " + currentCertDomain + "\",\"status\":\"WAIT\"}"
			}
			return false, "{\"message\":\"Espere, certificado en proceso\",\"status\":\"WAIT\"}"
		},
		"S": func(printErrors bool, args ...string) (bool, string) {
			argCount := len(args)
			if argCount < 3 || argCount > 5 {
				return false, msgMissingData + " en S"
			}

			value, err := strconv.Atoi(args[0])
			if err != nil {
				return false, "Valor incorrecto"
			}

			if !siteExists(args[1], args[2]) {
				if args[2] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			var configKey string
			if args[2] != "" {
				configKey = args[2] + "." + args[1]
			} else {
				configKey = args[1]
			}

			if _, exists := siteSSLConfig[configKey]; !exists {
				return false, "Configuración indefinida"
			}

			if value != 0 { // S is 0 or 1; older turbo.config files kept a certificate index, any value but 0 means on
				if _, exists := siteCertificates[configKey]; exists {
					return false, "Redirección a HTTPS existente"
				}
				if args[2] != "" {
					args[1] = changeWildcards(args[1]) + "/" + changeWildcards(args[2]) + "/"
				} else {
					args[1] = changeWildcards(args[1]) + "/"
				}
				if loadSiteCertificate(configKey, sitesDir.Get()+args[1]) != nil {
					return false, "Certificados SSL incorrectos o inexistentes"
				}
				siteSSLConfig[configKey]["S"] = 1
				if servers[0] != nil && !httpsListening {
					safeServerStart(servers[0], tlsConfig) // Opens httpsAddr (:443) with the first certificate
				}

				slog.Info("HTTPS activado", "sitio", configKey)
				return true, "Redirección a HTTPS activada"
			}

			// If the setting values is 0:
			setSiteCertificate(configKey, nil)
			siteSSLConfig[configKey]["S"] = 0
			return true, "Redirección a HTTPS desactivada"
		},
		"R": func(printErrors bool, args ...string) (bool, string) {
			argCount := len(args)
			if argCount < 3 || argCount > 5 {
				return false, msgMissingData + " en R"
			}
			if args[0] != "0" && args[0] != "1" {
				return false, "Valor incorrecto"
			}
			if !siteExists(args[1], args[2]) {
				if args[2] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if args[2] != "" {
				args[2] += "." + args[1]
			} else {
				args[2] = args[1]
			}

			if _, exists := siteSSLConfig[args[2]]; !exists {
				return false, "Configuración indefinida"
			}

			if args[0] != "0" {
				if siteSSLConfig[args[2]]["W"] == true {
					return false, "Redirección a www activada"
				}
				siteSSLConfig[args[2]]["R"] = true
				args[1] = ""
			} else {
				siteSSLConfig[args[2]]["R"] = false
				args[1] = "des"
			}
			return true, "Redirección a raíz " + args[1] + "activada"
		},
		"W": func(printErrors bool, args ...string) (bool, string) {
			argCount := len(args)
			if argCount < 3 || argCount > 5 {
				return false, msgMissingData + " en W"
			}
			if args[0] != "0" && args[0] != "1" {
				return false, "Valor incorrecto"
			}
			if !siteExists(args[1], args[2]) {
				if args[2] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if args[2] != "" {
				args[2] += "." + args[1]
			} else {
				args[2] = args[1]
			}

			if _, exists := siteSSLConfig[args[2]]; !exists {
				return false, "Configuración indefinida"
			}

			if args[0] != "0" {
				if siteSSLConfig[args[2]]["R"] == true {
					return false, "Redirección a raíz activada"
				}
				siteSSLConfig[args[2]]["W"] = true
				args[1] = ""
			} else {
				siteSSLConfig[args[2]]["W"] = false
				args[1] = "des"
			}
			return true, "Redirección a WWW " + args[1] + "activada"
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
		"FIRST_REQUEST": func(request *customNetHttp.Request, wildcardParts ...string) string {
			return url.QueryEscape(request.RequestURI)
		},
		"FIRST_QUERY": func(request *customNetHttp.Request, wildcardParts ...string) string {
			queryStart := strings.IndexByte(request.RequestURI, '?')
			if queryStart != -1 {
				return url.QueryEscape(request.RequestURI[queryStart+1:])
			}
			return ""
		},
		"DIR": func(request *customNetHttp.Request, wildcardParts ...string) string {
			requestDir := dir(cutAt(request.RequestURI, '?'))
			if requestDir == "/" {
				return ""
			}
			return url.QueryEscape(requestDir)
		},
		"FILE": func(request *customNetHttp.Request, wildcardParts ...string) string {
			requestPath := cutAt(request.RequestURI, '?')
			if requestPath[len(requestPath)-1] != '/' {
				return url.QueryEscape(serverFuncBase(requestPath))
			}
			return ""
		},
		"EXT": func(request *customNetHttp.Request, wildcardParts ...string) string {
			return ext(cutAt(request.RequestURI, '?'))
		},
		"REWRITE": func(request *customNetHttp.Request, wildcardParts ...string) string {
			return url.QueryEscape(wildcardParts[6])
		},
		"REWRITE_COMPLEMENT": func(request *customNetHttp.Request, wildcardParts ...string) string {
			length := len(wildcardParts[6])
			if length < len(request.RequestURI) {
				return url.QueryEscape(request.RequestURI[length:])
			}
			return ""
		},
	}
)
