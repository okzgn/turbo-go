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
	"fmt"
	"mime"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"turbo/customNetHttp"
)

var (
	currentDirPlaceholder = "TURBO_CURRENT_DIR"
	rawConfigMap          map[string]map[string]interface{}

	siteExistenceResetFallbacks = map[string]func(string, string){ // Site & subdomains existence check reset fallback
		"/": func(d string, s string) {},
	}

	siteExistenceCheckers = map[string]func(bool, string, string) (bool, string){ // Site & subdomains existence check
		"/": func(checkExists bool, domain string, subdomain string) (bool, string) {
			//k := checkExists
			d := domain
			s := subdomain
			targetPath := ""
			origDomain := d
			origSubdomain := s
			if s != "" {
				targetPath = s + "." + changeWildcards(d, "x") // To check if domain name is correct, because it can't be verified if '*' or '#' is present
			} else {
				targetPath = d
			}
			if isValidHost, _ := hostOk(targetPath, false); !isValidHost {
				return false, "Nombre incorrecto de directorio de sitio"
			}
			d = changeWildcards(d)
			pathSeparator := ""
			if s != "" {
				pathSeparator = "/"
				s = changeWildcards(s)
			}
			_, readErr := os.ReadDir(stringStore["A"] + d + pathSeparator + s)
			if readErr != nil {
				return false, "Directorio de sitio inexistente: " + d + pathSeparator + s
			}
			_, readErr = os.ReadDir(stringStore["A"] + d + pathSeparator + s + "/" + stringStore["F"])
			if readErr != nil {
				return false, "Directorio de contenido de sitio inexistente: " + d + pathSeparator + s + "/" + stringStore["F"]
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
			"MUB": func() { maxURILength = 1000 },
			"MHB": func() { maxHeaderBytes = 5000 },    // Need to be set first.
			"MBB": func() { maxBodySize = 1048576 }, // 1 Mb
			"CIL": func() { serverRequestLimits[0] = 10000000000 },
			"CIS": func() { serverRequestLimits[1] = 1000000000 }, // Need to be first to be set
			"CII": func() { serverRequestLimits[2] = 100 },
			"RT":  func() { serverTimeLimits["RT"] = 5 * time.Second }, // Need to be first to be set
			"RHT": func() { serverTimeLimits["RHT"] = 1 * time.Second },
			"WT":  func() { serverTimeLimits["WT"] = 10 * time.Second },
			"IT":  func() { serverTimeLimits["IT"] = 2 * time.Second },
		},
	}

	adminDeleteHandlers = map[string]func(string) (bool, string){
		"@": func(ip string) (bool, string) {
			k := ip
			if _, a := persistentIPs[k]; !a {
				return false, "IP inexistente"
			}
			delete(persistentIPs, k)
			return true, "IP denegado eliminado"
		},
		"#": func(httpCode string) (bool, string) {
			k := httpCode
			c, e := strconv.Atoi(k)
			if e != nil {
				return false, "Código HTTP inválido"
			}
			var a bool
			if _, a = httpResponses[c]; !a {
				return false, "Respuesta inexistente"
			}
			if _, a = fixedHTTPResponses[c]; a {
				return false, "Respuesta inmutable"
			}
			delete(httpResponses, c)
			return true, "Respuesta a código HTTP eliminada"
		},
		"_": func(char string) (bool, string) {
			k := char
			k = replaceURIChars(k)
			var a bool
			if _, a = charReplacements[k]; !a {
				return false, "Reemplazo inexistente"
			}
			if _, a = fixedCharReplacements[k]; a {
				return false, "Reemplazo inmutable"
			}
			delete(charReplacements, k)
			return true, "Reemplazo a caracter(es) eliminado"
		},
	}

	adminAddHandlers = map[string]func(string, string) (bool, string){
		"@": func(ip string, unixDate string) (bool, string) {
			k := ip
			v := unixDate
			if net.ParseIP(k) == nil {
				return false, "IP incorrecto"
			}
			v = strings.TrimSpace(v)
			k = ipAddr(k)
			if _, a := signedInTokens[k]; a {
				return false, "IP actual"
			}
			if k == "127.0.0.1" || k[:3] == "127" || k == "::1" || k == "0:0:0:0:0:0:0:1" {
				return false, "IP localhost"
			}
			parsedUnix, parseErr := strconv.ParseInt(v, 10, 64)
			if parseErr != nil {
				return false, "Fecha UNIX incorrecta"
			}
			existingUnix, exists := persistentIPs[k]
			if parsedUnix == 0 || time.Now().Unix() > parsedUnix {
				if exists {
					delete(persistentIPs, k)
					return true, "IP denegado eliminado"
				}
				return false, "Fecha UNIX expirada"
			}
			isModified := true
			if strconv.FormatInt(existingUnix, 10) == v {
				isModified = false
				v = "sin cambios"
			} else if exists {
				v = "modificado"
			} else {
				v = "agregado"
			}
			persistentIPs[k] = parsedUnix
			return isModified, "IP denegado " + v
		},
		"#": func(httpCode string, response string) (bool, string) {
			k := httpCode
			v := response
			codeInt, parseErr := strconv.Atoi(k)
			if parseErr != nil {
				return false, "Código HTTP inválido"
			}
			if (codeInt < 400 || codeInt > 599) && codeInt != 0 {
				return false, "Código HTTP incorrecto"
			}
			v = strings.TrimSpace(v)
			l := len(v)
			if l < 1 || l > 2048 {
				return false, "Respuesta muy corta o larga"
			}
			s, a := httpResponses[codeInt]
			if a && s == v {
				return false, "Respuesta sin cambios"
			}
			httpResponses[codeInt] = v
			return true, "Respuesta guardada"
		},
		"_": func(char string, replacement string) (bool, string) {
			k := char
			v := replacement
			unescapedChar := replaceURIChars(k)
			unescapedRepl := replaceURIChars(v)
			for i := range fixedCharReplacements {
				if (strings.IndexByte(k, i[0]) != -1 && k != i) || (strings.IndexByte(unescapedChar, i[0]) != -1 && unescapedChar != i) {
					return false, "Caracter de reemplazo inválido"
				}
				if strings.IndexByte(v, i[0]) != -1 || strings.IndexByte(unescapedRepl, i[0]) != -1 {
					return false, "Reemplazo inválido"
				}
			}
			var l int
			if unescapedChar != " " {
				unescapedChar = strings.TrimSpace(unescapedChar)
				l = len(unescapedChar)
				if l < 1 {
					return false, "Sin caracter"
				}
				if l > 4 {
					return false, "Muchos caracteres"
				}
			}
			if unescapedRepl != " " {
				unescapedRepl = strings.TrimSpace(unescapedRepl)
				l = len(unescapedRepl)
				if l < 1 || l > 16 {
					return false, "Reemplazo muy corto o largo"
				}
			}
			if s, a := charReplacements[unescapedChar]; a && s == unescapedRepl {
				return false, "Reemplazo sin cambios"
			}
			charReplacements[unescapedChar] = unescapedRepl
			return true, "Reemplazo de caracter(es) guardado"
		},
	}

	defaultSettingKeysGroup = map[string][]string{
		".": {"C", "U", "P", "M", "MUB", "MHB", "MBB", "CIL", "CIS", "CII", "RT", "RHT", "WT", "IT"},
	}

	defaultSettingErrorExceptions = map[string]map[string]map[string]bool{ // ME (E, for exceptions). There are some exceptions on errors, some cause unnecessary resets
		".": {
			"M":   map[string]bool{"Directorio de sitios sin cambios": true},
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
			"C": func(args ...string) (bool, string) { v := args
				if len(v) != 2 {
					return false, stringStore["Z"] + " en C"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña incorrecta"
				}
				if !saveDefaultConfig() {
					return false, "Error al guardar"
				}
				return true, "Configuración guardada"
			},
			"U": func(args ...string) (bool, string) { v := args
				if len(v) != 2 {
					return false, stringStore["Z"] + " en U"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña actual incorrecta"
				}
				l := len(v[0])
				if l < 1 || l > 24 {
					return false, "Usuario muy largo o corto"
				}
				stringStore["U"] = v[0]
				return true, "Usuario cambiado"
			},
			"P": func(args ...string) (bool, string) { v := args
				if len(v) != 2 {
					return false, stringStore["Z"] + " en P"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña actual incorrecta"
				}
				l := len(v[0])
				if l < 1 || l > 24 {
					return false, "Contraseña muy larga o corta"
				}
				stringStore["P"] = v[0]
				return true, "Contraseña cambiada"
			},
			"M": func(args ...string) (bool, string) { v := args
				if len(v) < 2 {
					return false, stringStore["Z"] + " en D"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña actual incorrecta"
				}

				v[0] = putSlash(v[0])
				if v[0] == stringStore["A"] {
					return false, "Directorio de sitios sin cambios"
				}

				v[0] = strings.Replace(v[0], "{"+currentDirPlaceholder+"}", currentDir(), 1)
				m, i := os.Stat(v[0])
				if os.IsNotExist(i) || !m.IsDir() {
					return false, "Directorio de sitios inexistente"
				}
				stringStore["A"] = v[0]
				return true, "Directorio de sitios configurado"
			},
			"MUB": func(args ...string) (bool, string) { v := args
				if len(v) != 2 {
					return false, stringStore["Z"] + " en MUB"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := strconv.Atoi(v[0])
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == maxURILength {
					return false, "Valor sin cambios"
				}
				if j < 40 {
					return false, "Inferior a 40 bytes"
				}
				if j > 10240 {
					return false, "Superior a 10240 bytes"
				}
				maxURILength = j
				return true, "Longitud máxima de URIs guardada"
			},
			"MHB": func(args ...string) (bool, string) { v := args
				if len(v) != 2 {
					return false, stringStore["Z"] + " en MHB"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := strconv.Atoi(v[0])
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == maxHeaderBytes {
					return false, "Valor sin cambios"
				}
				if j < 600 {
					return false, "Inferior a 600 bytes"
				}
				if j > 20480 {
					return false, "Superior a 20480 bytes"
				}
				maxHeaderBytes = j
				return true, "Longitud máxima de cabeceras guardada"
			},
			"MBB": func(args ...string) (bool, string) { v := args
				if len(v) != 2 {
					return false, stringStore["Z"] + " en MBB"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := strconv.ParseInt(v[0], 10, 64)
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == maxBodySize {
					return false, "Valor sin cambios"
				}
				if j < 1 {
					return false, "Inferior a 1 byte"
				}
				if j > 104857600 {
					return false, "Superior a 104857600 bytes (100 Mb)"
				}
				maxBodySize = j
				return true, "Longitud máxima de contenidos guardada"
			},
			"CIL": func(args ...string) (bool, string) { v := args
				if len(v) != 2 {
					return false, stringStore["Z"] + " en CIL"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := strconv.ParseInt(v[0], 10, 64)
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j*10000000 == serverRequestLimits[0] {
					return false, "Valor sin cambios"
				}
				if j < 100 {
					return false, "Inferior a 100 milisegundos"
				}
				if j > 80000 {
					return false, "Superior a 80000 milisegundos"
				}
				serverRequestLimits[0] = j * 10000000
				return true, "Límite de intervalo para peticiones guardado"
			},
			"CIS": func(args ...string) (bool, string) { v := args
				if len(v) != 2 {
					return false, stringStore["Z"] + " en CIS"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := strconv.ParseInt(v[0], 10, 64)
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j*10000000 == serverRequestLimits[1] {
					return false, "Valor sin cambios"
				}
				if j < 1 {
					return false, "Inferior a 1 milisegundo"
				}
				if j > 5000 {
					return false, "Superior a 5000 milisegundos"
				}
				serverRequestLimits[1] = j * 10000000
				return true, "Intervalo para peticiones guardado"
			},
			"CII": func(args ...string) (bool, string) { v := args
				if len(v) != 2 {
					return false, stringStore["Z"] + " en CII"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := strconv.ParseInt(v[0], 10, 64)
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == serverRequestLimits[2] {
					return false, "Valor sin cambios"
				}
				if j < 1 {
					return false, "Inferior a 1"
				}
				k := (serverRequestLimits[1] / 10000000) * 10
				if j > k {
					return false, "Superior a " + strconv.FormatInt(k, 10)
				}
				if k/j > 66 { // Represent minimum capability for panel, 1000ms => 2000 / 30 reqs = 66
					return false, "Valor incompatible con el panel"
				}
				serverRequestLimits[2] = j
				return true, "Peticiones máximas por intervalo guardado"
			},
			"RT": func(args ...string) (bool, string) { v := args // Need to be the first to be set
				if len(v) != 2 {
					return false, stringStore["Z"] + " en RT"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := time.ParseDuration(v[0])
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == serverTimeLimits["RT"] {
					return false, "Valor sin cambios"
				}
				if j != 0 {
					if j < 100*time.Millisecond {
						return false, "Inferior a 100 milisegundos"
					}
					if j > 900000*time.Millisecond {
						return false, "Superior a 15 minutos"
					}
				}
				serverTimeLimits["RT"] = j
				return true, "Valor guardado lectura de peticiones"
			},
			"RHT": func(args ...string) (bool, string) { v := args
				if len(v) != 2 {
					return false, stringStore["Z"] + " en RHT"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := time.ParseDuration(v[0])
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == serverTimeLimits["RHT"] {
					return false, "Valor sin cambios"
				}
				if j != 0 {
					if j < 50*time.Millisecond {
						return false, "Inferior a 50 milisegundos"
					}
					if j > (serverTimeLimits["RT"] / 2) {
						return false, "Más que la mitad de lectura de peticiones"
					}
					if j > 450000*time.Millisecond {
						return false, "Superior a 7.5 minutos"
					}
				}
				serverTimeLimits["RHT"] = j
				return true, "Valor guardado de lectura de cabeceras"
			},
			"WT": func(args ...string) (bool, string) { v := args
				if len(v) != 2 {
					return false, stringStore["Z"] + " en WT"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := time.ParseDuration(v[0])
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == serverTimeLimits["WT"] {
					return false, "Valor sin cambios"
				}
				if j != 0 {
					if j < 100*time.Millisecond {
						return false, "Inferior a 100 milisegundos"
					}
					if j > 1800000*time.Millisecond {
						return false, "Superior a 30 minutos"
					}
				}
				serverTimeLimits["WT"] = j
				return true, "Valor guardado de escritura de respuestas"
			},
			"IT": func(args ...string) (bool, string) { v := args
				if len(v) != 2 {
					return false, stringStore["Z"] + " en IT"
				}
				if v[1] != stringStore["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := time.ParseDuration(v[0])
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == serverTimeLimits["IT"] {
					return false, "Valor sin cambios"
				}
				if j != 0 {
					if j < 100*time.Millisecond {
						return false, "Inferior a 100 milisegundos"
					}
					if j > 300000*time.Millisecond {
						return false, "Superior a 5 minutos"
					}
				}
				serverTimeLimits["IT"] = j
				return true, "Valor guardado de conexiones inactivas"
			},
		},
	}

	subdomainContentCheckers = map[string]func(bool, interface{}, bool, ...string) (bool, string){ // Subdomains content check
		"!": func(printErrors bool, configData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // SSLs check
			z := printErrors
			c := configData
			x := isFromFile
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en configuraciones"
			}
			mapData, isMap := c.(map[string]interface{})
			if !isMap {
				return false, "Datos de configuraciones incorrectos"
			}
			var strVal string

			for k, _ := range siteSSLSettingCheckers {
				if _, isMap = mapData[k]; !isMap {
					continue
				}

				strVal, isMap = mapData[k].(string) // String is only for config file entries reading
				if !isMap {
					boolVal, isBool := mapData[k].(bool)
					if isBool {
						isMap = true
						if boolVal {
							strVal = "1"
						} else {
							strVal = "0"
						}
					} else {
						intVal, isInt := mapData[k].(int)
						if isInt {
							isMap = true
							strVal = strconv.Itoa(intVal)
						}
					}
				}

				if !isMap {
					if z {
						return false, "Valor de configuración incorrecto"
					}
					continue
				}

				if isMap, k = siteSSLSettingCheckers[k](x, strVal, s[0], s[1]); !isMap {
					if z {
						return false, k
					}
				}
			}
			return true, "Configuraciones procesadas"
		},
		"=": func(printErrors bool, rewriteData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Rewrites check
			z := printErrors
			l := rewriteData
			//x := isFromFile
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en reescrituras"
			}
			mapData, isMap := l.(map[string]interface{})
			if !isMap {
				return false, "Contenido de reescrituras incorrecto"
			}

			if z && !siteExists(s[0], s[1]) {
				if s[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			for targetURI, v := range mapData {
				strVal, isString := v.(string)
				if !isString {
					if z {
						return false, "Valor de reescritura incorrecto"
					}
					continue
				}

				var isExisting bool
				targetURI = replaceURIChars(targetURI)
				if _, isExisting = sitesMap[s[0]][s[1]][targetURI]; isExisting {
					if sitesMap[s[0]][s[1]][targetURI][1:] == strVal {
						if z {
							return false, "Reescritura sin cambios"
						}
						continue
					}
				}
				valueLen := len(targetURI)
				if valueLen < 1 || strings.Contains(targetURI, "//") || strings.Contains(targetURI, "..") || targetURI[0] != '/' {
					if z {
						return false, "Dirección relativa incorrecta"
					}
					continue
				}
				if valueLen > 128 {
					if z {
						return false, "Dirección relativa excesiva"
					}
					continue
				}
				strVal = replaceURIChars(strVal)
				valueLen = len(strVal)
				if valueLen < 1 || strings.Contains(strVal, "..") {
					if z {
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
					if z {
						return false, "Reescritura incorrecta"
					}
					continue
				}
				if valueLen > 512 {
					if z {
						return false, "Reescritura excesiva"
					}
					continue
				}
				sitesMap[s[0]][s[1]][targetURI] = schemeMode + strVal
				if z {
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
			z := printErrors
			l := mimeData
			//x := isFromFile
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en MIMEs"
			}
			c, a := l.(map[string]interface{})
			if !a {
				return false, "Contenido de MIMEs incorrecto"
			}

			if z && !siteExists(s[0], s[1]) {
				if s[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if s[1] != "" {
				s[1] += "." + s[0]
			} else {
				s[1] = s[0]
			}

			if _, a = mimeTypes[s[1]]; !a {
				return false, "MIMEs indefinidos"
			}

			for e, v := range c {
				m, a := v.(string)
				if !a {
					if z {
						return false, "Valor de MIME incorrecto"
					}
					continue
				}

				var j bool
				m = replaceURIChars(m)
				if _, a = mimeTypes[s[1]][e]; a {
					j = true
					if mimeTypes[s[1]][e] == m {
						if z {
							return false, "MIME sin cambios"
						}
						continue
					}
				} else {
					j = false
				}
				l := len(e)
				if l > 12 {
					if z {
						return false, "Extensión excesiva"
					}
					continue
				}
				if l > 0 && !extChars(e) {
					if z {
						return false, "Extensión incorrecta"
					}
					continue
				}
				if l > 0 && e[0] == '.' {
					e = e[1:]
				}
				l = len(m)
				if l < 4 || l > 128 {
					if z {
						return false, "MIME muy largo o corto"
					}
					continue
				}
				_, _, b := mime.ParseMediaType(m)
				if b != nil {
					if z {
						return false, "MIME incorrecto"
					}
					continue
				}
				mimeTypes[s[1]][e] = m
				if z {
					if !j {
						return true, "MIME creado"
					} else {
						return true, "MIME cambiado"
					}
				}
			}
			return true, "MIMEs procesados"
		},
		".": func(printErrors bool, headerData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Headers check
			z := printErrors
			l := headerData
			//x := isFromFile
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en cabeceras"
			}
			f, e := l.(map[string]interface{})
			if !e {
				return false, "Contenido de cabeceras incorrecto"
			}

			if z && !siteExists(s[0], s[1]) {
				if s[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if s[1] != "" {
				s[1] += "." + s[0]
			} else {
				s[1] = s[0]
			}

			if _, e = customHeaders[s[1]]; !e {
				return false, "Cabeceras indefinidas"
			}

			for h, v := range f {
				c, e := v.(string)
				if !e {
					if z {
						return false, "Valor de cabecera incorrecto"
					}
					continue
				}

				var j bool
				c = replaceURIChars(c)
				if _, e = customHeaders[s[1]][h]; e {
					j = true
					if customHeaders[s[1]][h] == c {
						if z {
							return false, "Cabecera sin cambios"
						}
						continue
					}
				} else {
					j = false
				}
				if !headerChars(h) {
					if z {
						return false, "Cabecera incorrecta"
					}
					continue
				}
				l := len(h)
				if l < 1 || l > maxHeaderKeyLength {
					if z {
						return false, "Cabecera muy larga o corta"
					}
					continue
				}
				l = len(c)
				if l < 1 || l > maxHeaderValueLength {
					if z {
						return false, "Contenido muy largo o corto"
					}
					continue
				}
				customHeaders[s[1]][h] = c
				if z {
					if !j {
						return true, "Cabecera creada"
					} else {
						return true, "Cabecera cambiada"
					}
				}
			}
			return true, "Cabeceras procesadas"
		},
		"?": func(printErrors bool, preprocessorData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Preprocessors check
			z := printErrors
			l := preprocessorData
			//x := isFromFile
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en preprocesadores"
			}
			c, a := l.(map[string]interface{})
			if !a {
				return false, "Contenido de preprocesadores incorrecto"
			}

			if z && !siteExists(s[0], s[1]) {
				if s[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if s[1] != "" {
				s[1] += "." + s[0]
			} else {
				s[1] = s[0]
			}

			if _, a = preprocessors[s[1]]; !a {
				return false, "Preprocesadores no definidos"
			}

			for e, v := range c {
				p, a := v.(string)
				if !a {
					if z {
						return false, "Valor de preprocesador incorrecto"
					}
					continue
				}

				var j bool
				p = replaceURIChars(p)
				if _, a = preprocessors[s[1]][e]; a {
					j = true
					if preprocessors[s[1]][e] == p {
						if z {
							return false, "Preprocesador sin cambios"
						}
						continue
					}
				} else {
					j = false
				}
				l := len(e)
				if l > 12 {
					if z {
						return false, "Extensión excesiva"
					}
				}
				if l > 0 && !extChars(e) {
					if z {
						return false, "Extensión incorrecta"
					}
					continue
				}
				if l > 0 && e[0] == '.' {
					e = e[1:]
				}
				l = len(p)
				if l < 1 || l > 128 {
					if z {
						return false, "Ruta del preprocesador muy larga o corta"
					}
					continue
				}

				q := strings.Index(p, ">")
				_q := "cgi"
				if q != -1 {
					_q = strings.ToLower(cutAt(p, '>'))
					p = p[q+1:]
				}

				if _q != "cgi" && _q != "dx" {
					return false, "Protocolo de preprocesador incorrecto."
				}

				p = strings.Replace(p, "{"+currentDirPlaceholder+"}", currentDir(), 1)

				m, n := os.Stat(p)
				if os.IsNotExist(n) {
					if z {
						return false, "Preprocesador inexistente"
					}
					continue
				} else if m.IsDir() {
					if z {
						return false, "Preprocesador incorrecto"
					}
					continue
				}

				if _q != "cgi" {
					p = _q + ">" + p
				}

				preprocessors[s[1]][e] = p
				if z {
					if !j {
						return true, "Preprocesador agregado"
					} else {
						return true, "Preprocesador modificado"
					}
				}
			}
			return true, "Preprocesadores procesados"
		},
		"-": func(printErrors bool, indexData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Indexes check
			z := printErrors
			l := indexData
			//x := isFromFile
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en índices"
			}
			c, e := l.(map[string]interface{})
			if !e {
				return false, "Contenido de índices incorrecto"
			}

			if z && !siteExists(s[0], s[1]) {
				if s[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if s[1] != "" {
				s[1] += "." + s[0]
			} else {
				s[1] = s[0]
			}

			if _, e = indexFiles[s[1]]; !e {
				return false, "Índices no definidos"
			}

			for i, _ := range c {
				i = replaceURIChars(i)
				l := len(i)
				if l < 1 || l > 48 {
					if z {
						return false, "Archivo de índice muy largo o corto"
					}
					continue
				}
				if strings.IndexByte(i, '\\') != -1 || strings.IndexByte(i, '/') != -1 || strings.Contains(i, "..") {
					if z {
						return false, "Archivo de índice incorrecto"
					}
					continue
				}
				indexFiles[s[1]][i] = false
				if z {
					return true, "Índice asignado"
				}
			}
			return true, "Índices procesados"
		},
		"&": func(printErrors bool, aliasData interface{}, isFromFile bool, siteKeys ...string) (bool, string) { // Alias check
			z := printErrors
			l := aliasData
			//x := isFromFile
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en alias"
			}
			c, e := l.(map[string]interface{})
			if !e {
				return false, "Contenido de alias incorrecto"
			}

			if z && !siteExists(s[0], s[1]) {
				if s[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if s[1] != "" {
				s[1] += "." + s[0]
			} else {
				s[1] = s[0]
			}

			for a, _ := range c {
				if strings.IndexByte(a, '*') != -1 {
					if z {
						return false, "Wildcards inadmitidos"
					}
					continue
				}
				k, m := hostOk(a, false)
				if !k {
					if z {
						return false, m
					}
					continue
				}
				if m, k := domainAliases[a]; k {
					if m == s[1] && z {
						return false, "Alias sin cambios"
					}
					if z {
						return false, "Alias preasignado"
					}
					continue
				}
				domainAliases[a] = s[1]
				if z {
					return true, "Alias asignado"
				}
			}
			return true, "Alias procesados"
		},
	}

	subdomainContentDeleters = map[string]func(bool, interface{}, ...string) (bool, string){ // Subdomains content deletion check
		"!": func(printErrors bool, configData interface{}, siteKeys ...string) (bool, string) {
			//z := printErrors
			//c := configData
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en borrado de SSLs"
			}
			return true, "Certificados SSL procesados"
		},
		"=": func(printErrors bool, rewriteData interface{}, siteKeys ...string) (bool, string) {
			z := printErrors
			l := rewriteData
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en borrado de reescrituras"
			}
			c, e := l.(map[string]interface{})
			if !e {
				return false, "Contenido de reescrituras incorrecto"
			}

			if !siteExists(s[0], s[1]) {
				if s[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			for a, _ := range c {
				a = replaceURIChars(a)
				if _, e = sitesMap[s[0]][s[1]][a]; !e {
					if z {
						return false, "Reescritura inexistente"
					}
					continue
				}
				delete(sitesMap[s[0]][s[1]], a)
				if z {
					return true, "Reescritura borrada"
				}
			}
			return true, "Reescrituras procesadas"
		},
		"$": func(printErrors bool, mimeData interface{}, siteKeys ...string) (bool, string) {
			z := printErrors
			l := mimeData
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en borrado de MIMEs"
			}
			c, e := l.(map[string]interface{})
			if !e {
				return false, "Contenido de MIMEs incorrecto"
			}

			if !siteExists(s[0], s[1]) {
				if s[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			if s[1] != "" {
				s[1] += "." + s[0]
			} else {
				s[1] = s[0]
			}

			if _, e = mimeTypes[s[1]]; !e {
				return false, "MIMEs indefinidos"
			}

			for a, _ := range c {
				if len(a) > 0 && a[0] == '.' {
					a = a[1:]
				}
				if _, e = mimeTypes[s[1]][a]; !e {
					if z {
						return false, "MIME inexistente"
					}
					continue
				}
				delete(mimeTypes[s[1]], a)
				if z {
					return true, "MIME borrado"
				}
			}
			return true, "MIMEs procesados"
		},
		".": func(printErrors bool, headerData interface{}, siteKeys ...string) (bool, string) {
			z := printErrors
			l := headerData
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en borrado de cabeceras"
			}
			c, e := l.(map[string]interface{})
			if !e {
				return false, "Contenido de cabeceras incorrecto"
			}

			if !siteExists(s[0], s[1]) {
				if s[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			if s[1] != "" {
				s[1] += "." + s[0]
			} else {
				s[1] = s[0]
			}

			if _, e = customHeaders[s[1]]; !e {
				return false, "Cabeceras indefinidas"
			}

			for a, _ := range c {
				if _, e = customHeaders[s[1]][a]; !e {
					if z {
						return false, "Cabecera inexistente"
					}
					continue
				}
				delete(customHeaders[s[1]], a)
				if z {
					return true, "Cabecera borrada"
				}
			}
			return true, "Cabeceras procesadas"
		},
		"?": func(printErrors bool, preprocessorData interface{}, siteKeys ...string) (bool, string) {
			z := printErrors
			l := preprocessorData
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en borrado de preprocesadores"
			}
			c, e := l.(map[string]interface{})
			if !e {
				return false, "Contenido de preprocesadores incorrecto"
			}

			if !siteExists(s[0], s[1]) {
				if s[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			if s[1] != "" {
				s[1] += "." + s[0]
			} else {
				s[1] = s[0]
			}

			if _, e = preprocessors[s[1]]; !e {
				return false, "Preprocesadores no definidos"
			}

			for a, _ := range c {
				if len(a) > 0 && a[0] == '.' {
					a = a[1:]
				}
				if _, e = preprocessors[s[1]][a]; !e {
					if z {
						return false, "Preprocesador inexistente"
					}
					continue
				}
				delete(preprocessors[s[1]], a)
				if z {
					return true, "Preprocesador borrado"
				}
			}
			return true, "Preprocesadores procesados"
		},
		"-": func(printErrors bool, indexData interface{}, siteKeys ...string) (bool, string) {
			z := printErrors
			l := indexData
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en borrado de índices"
			}
			c, e := l.(map[string]interface{})
			if !e {
				return false, "Contenido de índices incorrecto"
			}

			if !siteExists(s[0], s[1]) {
				if s[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			if s[1] != "" {
				s[1] += "." + s[0]
			} else {
				s[1] = s[0]
			}

			if _, e = indexFiles[s[1]]; !e {
				return false, "Índices no definidos"
			}

			for a, _ := range c {
				a = replaceURIChars(a)
				if _, e = indexFiles[s[1]][a]; !e {
					if z {
						return false, "Índice inexistente"
					}
					continue
				}
				delete(indexFiles[s[1]], a)
				if z {
					return true, "Índice borrado"
				}
			}
			return true, "Índices procesados"
		},
		"&": func(printErrors bool, aliasData interface{}, siteKeys ...string) (bool, string) {
			z := printErrors
			l := aliasData
			s := siteKeys
			if len(s) != 2 {
				return false, stringStore["Z"] + " en borrado de alias"
			}
			c, e := l.(map[string]interface{})
			if !e {
				return false, "Contenido de alias incorrecto"
			}

			if !siteExists(s[0], s[1]) {
				if s[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			if s[1] != "" {
				s[1] += "." + s[0]
			} else {
				s[1] = s[0]
			}

			for a, _ := range c {
				if _, e = domainAliases[a]; !e {
					if z {
						return false, "Alias inexistente"
					}
					continue
				} else if domainAliases[a] != s[1] {
					if z {
						return false, "Alias impertinente"
					}
					continue
				}
				delete(domainAliases, a)
				if z {
					return true, "Alias borrado"
				}
			}
			return true, "Alias procesados"
		},
	}

	serverRestartRequiredSettings = map[string]bool{"M": true}            // List of settings that use restartServers
	passwordInputRequiredSettings = map[string]bool{"U": true, "P": true} // List of settings that need password input

	validDomainRegex = regexp.MustCompile(`^[a-zA-Z0-9\-\.]+$`)
	siteSSLSettingCheckers = map[string]func(bool, ...string) (bool, string){
		"E": func(printErrors bool, args ...string) (bool, string) {
			//x := printErrors;
			v := args
			p := len(v)
			if p < 3 && p > 5 {
				return false, stringStore["Z"] + " en E"
			}
			i, e := url.QueryUnescape(v[0])
			v[0] = i
			if e != nil || strings.IndexByte(v[0], '#') != -1 || strings.Contains(v[0], "--") || strings.IndexByte(v[0], ' ') != -1 || strings.IndexByte(v[0], '@') == -1 || strings.IndexByte(v[0], '.') == -1 {
				return false, "Valor de e-mail incorrecto"
			}

			v[0] = validDomainRegex.ReplaceAllString(v[0], "")
			if len(v[0]) < 5 || len(v[0]) > 40 {
				return false, "Longitud de e-mail incorrecta"
			}

			if !siteExists(v[1], v[2]) {
				if v[2] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if v[2] != "" {
				v[2] += "." + v[1]
			} else {
				v[2] = v[1]
			}

			if _, e := siteSSLConfig[v[2]]; !e {
				return false, "Configuración indefinida"
			}
			siteSSLConfig[v[2]]["E"] = v[0]
			return true, "E-mail guardado"
		},
		"A": func(printErrors bool, args ...string) (bool, string) {
			//x := printErrors;
			v := args
			p := len(v)
			if p < 3 && p > 5 {
				return false, stringStore["Z"] + " en A"
			}

			i, e := url.QueryUnescape(v[0])
			v[0] = i
			if e != nil || strings.IndexByte(v[0], '#') != -1 || strings.Contains(v[0], "--") || strings.IndexByte(v[0], ' ') != -1 {
				return false, "Valor de adaptador incorrecto"
			}

			v[0] = validDomainRegex.ReplaceAllString(v[0], "")
			if len(v[0]) < 5 || len(v[0]) > 15 {
				return false, "Longitud de adaptador incorrecta"
			}

			if !siteExists(v[1], v[2]) {
				if v[2] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if v[2] != "" {
				v[2] += "." + v[1]
			} else {
				v[2] = v[1]
			}

			if _, e := siteSSLConfig[v[2]]; !e {
				return false, "Configuración indefinida"
			}

			siteSSLConfig[v[2]]["A"] = v[0]
			return true, "Adaptador guardado"
		},
		"C": func(printErrors bool, args ...string) (bool, string) { x := printErrors; v := args
			p := len(v)
			if p < 3 && p > 5 {
				return false, stringStore["Z"] + " en C"
			}

			if !siteExists(v[1], v[2]) {
				if v[2] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			var siteKey string
			domain := v[1]
			if v[2] != "" {
				siteKey = v[2] + "." + v[1]
				v[1] = changeWildcards(v[1]) + "/" + changeWildcards(v[2]) + "/"
			} else {
				siteKey = v[1]
				v[1] = changeWildcards(v[1]) + "/"
			}

			if p == 5 {
				if v[3] != "" {
					if len(v[3]) < 5 || len(v[3]) > 40 || strings.IndexByte(v[3], '#') != -1 || strings.Contains(v[3], "--") || strings.Contains(v[3], "--") || strings.IndexByte(v[3], ' ') != -1 || strings.IndexByte(v[3], '@') == -1 || strings.IndexByte(v[3], '.') == -1 {
						return false, "E-mail incorrecto"
					}
					siteSSLConfig[siteKey]["E"] = v[3]
				}
				if v[4] != "" {
					if len(v[4]) < 5 || len(v[4]) > 15 || strings.IndexByte(v[4], '#') != -1 || strings.Contains(v[4], "--") || strings.IndexByte(v[4], ' ') != -1 {
						return false, "Adaptador incorrecto"
					}
					siteSSLConfig[siteKey]["A"] = v[4]
				}
			}

			var exists bool
			if _, exists = siteSSLConfig[siteKey]; !exists {
				return false, "Configuración indefinida"
			}

			exists = true
			fileInfo, statErr := os.Stat(stringStore["A"] + v[1] + stringStore["C"])
			if statErr != nil || fileInfo.IsDir() {
				exists = false
			}
			fileInfo, statErr = os.Stat(stringStore["A"] + v[1] + stringStore["K"])
			if statErr != nil || fileInfo.IsDir() {
				exists = false
			}

			if exists && (time.Now().Unix()-fileInfo.ModTime().Unix()) > 6480000 {
				exists = false
			}

			if exists {
				if !x && v[0] == "0" {
					if os.Remove(stringStore["A"]+v[1]+stringStore["C"]) != nil ||
						os.Remove(stringStore["A"]+v[1]+stringStore["K"]) != nil {
						return false, "Error al borrar archivos SSL"
					}
					siteSSLConfig[siteKey]["C"] = false
					return true, "Certificado SSL borrado"
				}

				siteSSLConfig[siteKey]["C"] = true
				return true, "Certificado SSL activo"
			}

			// If there is no valid cert files:

			if x && v[0] != "0" && v[0] != "1" {
				siteSSLConfig[siteKey]["C"] = v[0]
			}

			_, k := siteSSLConfig[siteKey]["C"].(bool)
			if !k {
				v[1] = siteKey
				var certificateMsg string
				certificateMsg, k = siteSSLConfig[siteKey]["C"].(string)
				if !k {
					certificateMsg = "Respuesta incorrecta de certificado"
				}
				siteSSLConfig[v[1]]["C"] = false
				return false, certificateMsg
			}

			siteSSLConfig[siteKey]["C"] = false

			v[0] = stringStore["A"] + v[1]              // Dir where the certificate will remain with sites
			v[1] = stringStore["A"] + putSlash(stringStore["S"]) // Dir of certificates
			fileInfo, statErr = os.Stat(v[1])
			if statErr != nil || !fileInfo.IsDir() {
				fmt.Println("Try to create certificates dir.")
				if os.Mkdir(v[1], 0700) != nil {
					return false, "Error al crear directorio de certificados"
				}
			}

			v[1] += changeWildcards(domain) // m because the folder created by Certbot is not a subdomain name but domain name

			if currentCertDomain == siteKey {
				return false, "{\"message\":\"Espere, certificado procesándose\",\"status\":\"WAIT\"}"
			}

			obtainCertificate(siteKey, v[1], v[0]) // Creates a loop of attempts to get a certificate

			if currentCertDomain != siteKey {
				return false, "{\"message\":\"Espere, certificado ocupado en " + currentCertDomain + "\",\"status\":\"WAIT\"}"
			}
			return false, "{\"message\":\"Espere, certificado en proceso\",\"status\":\"WAIT\"}"
		},
		"S": func(printErrors bool, args ...string) (bool, string) {
			//x := printErrors;
			v := args
			p := len(v)
			if p < 3 && p > 5 {
				return false, stringStore["Z"] + " en S"
			}

			z, f := strconv.Atoi(v[0])
			if f != nil {
				return false, "Valor incorrecto"
			}

			if !siteExists(v[1], v[2]) {
				if v[2] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			var l string
			if v[2] != "" {
				l = v[2] + "." + v[1]
			} else {
				l = v[1]
			}

			var e bool
			if _, e = siteSSLConfig[l]; !e {
				return false, "Configuración indefinida"
			}

			if z != 0 {
				if _, e = tlsConfig.NameToCertificate[l]; !e {
					if v[2] != "" {
						v[1] = changeWildcards(v[1]) + "/" + changeWildcards(v[2]) + "/"
					} else {
						v[1] = changeWildcards(v[1]) + "/"
					}
					k, a := tls.LoadX509KeyPair(stringStore["A"]+v[1]+stringStore["C"], stringStore["A"]+v[1]+stringStore["K"])
					if a != nil {
						return false, "Certificados SSL incorrectos o inexistentes"
					}

					tlsConfig.Certificates = append(tlsConfig.Certificates, k)
					siteSSLConfig[l]["S"] = len(tlsConfig.Certificates)
					if tlsConfig.NameToCertificate == nil {
						tlsConfig.NameToCertificate = make(map[string]*tls.Certificate)
					}
					tlsConfig.NameToCertificate[l] = &tlsConfig.Certificates[siteSSLConfig[l]["S"].(int)-1]
					if servers[0] != nil {
						safeServerStart(servers[0], tlsConfig) // This starts a SSL server if isn't started yet
					}

					fmt.Println(l + " cert enabled.")
					return true, "Redirección a HTTPS activada"
				}
				siteSSLConfig[l]["S"] = 0
				return false, "Redirección a HTTPS existente"
			}

			// If the setting values is 0:

			if siteSSLConfig[l]["S"] != 0 {
				// This value is different that the setting value, means an index on Certificates map
				deleteCertificate(l)
			}

			siteSSLConfig[l]["S"] = 0
			return true, "Redirección a HTTPS desactivada"
		},
		"R": func(printErrors bool, args ...string) (bool, string) {
			//x := printErrors;
			v := args
			p := len(v)
			if p < 3 && p > 5 {
				return false, stringStore["Z"] + " en R"
			}
			if v[0] != "0" && v[0] != "1" {
				return false, "Valor incorrecto"
			}
			if !siteExists(v[1], v[2]) {
				if v[2] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if v[2] != "" {
				v[2] += "." + v[1]
			} else {
				v[2] = v[1]
			}

			if _, e := siteSSLConfig[v[2]]; !e {
				return false, "Configuración indefinida"
			}

			if v[0] != "0" {
				if siteSSLConfig[v[2]]["W"] == true {
					return false, "Redirección a www activada"
				}
				siteSSLConfig[v[2]]["R"] = true
				v[1] = ""
			} else {
				siteSSLConfig[v[2]]["R"] = false
				v[1] = "des"
			}
			return true, "Redirección a raíz " + v[1] + "activada"
		},
		"W": func(printErrors bool, args ...string) (bool, string) {
			//x := printErrors;
			v := args
			p := len(v)
			if p < 3 && p > 5 {
				return false, stringStore["Z"] + " en W"
			}
			if v[0] != "0" && v[0] != "1" {
				return false, "Valor incorrecto"
			}
			if !siteExists(v[1], v[2]) {
				if v[2] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}
			if v[2] != "" {
				v[2] += "." + v[1]
			} else {
				v[2] = v[1]
			}

			if _, e := siteSSLConfig[v[2]]; !e {
				return false, "Configuración indefinida"
			}

			if v[0] != "0" {
				if siteSSLConfig[v[2]]["R"] == true {
					return false, "Redirección a raíz activada"
				}
				siteSSLConfig[v[2]]["W"] = true
				v[1] = ""
			} else {
				siteSSLConfig[v[2]]["W"] = false
				v[1] = "des"
			}
			return true, "Redirección a WWW " + v[1] + "activada"
		},
	}

	shortcutWordReplacers = map[string]func(*customNetHttp.Request, ...string) string{
		currentDirPlaceholder: func(request *customNetHttp.Request, wildcardParts ...string) string {
			//r := request
			//x := wildcardParts
			return currentDir()
		},
		"WILDCARD_SITE": func(request *customNetHttp.Request, wildcardParts ...string) string {
			//r := request
			x := wildcardParts
			if x[1] != "" {
				return x[1] + "." + x[0]
			}
			return x[0]
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
		"FIRST_REQUEST": func(request *customNetHttp.Request, wildcardParts ...string) string { return url.QueryEscape(request.RequestURI) },
		"FIRST_QUERY": func(request *customNetHttp.Request, wildcardParts ...string) string {
			y := strings.IndexByte(request.RequestURI, '?')
			if y != -1 {
				return url.QueryEscape(request.RequestURI[y+1:])
			}
			return ""
		},
		"DIR": func(request *customNetHttp.Request, wildcardParts ...string) string {
			z := dir(cutAt(request.RequestURI, '?'))
			if z == "/" {
				return ""
			}
			return url.QueryEscape(z)
		},
		"FILE": func(request *customNetHttp.Request, wildcardParts ...string) string {
			z := cutAt(request.RequestURI, '?')
			if z[len(z)-1] != '/' {
				return url.QueryEscape(serverFuncBase(z))
			}
			return ""
		},
		"EXT":     func(request *customNetHttp.Request, wildcardParts ...string) string { return ext(cutAt(request.RequestURI, '?')) },
		"REWRITE": func(request *customNetHttp.Request, wildcardParts ...string) string { return url.QueryEscape(wildcardParts[6]) },
		"REWRITE_COMPLEMENT": func(request *customNetHttp.Request, wildcardParts ...string) string {
			z := len(wildcardParts[6])
			if z < len(request.RequestURI) {
				return url.QueryEscape(request.RequestURI[z:])
			}
			return ""
		},
	}
)
