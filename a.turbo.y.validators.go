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
	CD_ = "TURBO_CURRENT_DIR"
	X   map[string]map[string]interface{}

	F = map[string]func(string, string){ // Site & subdomains existence check reset fallback
		"/": func(d string, s string) {},
	}

	E = map[string]func(bool, string, string) (bool, string){ // Site & subdomains existence check
		"/": func(k bool, d string, s string) (bool, string) {
			var a string
			b := d
			c := s
			if s != "" {
				a = s + "." + changeWildcards(d, "x") // To check if domain name is correct, because it can't be verified if '*' or '#' is present
			} else {
				a = d
			}
			if m, _ := hostOk(a, false); !m {
				return false, "Nombre incorrecto de directorio de sitio"
			}
			d = changeWildcards(d)
			if s != "" {
				a = "/"
				s = changeWildcards(s)
			} else {
				a = ""
			}
			_, e := os.ReadDir(S_["A"] + d + a + s)
			if e != nil {
				return false, "Directorio de sitio inexistente: " + d + a + s
			}
			_, e = os.ReadDir(S_["A"] + d + a + s + "/" + S_["F"])
			if e != nil {
				return false, "Directorio de contenido de sitio inexistente: " + d + a + s + "/" + S_["F"]
			}
			if k && !siteExists(b, c) {
				_constructSite(b, c)
			}
			return true, "Directorio de sitio procesado"
		},
	}

	R_ = map[string]map[string]func(){ // Default settings check reset fallback
		".": {
			"C":   func() {},
			"U":   func() {},
			"P":   func() {},
			"M":   func() {},
			"MUB": func() { YU = 1000 },
			"MHB": func() { YH = 5000 },    // Need to be set first.
			"MBB": func() { L_ = 1048576 }, // 1 Mb
			"CIL": func() { G[0] = 10000000000 },
			"CIS": func() { G[1] = 1000000000 }, // Need to be first to be set
			"CII": func() { G[2] = 100 },
			"RT":  func() { V["RT"] = 5 * time.Second }, // Need to be first to be set
			"RHT": func() { V["RHT"] = 1 * time.Second },
			"WT":  func() { V["WT"] = 10 * time.Second },
			"IT":  func() { V["IT"] = 2 * time.Second },
		},
	}

	_MD = map[string]func(string) (bool, string){
		"@": func(k string) (bool, string) {
			if _, a := J[k]; !a {
				return false, "IP inexistente"
			}
			delete(J, k)
			return true, "IP denegado eliminado"
		},
		"#": func(k string) (bool, string) {
			c, e := strconv.Atoi(k)
			if e != nil {
				return false, "Código HTTP inválido"
			}
			var a bool
			if _, a = Y[c]; !a {
				return false, "Respuesta inexistente"
			}
			if _, a = YF[c]; a {
				return false, "Respuesta inmutable"
			}
			delete(Y, c)
			return true, "Respuesta a código HTTP eliminada"
		},
		"_": func(k string) (bool, string) {
			k = replaceURIChars(k)
			var a bool
			if _, a = B_[k]; !a {
				return false, "Reemplazo inexistente"
			}
			if _, a = BF[k]; a {
				return false, "Reemplazo inmutable"
			}
			delete(B_, k)
			return true, "Reemplazo a caracter(es) eliminado"
		},
	}

	_MX = map[string]func(string, string) (bool, string){
		"@": func(k string, v string) (bool, string) {
			if net.ParseIP(k) == nil {
				return false, "IP incorrecto"
			}
			v = strings.TrimSpace(v)
			k = ipAddr(k)
			if _, a := I[k]; a {
				return false, "IP actual"
			}
			if k == "127.0.0.1" || k[:3] == "127" || k == "::1" || k == "0:0:0:0:0:0:0:1" {
				return false, "IP localhost"
			}
			i, e := strconv.ParseInt(v, 10, 64)
			if e != nil {
				return false, "Fecha UNIX incorrecta"
			}
			l, a := J[k]
			if i == 0 || time.Now().Unix() > i {
				if a {
					delete(J, k)
					return true, "IP denegado eliminado"
				}
				return false, "Fecha UNIX expirada"
			}
			z := true
			if strconv.FormatInt(l, 10) == v {
				z = false
				v = "sin cambios"
			} else if a {
				v = "modificado"
			} else {
				v = "agregado"
			}
			J[k] = i
			return z, "IP denegado " + v
		},
		"#": func(k string, v string) (bool, string) {
			c, e := strconv.Atoi(k)
			if e != nil {
				return false, "Código HTTP inválido"
			}
			if (c < 400 || c > 599) && c != 0 {
				return false, "Código HTTP incorrecto"
			}
			v = strings.TrimSpace(v)
			l := len(v)
			if l < 1 || l > 2048 {
				return false, "Respuesta muy corta o larga"
			}
			s, a := Y[c]
			if a && s == v {
				return false, "Respuesta sin cambios"
			}
			Y[c] = v
			return true, "Respuesta guardada"
		},
		"_": func(k string, v string) (bool, string) {
			k2 := replaceURIChars(k)
			v2 := replaceURIChars(v)
			for i := range BF {
				if (strings.IndexByte(k, i[0]) != -1 && k != i) || (strings.IndexByte(k2, i[0]) != -1 && k2 != i) {
					return false, "Caracter de reemplazo inválido"
				}
				if strings.IndexByte(v, i[0]) != -1 || strings.IndexByte(v2, i[0]) != -1 {
					return false, "Reemplazo inválido"
				}
			}
			var l int
			if k2 != " " {
				k2 = strings.TrimSpace(k2)
				l = len(k2)
				if l < 1 {
					return false, "Sin caracter"
				}
				if l > 4 {
					return false, "Muchos caracteres"
				}
			}
			if v2 != " " {
				v2 = strings.TrimSpace(v2)
				l = len(v2)
				if l < 1 || l > 16 {
					return false, "Reemplazo muy corto o largo"
				}
			}
			if s, a := B_[k2]; a && s == v2 {
				return false, "Reemplazo sin cambios"
			}
			B_[k2] = v2
			return true, "Reemplazo de caracter(es) guardado"
		},
	}

	_MO = map[string][]string{
		".": {"C", "U", "P", "M", "MUB", "MHB", "MBB", "CIL", "CIS", "CII", "RT", "RHT", "WT", "IT"},
	}

	_ME = map[string]map[string]map[string]bool{ // ME (E, for exceptions). There are some exceptions on errors, some cause unnecessary resets
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

	M = map[string]map[string]func(...string) (bool, string){ // Default settings check
		".": {
			"C": func(v ...string) (bool, string) {
				if len(v) != 2 {
					return false, S_["Z"] + " en C"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña incorrecta"
				}
				if !saveDefaultConfig() {
					return false, "Error al guardar"
				}
				return true, "Configuración guardada"
			},
			"U": func(v ...string) (bool, string) {
				if len(v) != 2 {
					return false, S_["Z"] + " en U"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña actual incorrecta"
				}
				l := len(v[0])
				if l < 1 || l > 24 {
					return false, "Usuario muy largo o corto"
				}
				S_["U"] = v[0]
				return true, "Usuario cambiado"
			},
			"P": func(v ...string) (bool, string) {
				if len(v) != 2 {
					return false, S_["Z"] + " en P"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña actual incorrecta"
				}
				l := len(v[0])
				if l < 1 || l > 24 {
					return false, "Contraseña muy larga o corta"
				}
				S_["P"] = v[0]
				return true, "Contraseña cambiada"
			},
			"M": func(v ...string) (bool, string) {
				if len(v) < 2 {
					return false, S_["Z"] + " en D"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña actual incorrecta"
				}

				v[0] = putSlash(v[0])
				if v[0] == S_["A"] {
					return false, "Directorio de sitios sin cambios"
				}

				v[0] = strings.Replace(v[0], "{"+CD_+"}", currentDir(), 1)
				m, i := os.Stat(v[0])
				if os.IsNotExist(i) || !m.IsDir() {
					return false, "Directorio de sitios inexistente"
				}
				S_["A"] = v[0]
				return true, "Directorio de sitios configurado"
			},
			"MUB": func(v ...string) (bool, string) {
				if len(v) != 2 {
					return false, S_["Z"] + " en MUB"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := strconv.Atoi(v[0])
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == YU {
					return false, "Valor sin cambios"
				}
				if j < 40 {
					return false, "Inferior a 40 bytes"
				}
				if j > 10240 {
					return false, "Superior a 10240 bytes"
				}
				YU = j
				return true, "Longitud máxima de URIs guardada"
			},
			"MHB": func(v ...string) (bool, string) {
				if len(v) != 2 {
					return false, S_["Z"] + " en MHB"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := strconv.Atoi(v[0])
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == YH {
					return false, "Valor sin cambios"
				}
				if j < 600 {
					return false, "Inferior a 600 bytes"
				}
				if j > 20480 {
					return false, "Superior a 20480 bytes"
				}
				YH = j
				return true, "Longitud máxima de cabeceras guardada"
			},
			"MBB": func(v ...string) (bool, string) {
				if len(v) != 2 {
					return false, S_["Z"] + " en MBB"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := strconv.ParseInt(v[0], 10, 64)
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == L_ {
					return false, "Valor sin cambios"
				}
				if j < 1 {
					return false, "Inferior a 1 byte"
				}
				if j > 104857600 {
					return false, "Superior a 104857600 bytes (100 Mb)"
				}
				L_ = j
				return true, "Longitud máxima de contenidos guardada"
			},
			"CIL": func(v ...string) (bool, string) {
				if len(v) != 2 {
					return false, S_["Z"] + " en CIL"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := strconv.ParseInt(v[0], 10, 64)
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j*10000000 == G[0] {
					return false, "Valor sin cambios"
				}
				if j < 100 {
					return false, "Inferior a 100 milisegundos"
				}
				if j > 80000 {
					return false, "Superior a 80000 milisegundos"
				}
				G[0] = j * 10000000
				return true, "Límite de intervalo para peticiones guardado"
			},
			"CIS": func(v ...string) (bool, string) {
				if len(v) != 2 {
					return false, S_["Z"] + " en CIS"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := strconv.ParseInt(v[0], 10, 64)
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j*10000000 == G[1] {
					return false, "Valor sin cambios"
				}
				if j < 1 {
					return false, "Inferior a 1 milisegundo"
				}
				if j > 5000 {
					return false, "Superior a 5000 milisegundos"
				}
				G[1] = j * 10000000
				return true, "Intervalo para peticiones guardado"
			},
			"CII": func(v ...string) (bool, string) {
				if len(v) != 2 {
					return false, S_["Z"] + " en CII"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := strconv.ParseInt(v[0], 10, 64)
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == G[2] {
					return false, "Valor sin cambios"
				}
				if j < 1 {
					return false, "Inferior a 1"
				}
				k := (G[1] / 10000000) * 10
				if j > k {
					return false, "Superior a " + strconv.FormatInt(k, 10)
				}
				if k/j > 66 { // Represent minimum capability for panel, 1000ms => 2000 / 30 reqs = 66
					return false, "Valor incompatible con el panel"
				}
				G[2] = j
				return true, "Peticiones máximas por intervalo guardado"
			},
			"RT": func(v ...string) (bool, string) { // Need to be the first to be set
				if len(v) != 2 {
					return false, S_["Z"] + " en RT"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := time.ParseDuration(v[0])
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == V["RT"] {
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
				V["RT"] = j
				return true, "Valor guardado lectura de peticiones"
			},
			"RHT": func(v ...string) (bool, string) {
				if len(v) != 2 {
					return false, S_["Z"] + " en RHT"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := time.ParseDuration(v[0])
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == V["RHT"] {
					return false, "Valor sin cambios"
				}
				if j != 0 {
					if j < 50*time.Millisecond {
						return false, "Inferior a 50 milisegundos"
					}
					if j > (V["RT"] / 2) {
						return false, "Más que la mitad de lectura de peticiones"
					}
					if j > 450000*time.Millisecond {
						return false, "Superior a 7.5 minutos"
					}
				}
				V["RHT"] = j
				return true, "Valor guardado de lectura de cabeceras"
			},
			"WT": func(v ...string) (bool, string) {
				if len(v) != 2 {
					return false, S_["Z"] + " en WT"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := time.ParseDuration(v[0])
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == V["WT"] {
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
				V["WT"] = j
				return true, "Valor guardado de escritura de respuestas"
			},
			"IT": func(v ...string) (bool, string) {
				if len(v) != 2 {
					return false, S_["Z"] + " en IT"
				}
				if v[1] != S_["P"] {
					return false, "Contraseña actual incorrecta"
				}
				j, e := time.ParseDuration(v[0])
				if e != nil {
					return false, "Valor incorrecto"
				}
				if j == V["IT"] {
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
				V["IT"] = j
				return true, "Valor guardado de conexiones inactivas"
			},
		},
	}

	C = map[string]func(bool, interface{}, bool, ...string) (bool, string){ // Subdomains content check
		"!": func(z bool, c interface{}, x bool, s ...string) (bool, string) { // SSLs check
			if len(s) != 2 {
				return false, S_["Z"] + " en configuraciones"
			}
			g, e := c.(map[string]interface{})
			if !e {
				return false, "Datos de configuraciones incorrectos"
			}
			var v string

			for k, _ := range _B {
				if _, e = g[k]; !e {
					continue
				}

				v, e = g[k].(string) // String is only for config file entries reading
				if !e {
					w, f := g[k].(bool)
					if f {
						e = true
						if w {
							v = "1"
						} else {
							v = "0"
						}
					} else {
						x, g := g[k].(int)
						if g {
							e = true
							v = strconv.Itoa(x)
						}
					}
				}

				if !e {
					if z {
						return false, "Valor de configuración incorrecto"
					}
					continue
				}

				if e, k = _B[k](x, v, s[0], s[1]); !e {
					if z {
						return false, k
					}
				}
			}
			return true, "Configuraciones procesadas"
		},
		"=": func(z bool, l interface{}, x bool, s ...string) (bool, string) { // Rewrites check
			if len(s) != 2 {
				return false, S_["Z"] + " en reescrituras"
			}
			c, e := l.(map[string]interface{})
			if !e {
				return false, "Contenido de reescrituras incorrecto"
			}

			if z && !siteExists(s[0], s[1]) {
				if s[1] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			for u, v := range c {
				r, e := v.(string)
				if !e {
					if z {
						return false, "Valor de reescritura incorrecto"
					}
					continue
				}

				var j bool
				u = replaceURIChars(u)
				if _, e = O[s[0]][s[1]][u]; e {
					j = true
					if O[s[0]][s[1]][u][1:] == r {
						if z {
							return false, "Reescritura sin cambios"
						}
						continue
					}
				} else {
					j = false
				}
				l := len(u)
				if l < 1 || strings.Contains(u, "//") || strings.Contains(u, "..") || u[0] != '/' {
					if z {
						return false, "Dirección relativa incorrecta"
					}
					continue
				}
				if l > 128 {
					if z {
						return false, "Dirección relativa excesiva"
					}
					continue
				}
				r = replaceURIChars(r)
				l = len(r)
				if l < 1 || strings.Contains(r, "..") {
					if z {
						return false, "Reescritura incorrecta"
					}
					continue
				}
				m := "N"
				if l > 7 {
					if (r[0] == 'h' || r[0] == 'H') &&
						(r[1] == 't' || r[1] == 'T') &&
						(r[2] == 't' || r[2] == 'T') &&
						(r[3] == 'p' || r[3] == 'P') {
						if r[4] == ':' && r[5] == '/' && r[6] == '/' {
							m = "H"
							r = r[7:]
						} else if r[4] == 's' && r[5] == ':' && r[6] == '/' && r[7] == '/' {
							m = "S"
							r = r[8:]
						}
					}
				}
				if strings.Contains(r, "//") {
					if z {
						return false, "Reescritura incorrecta"
					}
					continue
				}
				if l > 512 {
					if z {
						return false, "Reescritura excesiva"
					}
					continue
				}
				O[s[0]][s[1]][u] = m + r
				if z {
					if !j {
						return true, "Reescritura creada"
					} else {
						return true, "Reescritura cambiada"
					}
				}
			}
			return true, "Reescrituras procesadas"
		},
		"$": func(z bool, l interface{}, x bool, s ...string) (bool, string) { // MIMEs check
			if len(s) != 2 {
				return false, S_["Z"] + " en MIMEs"
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

			if _, a = T[s[1]]; !a {
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
				if _, a = T[s[1]][e]; a {
					j = true
					if T[s[1]][e] == m {
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
				T[s[1]][e] = m
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
		".": func(z bool, l interface{}, x bool, s ...string) (bool, string) { // Headers check
			if len(s) != 2 {
				return false, S_["Z"] + " en cabeceras"
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

			if _, e = Q[s[1]]; !e {
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
				if _, e = Q[s[1]][h]; e {
					j = true
					if Q[s[1]][h] == c {
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
				if l < 1 || l > H1_ {
					if z {
						return false, "Cabecera muy larga o corta"
					}
					continue
				}
				l = len(c)
				if l < 1 || l > H2_ {
					if z {
						return false, "Contenido muy largo o corto"
					}
					continue
				}
				Q[s[1]][h] = c
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
		"?": func(z bool, l interface{}, x bool, s ...string) (bool, string) { // Preprocessors check
			if len(s) != 2 {
				return false, S_["Z"] + " en preprocesadores"
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

			if _, a = D[s[1]]; !a {
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
				if _, a = D[s[1]][e]; a {
					j = true
					if D[s[1]][e] == p {
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

				p = strings.Replace(p, "{"+CD_+"}", currentDir(), 1)

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

				D[s[1]][e] = p
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
		"-": func(z bool, l interface{}, x bool, s ...string) (bool, string) { // Indexes check
			if len(s) != 2 {
				return false, S_["Z"] + " en índices"
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

			if _, e = H[s[1]]; !e {
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
				H[s[1]][i] = false
				if z {
					return true, "Índice asignado"
				}
			}
			return true, "Índices procesados"
		},
		"&": func(z bool, l interface{}, x bool, s ...string) (bool, string) { // Alias check
			if len(s) != 2 {
				return false, S_["Z"] + " en alias"
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
				if m, k := A[a]; k {
					if m == s[1] && z {
						return false, "Alias sin cambios"
					}
					if z {
						return false, "Alias preasignado"
					}
					continue
				}
				A[a] = s[1]
				if z {
					return true, "Alias asignado"
				}
			}
			return true, "Alias procesados"
		},
	}

	K = map[string]func(bool, interface{}, ...string) (bool, string){ // Subdomains content deletion check
		"!": func(z bool, c interface{}, s ...string) (bool, string) {
			if len(s) != 2 {
				return false, S_["Z"] + " en borrado de SSLs"
			}
			return true, "Certificados SSL procesados"
		},
		"=": func(z bool, l interface{}, s ...string) (bool, string) {
			if len(s) != 2 {
				return false, S_["Z"] + " en borrado de reescrituras"
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
				if _, e = O[s[0]][s[1]][a]; !e {
					if z {
						return false, "Reescritura inexistente"
					}
					continue
				}
				delete(O[s[0]][s[1]], a)
				if z {
					return true, "Reescritura borrada"
				}
			}
			return true, "Reescrituras procesadas"
		},
		"$": func(z bool, l interface{}, s ...string) (bool, string) {
			if len(s) != 2 {
				return false, S_["Z"] + " en borrado de MIMEs"
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

			if _, e = T[s[1]]; !e {
				return false, "MIMEs indefinidos"
			}

			for a, _ := range c {
				if len(a) > 0 && a[0] == '.' {
					a = a[1:]
				}
				if _, e = T[s[1]][a]; !e {
					if z {
						return false, "MIME inexistente"
					}
					continue
				}
				delete(T[s[1]], a)
				if z {
					return true, "MIME borrado"
				}
			}
			return true, "MIMEs procesados"
		},
		".": func(z bool, l interface{}, s ...string) (bool, string) {
			if len(s) != 2 {
				return false, S_["Z"] + " en borrado de cabeceras"
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

			if _, e = Q[s[1]]; !e {
				return false, "Cabeceras indefinidas"
			}

			for a, _ := range c {
				if _, e = Q[s[1]][a]; !e {
					if z {
						return false, "Cabecera inexistente"
					}
					continue
				}
				delete(Q[s[1]], a)
				if z {
					return true, "Cabecera borrada"
				}
			}
			return true, "Cabeceras procesadas"
		},
		"?": func(z bool, l interface{}, s ...string) (bool, string) {
			if len(s) != 2 {
				return false, S_["Z"] + " en borrado de preprocesadores"
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

			if _, e = D[s[1]]; !e {
				return false, "Preprocesadores no definidos"
			}

			for a, _ := range c {
				if len(a) > 0 && a[0] == '.' {
					a = a[1:]
				}
				if _, e = D[s[1]][a]; !e {
					if z {
						return false, "Preprocesador inexistente"
					}
					continue
				}
				delete(D[s[1]], a)
				if z {
					return true, "Preprocesador borrado"
				}
			}
			return true, "Preprocesadores procesados"
		},
		"-": func(z bool, l interface{}, s ...string) (bool, string) {
			if len(s) != 2 {
				return false, S_["Z"] + " en borrado de índices"
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

			if _, e = H[s[1]]; !e {
				return false, "Índices no definidos"
			}

			for a, _ := range c {
				a = replaceURIChars(a)
				if _, e = H[s[1]][a]; !e {
					if z {
						return false, "Índice inexistente"
					}
					continue
				}
				delete(H[s[1]], a)
				if z {
					return true, "Índice borrado"
				}
			}
			return true, "Índices procesados"
		},
		"&": func(z bool, l interface{}, s ...string) (bool, string) {
			if len(s) != 2 {
				return false, S_["Z"] + " en borrado de alias"
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
				if _, e = A[a]; !e {
					if z {
						return false, "Alias inexistente"
					}
					continue
				} else if A[a] != s[1] {
					if z {
						return false, "Alias impertinente"
					}
					continue
				}
				delete(A, a)
				if z {
					return true, "Alias borrado"
				}
			}
			return true, "Alias procesados"
		},
	}

	_A  = map[string]bool{"M": true}            // List of settings that use restartServers
	_AP = map[string]bool{"U": true, "P": true} // List of settings that need password input

	_B_r = regexp.MustCompile(`^[a-zA-Z0-9\-\.]+$`)
	_B   = map[string]func(bool, ...string) (bool, string){
		"E": func(x bool, v ...string) (bool, string) {
			p := len(v)
			if p < 3 && p > 5 {
				return false, S_["Z"] + " en E"
			}
			i, e := url.QueryUnescape(v[0])
			v[0] = i
			if e != nil || strings.IndexByte(v[0], '#') != -1 || strings.Contains(v[0], "--") || strings.IndexByte(v[0], ' ') != -1 || strings.IndexByte(v[0], '@') == -1 || strings.IndexByte(v[0], '.') == -1 {
				return false, "Valor de e-mail incorrecto"
			}

			v[0] = _B_r.ReplaceAllString(v[0], "")
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

			if _, e := W[v[2]]; !e {
				return false, "Configuración indefinida"
			}
			W[v[2]]["E"] = v[0]
			return true, "E-mail guardado"
		},
		"A": func(x bool, v ...string) (bool, string) {
			p := len(v)
			if p < 3 && p > 5 {
				return false, S_["Z"] + " en A"
			}

			i, e := url.QueryUnescape(v[0])
			v[0] = i
			if e != nil || strings.IndexByte(v[0], '#') != -1 || strings.Contains(v[0], "--") || strings.IndexByte(v[0], ' ') != -1 {
				return false, "Valor de adaptador incorrecto"
			}

			v[0] = _B_r.ReplaceAllString(v[0], "")
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

			if _, e := W[v[2]]; !e {
				return false, "Configuración indefinida"
			}

			W[v[2]]["A"] = v[0]
			return true, "Adaptador guardado"
		},
		"C": func(x bool, v ...string) (bool, string) {
			p := len(v)
			if p < 3 && p > 5 {
				return false, S_["Z"] + " en C"
			}

			if !siteExists(v[1], v[2]) {
				if v[2] != "" {
					return false, "Subdominio inexistente"
				}
				return false, "Sitio inexistente"
			}

			var l string
			m := v[1]
			if v[2] != "" {
				l = v[2] + "." + v[1]
				v[1] = changeWildcards(v[1]) + "/" + changeWildcards(v[2]) + "/"
			} else {
				l = v[1]
				v[1] = changeWildcards(v[1]) + "/"
			}

			if p == 5 {
				if v[3] != "" {
					if len(v[3]) < 5 || len(v[3]) > 40 || strings.IndexByte(v[3], '#') != -1 || strings.Contains(v[3], "--") || strings.Contains(v[3], "--") || strings.IndexByte(v[3], ' ') != -1 || strings.IndexByte(v[3], '@') == -1 || strings.IndexByte(v[3], '.') == -1 {
						return false, "E-mail incorrecto"
					}
					W[l]["E"] = v[3]
				}
				if v[4] != "" {
					if len(v[4]) < 5 || len(v[4]) > 15 || strings.IndexByte(v[4], '#') != -1 || strings.Contains(v[4], "--") || strings.IndexByte(v[4], ' ') != -1 {
						return false, "Adaptador incorrecto"
					}
					W[l]["A"] = v[4]
				}
			}

			var e bool
			if _, e = W[l]; !e {
				return false, "Configuración indefinida"
			}

			e = true
			b, g := os.Stat(S_["A"] + v[1] + S_["C"])
			if g != nil || b.IsDir() {
				e = false
			}
			b, g = os.Stat(S_["A"] + v[1] + S_["K"])
			if g != nil || b.IsDir() {
				e = false
			}

			if e && (time.Now().Unix()-b.ModTime().Unix()) > 6480000 {
				e = false
			}

			if e {
				if !x && v[0] == "0" {
					if os.Remove(S_["A"]+v[1]+S_["C"]) != nil ||
						os.Remove(S_["A"]+v[1]+S_["K"]) != nil {
						return false, "Error al borrar archivos SSL"
					}
					W[l]["C"] = false
					return true, "Certificado SSL borrado"
				}

				W[l]["C"] = true
				return true, "Certificado SSL activo"
			}

			// If there is no valid cert files:

			if x && v[0] != "0" && v[0] != "1" {
				W[l]["C"] = v[0]
			}

			_, k := W[l]["C"].(bool)
			if !k {
				v[1] = l
				l, k = W[l]["C"].(string)
				if !k {
					l = "Respuesta incorrecta de certificado"
				}
				W[v[1]]["C"] = false
				return false, l
			}

			W[l]["C"] = false

			v[0] = S_["A"] + v[1]              // Dir where the certificate will remain with sites
			v[1] = S_["A"] + putSlash(S_["S"]) // Dir of certificates
			b, g = os.Stat(v[1])
			if g != nil || !b.IsDir() {
				fmt.Println("Try to create certificates dir.")
				if os.Mkdir(v[1], 0700) != nil {
					return false, "Error al crear directorio de certificados"
				}
			}

			v[1] += changeWildcards(m) // m because the folder created by Certbot is not a subdomain name but domain name

			if CC == l {
				return false, "Espere, certificado procesándose"
			}

			obtainCertificate(l, v[1], v[0]) // Creates a loop of attempts to get a certificate

			if CC != l {
				return false, "Espere, certificado ocupado en " + CC
			}
			return false, "Espere, certificado en proceso"
		},
		"S": func(x bool, v ...string) (bool, string) {
			p := len(v)
			if p < 3 && p > 5 {
				return false, S_["Z"] + " en S"
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
			if _, e = W[l]; !e {
				return false, "Configuración indefinida"
			}

			if z != 0 {
				if _, e = U.NameToCertificate[l]; !e {
					if v[2] != "" {
						v[1] = changeWildcards(v[1]) + "/" + changeWildcards(v[2]) + "/"
					} else {
						v[1] = changeWildcards(v[1]) + "/"
					}
					k, a := tls.LoadX509KeyPair(S_["A"]+v[1]+S_["C"], S_["A"]+v[1]+S_["K"])
					if a != nil {
						return false, "Certificados SSL incorrectos o inexistentes"
					}

					U.Certificates = append(U.Certificates, k)
					W[l]["S"] = len(U.Certificates)
					if U.NameToCertificate == nil {
						U.NameToCertificate = make(map[string]*tls.Certificate)
					}
					U.NameToCertificate[l] = &U.Certificates[W[l]["S"].(int)-1]
					if N[0] != nil {
						safeServerStart(N[0], U) // This starts a SSL server if isn't started yet
					}

					fmt.Println(l + " cert enabled.")
					return true, "Redirección a HTTPS activada"
				}
				W[l]["S"] = 0
				return false, "Redirección a HTTPS existente"
			}

			// If the setting values is 0:

			if W[l]["S"] != 0 {
				// This value is different that the setting value, means an index on Certificates map
				deleteCertificate(l)
			}

			W[l]["S"] = 0
			return true, "Redirección a HTTPS desactivada"
		},
		"R": func(x bool, v ...string) (bool, string) {
			p := len(v)
			if p < 3 && p > 5 {
				return false, S_["Z"] + " en R"
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

			if _, e := W[v[2]]; !e {
				return false, "Configuración indefinida"
			}

			if v[0] != "0" {
				if W[v[2]]["W"] == true {
					return false, "Redirección a www activada"
				}
				W[v[2]]["R"] = true
				v[1] = ""
			} else {
				W[v[2]]["R"] = false
				v[1] = "des"
			}
			return true, "Redirección a raíz " + v[1] + "activada"
		},
		"W": func(x bool, v ...string) (bool, string) {
			p := len(v)
			if p < 3 && p > 5 {
				return false, S_["Z"] + " en W"
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

			if _, e := W[v[2]]; !e {
				return false, "Configuración indefinida"
			}

			if v[0] != "0" {
				if W[v[2]]["R"] == true {
					return false, "Redirección a raíz activada"
				}
				W[v[2]]["W"] = true
				v[1] = ""
			} else {
				W[v[2]]["W"] = false
				v[1] = "des"
			}
			return true, "Redirección a WWW " + v[1] + "activada"
		},
	}

	_R = map[string]func(*customNetHttp.Request, ...string) string{
		CD_: func(r *customNetHttp.Request, x ...string) string {
			return currentDir()
		},
		"WILDCARD_SITE": func(r *customNetHttp.Request, x ...string) string {
			if x[1] != "" {
				return x[1] + "." + x[0]
			}
			return x[0]
		},
		"WILDCARD_DOMAIN":    func(r *customNetHttp.Request, x ...string) string { return x[0] },
		"WILDCARD_SUBDOMAIN": func(r *customNetHttp.Request, x ...string) string { return x[1] },
		"DOMAIN":             func(r *customNetHttp.Request, x ...string) string { return x[2] },
		"SUBDOMAIN":          func(r *customNetHttp.Request, x ...string) string { return x[3] },
		"SITE": func(r *customNetHttp.Request, x ...string) string {
			if x[3] != "" {
				return x[3] + "." + x[2]
			}
			return x[2]
		},
		"FIRST_DOMAIN":    func(r *customNetHttp.Request, x ...string) string { return x[4] },
		"FIRST_SUBDOMAIN": func(r *customNetHttp.Request, x ...string) string { return x[5] },
		"FIRST_SITE": func(r *customNetHttp.Request, x ...string) string {
			if x[5] != "" {
				return x[5] + "." + x[4]
			}
			return x[4]
		},
		"FIRST_REQUEST": func(r *customNetHttp.Request, x ...string) string { return url.QueryEscape(r.RequestURI) },
		"FIRST_QUERY": func(r *customNetHttp.Request, x ...string) string {
			y := strings.IndexByte(r.RequestURI, '?')
			if y != -1 {
				return url.QueryEscape(r.RequestURI[y+1:])
			}
			return ""
		},
		"DIR": func(r *customNetHttp.Request, x ...string) string {
			z := dir(cutAt(r.RequestURI, '?'))
			if z == "/" {
				return ""
			}
			return url.QueryEscape(z)
		},
		"FILE": func(r *customNetHttp.Request, x ...string) string {
			z := cutAt(r.RequestURI, '?')
			if z[len(z)-1] != '/' {
				return url.QueryEscape(serverFuncBase(z))
			}
			return ""
		},
		"EXT":     func(r *customNetHttp.Request, x ...string) string { return ext(cutAt(r.RequestURI, '?')) },
		"REWRITE": func(r *customNetHttp.Request, x ...string) string { return url.QueryEscape(x[6]) },
		"REWRITE_COMPLEMENT": func(r *customNetHttp.Request, x ...string) string {
			z := len(x[6])
			if z < len(r.RequestURI) {
				return url.QueryEscape(r.RequestURI[z:])
			}
			return ""
		},
	}
)
