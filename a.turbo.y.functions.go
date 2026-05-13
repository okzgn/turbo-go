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
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
	"turbo/customNetHttp"
)

func isConn(b customNetHttp.ConnState) bool {
	if b == customNetHttp.StateNew || b == customNetHttp.StateActive || b == customNetHttp.StateIdle {
		return true
	}
	return false
}

func ipAddr(a string) string {
	if a[0] == '[' {
		return cutAt(a[1:], ']')
	}
	if strings.IndexByte(a, '.') != -1 {
		return cutAt(a, ':')
	}
	return a
}

func cutAt(a string, b byte) string {
	c := strings.IndexByte(a, b)
	if c != -1 {
		return a[:c]
	}
	return a
}

func cleanOldValues(i *map[string]int64) {
	c := time.Now().Unix()
	for a, b := range *i {
		if c > b {
			delete(*i, a)
		}
	}
}

func host(e string) (bool, string, string, string) {
	/*if e[0] == '[' {
		//e = cutAt(e[1:], ']')
		//e = strings.ReplaceAll(e, ":", "_")
		return true, "", "", e
	}*/
	e = cutAt(e, ':')
	if hostDisposition(e) {
		return false, "", "", ""
	}
	return hostExist(e)
}

func hostExist(e string) (bool, string, string, string) {
	a, b, c, d := detectWildcards(e, "")

	if !a {
		b, c, d, e = hostParts(e)
		if b != "" {
			b += "."
		}
		if d != "" {
			d += "."
		}
		//fmt.Println("UNKNOWN DOMAIN", b + c, d + e)
		return a, "", b + c, d + e
	}

	if c != "" { // c is filled when wildcard is detected
		//fmt.Println("WILDCARD", a, d, b, c)
		return a, d, b, c
	}
	//fmt.Println("DOMAIN", a, c, b, d)
	return a, c, b, d
}

func hostParts(a string) (string, string, string, string) {
	if a == "" {
		return "", "", "", ""
	}
	var b string
	var c string
	var d string
	var e string
	f := len(a) - 1
	if a[f] == '.' { // Dot chars on the right side causes an empty string on domain name
		for {
			a = a[:f]
			f -= 1
			if f < 0 || a[f] != '.' {
				break
			}
		}
	}
	for {
		f = strings.IndexByte(a, '.')
		if f == -1 {
			break
		}
		d = c
		c = b
		b = a[:f]
		a = a[f+1:]
		if b == "" {
			b = c
			c = d
			d = ""
			continue
		}
		if d != "" {
			if e != "" {
				e += "."
			}
			e += d
		}
	}
	return e, c, b, a
}

func hostDisposition(e string) bool {
	l := len(e)
	m := strings.LastIndexByte(e, '*')
	if l < 1 || l > 220 ||
		e[0] == '.' || e[l-1] == '.' ||
		e[0] == '-' || e[l-1] == '-' ||
		strings.Contains(e, "--") ||
		strings.Contains(e, "..") ||
		strings.Contains(e, ".-") ||
		strings.Contains(e, "-.") ||
		((m != -1) && l > 1 && ((m != 0) || (e[m+1] != '.'))) {
		return true
	}
	return false
}

func hostOk(e string, f bool) (bool, string) {
	if hostDisposition(e) {
		return false, "Dirección incorrecta"
	}
	if !hostChars(e) {
		return false, "Caracteres incorrectos"
	}
	if f {
		c, _, _, _ := hostExist(e)
		if c {
			return false, "Sitio existente"
		}
	}
	a, b, d, e := hostParts(e)
	k := len(e)
	if k > 31 {
		return false, "TLD incorrecto"
	}
	k = len(d)
	if k > 63 {
		return false, "Dominio incorrecto"
	} // Initially unsupported 1 digit domain names: (b != "" && k == 1) ||
	k = len(b)
	if k > 63 {
		return false, "Longitud excesiva"
	}
	k = len(a)
	if k > 63 {
		return false, "Longitud excesiva"
	}
	return true, ""
}

func hostChars(e string) bool {
	for k, _ := range e {
		if (e[k] < 97 || e[k] > 122) && (e[k] < 45 || e[k] > 46) && (e[k] < 48 || e[k] > 57) && e[k] != 42 {
			return false
		}
	}
	return true
}

func extChars(e string) bool {
	if e[0] == '.' {
		e = e[1:]
	}
	if e[0] == '-' || e[len(e)-1] == '.' || e[len(e)-1] == '-' || strings.Contains(e, "..") || strings.Contains(e, "--") {
		return false
	}
	for k, _ := range e {
		if (e[k] < 97 || e[k] > 122) && (e[k] < 45 || e[k] > 46) && (e[k] < 48 || e[k] > 57) && (e[k] < 65 || e[k] > 90) {
			return false
		}
	}
	return true
}

func headerChars(e string) bool {
	for k, _ := range e {
		if (e[k] < 97 || e[k] > 122) && (e[k] < 45 || e[k] > 46) && (e[k] < 48 || e[k] > 57) && (e[k] < 65 || e[k] > 90) {
			return false
		}
	}
	return true
}

func replaceURIChars(s string) string {
	for k, v := range B_ {
		s = strings.ReplaceAll(s, v, k)
	}
	return s
}
func changeWildcards(s ...string) string {
	r := "#"
	if len(s) == 2 {
		r = s[1]
	}
	return strings.ReplaceAll(s[0], "*", r)
}
func putWildcards(s ...string) string {
	r := "#"
	if len(s) == 2 {
		r = s[1]
	}
	return strings.ReplaceAll(s[0], r, "*")
}
func detectWildcards(a string, b string) (bool, string, string, string) {
	if a == "" && b == "" {
		return false, "", "", ""
	}
	var d string
	var e string
	for {
		c := strings.IndexByte(a, '.')
		if c == -1 {
			d = a
			break
		}
		d = a[:c]
		a = a[c+1:]

		if existWildcards(d+"."+a, b) {
			return true, e, "", d + "." + a
		}
		if existWildcards("*."+a, b) {
			return true, e, d + "." + a, "*." + a
		}
		if e != "" {
			e += "." + d
		} else {
			e += d
		}
	}

	if existWildcards(a, b) {
		return true, e, "", a
	}
	if existWildcards("*", b) {
		return true, e, d, "*"
	}
	return false, "", "", ""
}

func existWildcards(a string, b string) bool {
	if b != "" {
		if _, c := O[b][a]; c {
			return true
		}
		return false
	}
	if _, c := O[a]; c {
		return true
	}
	return false
}

func changeChars(j bool, s string, f []string) string {
	g := len(f)
	h := g / 2

	m := 1
	i := 0
	l := h
	n := h
	if !j {
		m = -1
		i = g - 1
		l = h - 1
		n = h * m
	}
	for {
		if i == l {
			break
		}
		s = strings.ReplaceAll(s, f[i], f[i+n])
		i += m
	}
	return s
}

func putSlash(s string) string {
	l := len(s)
	if l > 0 && s[l-1] != '/' {
		s += "/"
	}
	return s
}

func fileExists(p string) bool {
	m, i := os.Stat(p)
	if !os.IsNotExist(i) && !m.IsDir() {
		return true
	}
	return false
}

func currentDir() string {
	d, e := os.Getwd()
	if e != nil {
		return ""
	}
	return putSlash(d)
}

func reqMsg(w customNetHttp.ResponseWriter, r *customNetHttp.Request, s int) {
	customNetHttp.Error(w, "", s)
}

func badReq(w customNetHttp.ResponseWriter, r *customNetHttp.Request, m string) {
	w.WriteHeader(400)
	w.Write([]byte(m))
}

func ext(s string) string {
	s = path.Ext(s)
	if s == "." {
		s = ""
	}
	if s != "" {
		s = s[1:]
	}
	return s
}

func serverFuncBase(s string) string {
	s = path.Base(s)
	if s == "." || s == "/" {
		s = ""
	}
	return s
}

func dir(s string) string {
	s = path.Dir(s)
	if s == "." {
		s = "/"
	}
	return s
}

func siteExists(s string, d string) bool {
	var i bool
	if _, i = O[s]; !i {
		return false
	}
	if _, i = O[s][d]; !i {
		return false
	}
	return true
}

func deleteCertificate(l string) {
	var x bool
	if _, x = W[l]["S"]; !x {
		return
	}
	j := len(U.Certificates)
	if j > 1 {
		k := W[l]["S"].(int)
		if j != k {
			for a, _ := range W {
				if W[a]["S"] == j { // Assign the map key and value to deletion to the last one that will be removed instead
					U.Certificates[k-1] = U.Certificates[j-1]
					U.NameToCertificate[a] = &U.Certificates[k-1]
					W[a]["S"] = k
					break
				}
			}
		}
		U.Certificates = U.Certificates[:j-1]
		delete(U.NameToCertificate, l)
	} else {
		U.Certificates = []tls.Certificate{}
		U.NameToCertificate = nil
		// Don't close N[0] because need to restart createSafeServer(U)
	}
}

func obtainCertificate(s string, p string, z string) {
	if CC == "" {
		CC = s

		go func() {
			x, c := context.WithTimeout(context.Background(), 3*time.Minute)
			defer c()

			//j := exec.CommandContext(x, "C://timeWaitExample.exe") // Windows tests

			if _, b := W[s]; !b { // If site is deleted
				CC = ""
				fmt.Println("Certificate intent truncated from deleted site \"" + s + "\"")
				return
			}

			j := exec.CommandContext(x, "certbot", "--version")
			_, g := j.CombinedOutput()

			if g != nil {
				CC = ""
				W[s]["C"] = "Certbot no está instalado"
				return
			}

			_, g = os.ReadDir(p)
			if g == nil {
				if os.RemoveAll(p) != nil {
					CC = ""
					W[s]["C"] = "Error al vaciar directorio de certificado anterior"
					return
				}
			}

			/*j := exec.CommandContext(x,
			"sudo", // This causes issues on other types of Linux, like Alpine
			"certbot",
			"certonly",
			"-d", s,
			"--dns-route53",
			"-n", // Not interactive
			"--agree-tos",
			"-m", S["X"], // Email for expiring notifications
			//"--test-cert",
			"--no-eff-email", // --eff-email to acept share email with EFF
			//"--force-renewal", "--break-my-certs", // Both needed for --test-cert
			"--config-dir", p)*/

			if W[s]["A"] != "" {
				j = exec.CommandContext(x, // For incompatibility with wildcards or --dns-route53
					"certbot",
					"certonly",
					"-d", s,
					"--"+W[s]["A"].(string),
					"-n", // Not interactive
					"--agree-tos",
					"-m", W[s]["E"].(string), // Email for expiring notifications
					// "--test-cert",
					"--no-eff-email", // --eff-email
					// "--force-renewal", "--break-my-certs", // Both needed for --test-cert
					"--config-dir", p)
			} else {
				j = exec.CommandContext(x, // For incompatibility with wildcards or --dns-route53
					"certbot",
					"certonly",
					"-d", s,
					"--webroot",
					"--webroot-path", z+S_["F"],
					"-n", // Not interactive
					"--agree-tos",
					"-m", W[s]["E"].(string), // Email for expiring notifications
					// "--test-cert",
					"--no-eff-email", // --eff-email
					// "--force-renewal", "--break-my-certs", // Both needed for --test-cert
					"--config-dir", p)
			}

			r, g := j.CombinedOutput()
			CC = ""

			if g != nil {
				W[s]["C"] = string(r)
				return
			}

			p += "/archive/"

			d, g := os.ReadDir(p)
			if g != nil {
				W[s]["C"] = "Directorio de certificado ilegible al obtenerlo"
				return
			}

			var _C string
			var _K string
			t := time.Now().Unix()
			for _, f := range d {
				n := p + f.Name() + "/"
				h, g := os.ReadDir(n)
				if g != nil {
					continue
				}
				for _, f = range h {
					m := f.Name()
					w, g := os.Stat(n + m)
					if g != nil {
						continue
					}
					if len(m) > 10 && t-w.ModTime().Unix() < 216000 {
						switch m[:4] {
						case "full":
							_C = n + m
						case "priv":
							_K = n + m
						}
					}
				}
				break // Because is only one dir
			}

			if _C == "" || _K == "" {
				W[s]["C"] = "Archivos de certificado inexistentes al obtenerlo"
				return
			}

			i := os.Rename(_C, z+S_["C"])
			if i != nil {
				W[s]["C"] = "'Fullchain' inmovible al obtenerlo"
				return
			}

			i = os.Rename(_K, z+S_["K"])
			if i != nil {
				W[s]["C"] = "'Privkey' inmovible al obtenerlo"
				return
			}

			W[s]["C"] = true
			fmt.Println("SSL cert: " + s)
			CC = ""
		}()
		return
	}

	if CC == s {
		return
	} // To prevent new certificate attempts from the same site

	CD += 100
	time.AfterFunc(CD*time.Millisecond, func() { obtainCertificate(s, p, z) })
}
