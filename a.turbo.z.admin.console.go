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
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"turbo/customNetHttp"
)

func console(w customNetHttp.ResponseWriter, r *customNetHttp.Request) bool {
	l := len(S_["B"]) + 2
	if len(r.RequestURI) < l || r.RequestURI[:l] != "/"+S_["B"]+":" {
		return false
	}

	s := "?" + S_["M"]
	q := strings.Index(r.RequestURI, s)
	if q != -1 {
		s = cutAt(r.RequestURI[q+len(s):], '&')
	} else {
		s = ""
	}

	r.RequestURI = cutAt(r.RequestURI[l:], '?')

	if consoleActions(r.RequestURI, s, w, r) {
		return true
	}
	if r.RequestURI == "" {
		r.RequestURI = S_["J"]
	}
	//fmt.Println("CONSOLE REQUEST", r.RequestURI)
	consoleFiles(S_["B"], r.RequestURI, w, r)
	return true
}

func consoleFiles(x string, a string, w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
	// Turbo Dev
	p := S_["A"] + putSlash(S_["Y"])

	if d, err := os.Stat(p); err == nil {
		if !d.IsDir() {
			customNetHttp.Error(w, "\nDev Error:\n"+p+" isn't dir.", 500)
			return
		}

		p += putSlash(x) + filepath.Clean(a)
		if _, err = os.Stat(p); err != nil {
			customNetHttp.Error(w, "\nDev Error:\n"+err.Error(), 500)
			return
		}
		customNetHttp.ServeFile(w, r, p)
		return
	}
	// Turbo Dev end

	var b bool
	if _, b = _AB[x][a]; b { // Look first on binaries
		customNetHttp.ServeContent(w, r, a, time.Time{}, bytes.NewReader(_AB[x][a]))
		return
	}

	if _, b = _AF[x][a]; b { // Look then on strings
		customNetHttp.ServeContent(w, r, a, time.Time{}, bytes.NewReader([]byte(_AF[x][a])))
		return
	}

	reqMsg(w, r, 404)
}

func consoleActions(q string, token string, w customNetHttp.ResponseWriter, r *customNetHttp.Request) bool {
	c := strings.IndexByte(q, ':')
	if c != -1 {
		r.RequestURI = r.RequestURI[c+1:]
		q = q[:c]
	}
	if r.RequestURI == "" {
		r.RequestURI = S_["J"]
	}

	cleanOldValues(&I)

	_t := token
	t := r.Header.Get(S_["M"])
	if t != "" {
		token = t
	}

	i := ipAddr(r.RemoteAddr)

	L.RLock()
	_, a := I[i+token]
	L.RUnlock()

	w.Header().Set("Access-Control-Allow-Origin", "default://home")
	w.Header().Set("Access-Control-Allow-Headers", "ok") // This is to accept ok header from default://home

	switch q {
	case "signout":
		L.Lock()
		if !a && _t == t {
			for k := range I {
				if len(k) > len(i) && k[:len(i)] == i {
					delete(I, k)
				}
			}
		} else {
			delete(I, i+token)
		}
		L.Unlock()

		consoleHtmlRedir("/"+S_["B"]+":", w, r)
		return true

	case S_["H"]:
		/*if len(I) != 0 && !a { // Only for logging from one IP at time
			w.Write([]byte("<p data-err>Inautorizado</p>"))
			return true
		}*/

		if a {
			L.Lock()
			I[i+token] = time.Now().Unix() + 600
			L.Unlock()

			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

			if consoleActionsApi(r.RequestURI, w, r) {
				return true
			}

			consoleFiles(S_["H"], r.RequestURI, w, r)
			return true
		}
		consoleHtmlRedir("/"+S_["B"]+":", w, r)
		return true
	default:
		r.ParseMultipartForm(1024)
		_, a := r.Form["u"]
		_, b := r.Form["p"]
		if a && b {
			if r.Form["u"][0] == S_["U"] && r.Form["p"][0] == S_["P"] {
				t := time.Now().Unix()
				hash := sha256.New()
				hash.Write([]byte(S_["M"] + S_["U"] + S_["P"] + strconv.FormatInt(t, 10)))
				token := hex.EncodeToString(hash.Sum(nil))

				L.Lock()
				I[i+token] = t + 600
				L.Unlock()
				w.Write([]byte(S_["M"] + token))
			} else {
				w.WriteHeader(403)
			}
			return true
		}
	}
	return false
}

func consoleHtmlRedir(g string, w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
	w.Header().Set(S_["D"], "text/html; charset=UTF-8")
	w.Write([]byte("<meta http-equiv='refresh' content='0; URL=" + g + "'/>"))
}

func consoleActionsApi(q string, w customNetHttp.ResponseWriter, r *customNetHttp.Request) bool {
	if r.Method != customNetHttp.MethodPost {
		return false
	}

	if len(q) < 4 {
		return false
	}
	switch q[:3] {
	case "set":
		q = q[3:]
		if _, i := M["."][q]; i {
			r.ParseForm()
			if _, i = r.Form["a"]; i {
				var j []string
				j = append(j, replaceURIChars(r.Form["a"][0]))
				j = append(j, S_["P"]) // Password auto set for common settings
				if _, i = _AP[q]; i {  // _AP: list of settings that need password input
					j[1] = ""
				}
				if _, i = r.Form["b"]; i {
					j[1] = replaceURIChars(r.Form["b"][0])
				}

				var k string
				L.Lock()
				i, k = M["."][q](j...)
				L.Unlock()
				if !i {
					badReq(w, r, k)
				} else {
					if _, i = _A[q]; i { // _A: List of settings that use restartServers
						w.Write([]byte(k))
						//time.AfterFunc(50*time.Millisecond, func() {
						resetSettings()
						updateSettings(true)
						//})
					} else {
						w.Write([]byte(k))
					}
				}
			} else {
				badReq(w, r, S_["Z"])
			}
			return true
		}
		return false

	case "add":
		q = q[3:]
		switch q {
		case "Rewrite", "MIME", "Header", "Preprocessor":
			r.ParseForm()
			_, h := r.Form["s"]
			_, i := r.Form["d"]
			_, j := r.Form["a"]
			_, k := r.Form["b"]
			if h && i && j && k {
				m := "="
				c := make(map[string]interface{})
				c[r.Form["a"][0]] = r.Form["b"][0]
				if q[0] == 'M' {
					m = "$"
				} else if q[0] == 'H' {
					m = "."
				} else if q[0] == 'P' {
					m = "?"
				}
				L.Lock()
				k, m = C[m](true, c, false, r.Form["s"][0], r.Form["d"][0])
				L.Unlock()
				if !k {
					badReq(w, r, m)
				} else {
					w.Write([]byte(m))
				}
			} else {
				badReq(w, r, S_["Z"])
			}
			return true

		case "Index", "Alias":
			r.ParseForm()
			_, h := r.Form["d"]
			_, i := r.Form["s"]
			_, j := r.Form["a"]
			if h && i && j {
				k := make(map[string]interface{})
				k[r.Form["a"][0]] = false
				m := "-"
				if q[0] == 'A' {
					m = "&"
				}
				L.Lock()
				h, m = C[m](true, k, false, r.Form["s"][0], r.Form["d"][0])
				L.Unlock()
				if !h {
					badReq(w, r, m)
				} else {
					w.Write([]byte(m))
				}
			} else {
				badReq(w, r, S_["Z"])
			}
			return true

		case "Subdomain":
			r.ParseForm()
			_, i := r.Form["s"]
			_, j := r.Form["d"]
			if i && j {
				if _, i = O[r.Form["s"][0]]; i {
					k, m := hostOk(r.Form["d"][0]+"."+changeWildcards(r.Form["s"][0], "x"), false) // Because wildcard is only accepted on begining
					if k {
						L.RLock()
						_e := siteExists(r.Form["s"][0], r.Form["d"][0])
						L.RUnlock()
						if _e {
							badReq(w, r, "Subdominio existente")
							return true
						}

						/* Domains map keys coincidence detection */
						i, _, _, m = detectWildcards(r.Form["d"][0]+"."+r.Form["s"][0], "")
						if i && m != r.Form["s"][0] {
							badReq(w, r, "Coincidencia con sitio: "+m)
							return true
						}

						m = S_["A"] + changeWildcards(r.Form["s"][0]) + "/" + changeWildcards(r.Form["d"][0]) + "/" + S_["F"] + "/"
						if os.MkdirAll(m, 0755) != nil {
							badReq(w, r, "Error al crear")
							return true
						}
						constructSite(r.Form["s"][0], r.Form["d"][0])
						w.Write([]byte("Subdominio agregado"))
					} else {
						badReq(w, r, m)
					}
				} else {
					badReq(w, r, "Sitio inexistente")
				}
			} else {
				badReq(w, r, S_["Z"])
			}
			return true

		case "Site":
			r.ParseForm()
			_, i := r.Form["s"]
			if i {
				L.RLock()
				_e := siteExists(r.Form["s"][0], "")
				L.RUnlock()
				if _e {
					badReq(w, r, "Sitio existente.")
					return true
				}
				var m string
				if i, m = hostOk(r.Form["s"][0], false); !i {
					badReq(w, r, m)
					return true
				}

				/* Subdomains map keys coincidence detection */
				var g string
				i, g, _, m = detectWildcards(r.Form["s"][0], "")
				if i {
					i, _, _, g = detectWildcards(g, m)
					if i {
						badReq(w, r, "Coincidencia con sitio: "+g+"."+m)
						return true
					}
				}

				m = S_["A"] + changeWildcards(r.Form["s"][0]) + "/" + S_["F"] + "/"
				if os.MkdirAll(m, 0755) != nil {
					badReq(w, r, "Error al crear")
					return true
				}
				constructSite(r.Form["s"][0], "")
				w.Write([]byte("Sitio agregado"))
				return true
			} else {
				badReq(w, r, S_["Z"])
			}
			return true

		case "Denied", "HttpCodeResponse", "CharsReplace":
			r.ParseForm()
			_, i := r.Form["s"]
			_, j := r.Form["d"]
			if i && j {
				k := "#"
				switch q[0] {
				case 'C':
					k = "_"
				case 'D':
					k = "@"
				}

				L.Lock()
				i, k = _MX[k](r.Form["s"][0], r.Form["d"][0])
				L.Unlock()

				if !i {
					badReq(w, r, k)
					return true
				}
				w.Write([]byte(k))
				return true
			} else {
				badReq(w, r, S_["Z"])
			}
			return true
		}
		return false

	case "del":
		q = q[3:]
		switch q {
		case "Index", "Alias", "Preprocessor", "Header", "MIME", "Rewrite":
			r.ParseForm()
			_, h := r.Form["d"]
			_, i := r.Form["s"]
			_, j := r.Form["a"]
			if h && i && j {
				k := make(map[string]interface{})
				k[r.Form["a"][0]] = false
				m := "="
				if q[0] == 'A' {
					m = "&"
				} else if q[0] == 'I' {
					m = "-"
				} else if q[0] == 'P' {
					m = "?"
				} else if q[0] == 'H' {
					m = "."
				} else if q[0] == 'M' {
					m = "$"
				}

				L.Lock()
				h, m = K[m](true, k, r.Form["s"][0], r.Form["d"][0])
				L.Unlock()

				if !h {
					badReq(w, r, m)
				} else {
					w.Write([]byte(m))
				}
			}
			return true

		case "Site":
			r.ParseForm()
			_, i := r.Form["s"]
			_, j := r.Form["d"]
			if i && j {
				m := "Sitio"
				i = r.Form["d"][0] != ""
				if i {
					m = "Subdominio"
				}

				L.RLock()
				_e := siteExists(r.Form["s"][0], r.Form["d"][0])
				L.RUnlock()

				if !_e {
					badReq(w, r, m+" inexistente")
					return true
				}

				s := S_["A"] + changeWildcards(r.Form["s"][0])
				if i {
					s += "/" + changeWildcards(r.Form["d"][0])
				}
				s += "/"
				if os.RemoveAll(s) != nil {
					badReq(w, r, "Error al borrar")
					return true
				}

				deleteSite(r.Form["s"][0], r.Form["d"][0])
				w.Write([]byte(m + " borrado"))
			} else {
				badReq(w, r, S_["Z"])
			}
			return true

		case "Denied", "HttpCodeResponse", "CharsReplace":
			r.ParseForm()
			_, i := r.Form["s"]
			if i {
				k := "#"
				switch q[0] {
				case 'C':
					k = "_"
				case 'D':
					k = "@"
				}

				L.Lock()
				i, k = _MD[k](r.Form["s"][0])
				L.Unlock()

				if !i {
					badReq(w, r, k)
					return true
				}
				w.Write([]byte(k))
				return true
			} else {
				badReq(w, r, S_["Z"])
			}
			return true
		}
		return false

	case "cfg":
		q = q[3:]
		if _, i := _B[q]; i {
			r.ParseForm()
			_, i = r.Form["a"]
			_, j := r.Form["s"]
			_, k := r.Form["d"]
			_, l := r.Form["z"]
			_, m := r.Form["y"]
			z := ""
			y := ""
			if l {
				z = r.Form["z"][0]
			}
			if m {
				y = r.Form["y"][0]
			}
			if i && j && k {
				L.Lock()
				j, q = _B[q](false, r.Form["a"][0], r.Form["s"][0], r.Form["d"][0], z, y)
				L.Unlock()

				if !j {
					badReq(w, r, q)
					return true
				}
				w.Write([]byte(q))
			} else {
				badReq(w, r, S_["Z"])
			}
			return true
		}
		return false

	default:
		switch q {
		case "hardUpload":
			r.ParseForm()
			_, i := r.Form["s"]
			_, j := r.Form["d"]
			if i && j {
				L.RLock()
				_e := siteExists(r.Form["s"][0], r.Form["d"][0])
				L.RUnlock()

				if !_e {
					if r.Form["d"][0] != "" {
						badReq(w, r, "Subdominio inexistente")
					} else {
						badReq(w, r, "Sitio inexistente")
					}
					return true
				}

				e := r.ParseMultipartForm(L_)
				if e != nil {
					badReq(w, r, "Longitud máxima de contenidos excedida")
					return true
				}
				if _, i = r.MultipartForm.File["f"]; !i {
					badReq(w, r, "No hay datos")
					r.MultipartForm.RemoveAll()
					return true
				}

				L.RLock()
				r.Form["s"][0] = S_["A"] + changeWildcards(r.Form["s"][0])
				if r.Form["d"][0] != "" {
					r.Form["s"][0] += "/" + changeWildcards(r.Form["d"][0])
				}
				r.Form["s"][0] += "/" + S_["F"] + "/"
				L.RUnlock()

				g, e := os.ReadDir(r.Form["s"][0])
				if e != nil {
					badReq(w, r, "Directorio inaccesible")
					return true
				}

				for _, f := range g {
					os.Remove(r.Form["s"][0] + f.Name())
				}

				for _, k := range r.MultipartForm.File["f"] {
					_, n, e := mime.ParseMediaType(k.Header["Content-Disposition"][0]) // Maybe exists a concise function for this
					if e != nil {
						continue
					}
					m := strings.IndexByte(n["filename"], '/')
					if m != -1 {
						n["filename"] = n["filename"][m+1:]
					}
					m = strings.LastIndexByte(n["filename"], '/')
					if m != -1 {
						n["filename"] = n["filename"][:m+1]
						if strings.Contains(n["filename"], "..") || os.MkdirAll(r.Form["s"][0]+n["filename"], 0755) != nil {
							continue
						}
					} else {
						n["filename"] = ""
					}

					o, e := k.Open()
					if e != nil {
						continue
					}

					p, e := os.OpenFile(r.Form["s"][0]+n["filename"]+filepath.Base(k.Filename), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
					if e != nil {
						continue
					}

					io.Copy(p, o)
					o.Close()
					p.Close()
				}
				r.MultipartForm.RemoveAll()
				w.Write([]byte("Datos volcados"))
			} else {
				badReq(w, r, "Faltan fatos")
			}
			return true

		case "sites":
			L.RLock()
			w.Write([]byte(createDefaultConfig(false, true)))
			L.RUnlock()
			return true

		case "subdomains":

			r.ParseForm()
			_, j := r.Form["s"]
			if j {
				L.RLock()
				_e := siteExists(r.Form["s"][0], "")
				L.RUnlock()

				if !_e {
					badReq(w, r, "Sitio inexistente")
					return true
				}

				L.RLock()
				w.Write([]byte(createSubdomainsList(false, r.Form["s"][0])))
				L.RUnlock()
			} else {
				badReq(w, r, S_["Z"])
			}
			return true

		case "subdomainData":
			r.ParseForm()
			_, i := r.Form["s"]
			_, j := r.Form["d"]
			if i && j {
				L.RLock()
				_e := siteExists(r.Form["s"][0], r.Form["d"][0])
				L.RUnlock()

				if !_e {
					badReq(w, r, "Subdominio inexistente")
					return true
				}

				L.RLock()
				w.Write([]byte(createSubdomainData(r.Form["s"][0], r.Form["d"][0])))
				L.RUnlock()
			} else {
				badReq(w, r, S_["Z"])
			}
			return true
		}
	}
	return false
}
