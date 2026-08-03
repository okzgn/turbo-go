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

func console(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) bool {
	prefixLen := len(stringStore["B"]) + 2
	if len(request.RequestURI) < prefixLen || request.RequestURI[:prefixLen] != "/"+stringStore["B"]+":" {
		return false
	}

	queryToken := "?" + stringStore["M"]
	queryIdx := strings.Index(request.RequestURI, queryToken)
	if queryIdx != -1 {
		queryToken = cutAt(request.RequestURI[queryIdx+len(queryToken):], '&')
	} else {
		queryToken = ""
	}

	request.RequestURI = cutAt(request.RequestURI[prefixLen:], '?')

	if consoleActions(request.RequestURI, queryToken, responseWriter, request) {
		return true
	}
	if request.RequestURI == "" {
		request.RequestURI = stringStore["J"]
	}
	//fmt.Println("CONSOLE REQUEST", r.RequestURI)
	consoleFiles(stringStore["B"], request.RequestURI, responseWriter, request)
	return true
}

func consoleFiles(panelName string, requestPath string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	// Turbo Dev
	p := stringStore["A"] + putSlash(stringStore["Y"])

	if d, err := os.Stat(p); err == nil {
		if !d.IsDir() {
		customNetHttp.Error(responseWriter, "\nDev Error:\n"+p+" isn't dir.", 500)
			return
		}

		p += putSlash(panelName) + filepath.Clean(requestPath)
		if _, err = os.Stat(p); err != nil {
			customNetHttp.Error(responseWriter, "\nDev Error:\n"+err.Error(), 500)
			return
		}
		customNetHttp.ServeFile(responseWriter, request, p)
		return
	}
	// Turbo Dev end

	var b bool
	if _, b = embeddedBinaryFiles[panelName][requestPath]; b { // Look first on binaries
		customNetHttp.ServeContent(responseWriter, request, requestPath, time.Time{}, bytes.NewReader(embeddedBinaryFiles[panelName][requestPath]))
		return
	}

	if _, b = embeddedTextFiles[panelName][requestPath]; b { // Look then on strings
		customNetHttp.ServeContent(responseWriter, request, requestPath, time.Time{}, bytes.NewReader([]byte(embeddedTextFiles[panelName][requestPath])))
		return
	}

	reqMsg(responseWriter, request, 404)
}

func consoleActions(actionPath string, sessionToken string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) bool {
	colonIdx := strings.IndexByte(actionPath, ':')
	if colonIdx != -1 {
		request.RequestURI = request.RequestURI[colonIdx+1:]
		actionPath = actionPath[:colonIdx]
	}
	if request.RequestURI == "" {
		request.RequestURI = stringStore["J"]
	}

	cleanOldValues(&signedInTokens)

	urlToken := sessionToken
	headerToken := request.Header.Get(stringStore["M"])
	if headerToken != "" {
		sessionToken = headerToken
	}

	clientIP := ipAddr(request.RemoteAddr)

	globalMutex.RLock()
	_, isSessionValid := signedInTokens[clientIP+sessionToken]
	globalMutex.RUnlock()

	responseWriter.Header().Set("Access-Control-Allow-Origin", "default://home")
	responseWriter.Header().Set("Access-Control-Allow-Headers", "ok") // This is to accept ok header from default://home

	switch actionPath {
	case "signout":
		globalMutex.Lock()
		if !isSessionValid && urlToken == headerToken {
			for k := range signedInTokens {
				if len(k) > len(clientIP) && k[:len(clientIP)] == clientIP {
					delete(signedInTokens, k)
				}
			}
		} else {
			delete(signedInTokens, clientIP+sessionToken)
		}
		globalMutex.Unlock()

		consoleHtmlRedir("/"+stringStore["B"]+":", responseWriter, request)
		return true

	case stringStore["H"]:
		/*if len(I) != 0 && !a { // Only for logging from one IP at time
			w.Write([]byte("<p data-err>Inautorizado</p>"))
			return true
		}*/

		if isSessionValid {
			globalMutex.Lock()
			 signedInTokens[clientIP+sessionToken] = time.Now().Unix() + 600
			globalMutex.Unlock()

			responseWriter.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

			if consoleActionsApi(request.RequestURI, responseWriter, request) {
				return true
			}

			consoleFiles(stringStore["H"], request.RequestURI, responseWriter, request)
			return true
		}
		consoleHtmlRedir("/"+stringStore["B"]+":", responseWriter, request)
		return true
	default:
		request.ParseMultipartForm(1024)
			_, isSessionValid := request.Form["u"]
		_, b := request.Form["p"]
			if isSessionValid && b {
			if request.Form["u"][0] == stringStore["U"] && request.Form["p"][0] == stringStore["P"] {
				t := time.Now().Unix()
			sha256Hasher := sha256.New()
			sha256Hasher.Write([]byte(stringStore["M"] + stringStore["U"] + stringStore["P"] + strconv.FormatInt(t, 10)))
				token := hex.EncodeToString(sha256Hasher.Sum(nil))

				globalMutex.Lock()
				signedInTokens[clientIP+token] = t + 600
				globalMutex.Unlock()
				responseWriter.Write([]byte(stringStore["M"] + token))
			} else {
				responseWriter.WriteHeader(403)
			}
			return true
		}
	}
	return false
}

func consoleHtmlRedir(redirectURL string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	responseWriter.Header().Set(stringStore["D"], "text/html; charset=UTF-8")
	responseWriter.Write([]byte("<meta http-equiv='refresh' content='0; URL=" + redirectURL + "'/>"))
}

func consoleActionsApi(apiPath string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) bool {
	w := responseWriter
	r := request
	if request.Method != customNetHttp.MethodPost {
		return false
	}

	if len(apiPath) < 4 {
		return false
	}
	switch apiPath[:3] {
	case "set":
		apiPath = apiPath[3:]
			if _, handlerExists := defaultSettingValidators["."][apiPath]; handlerExists {
				r.ParseForm()
				if _, paramExists := r.Form["a"]; paramExists {
					var argumentList []string
					argumentList = append(argumentList, replaceURIChars(r.Form["a"][0]))
					argumentList = append(argumentList, stringStore["P"]) // Password auto set for common settings
				if _, paramExists = passwordInputRequiredSettings[apiPath]; paramExists {  // passwordInputRequiredSettings: list of settings that need password input
						argumentList[1] = ""
					}
				if _, paramExists = r.Form["b"]; paramExists {
					argumentList[1] = replaceURIChars(r.Form["b"][0])
				}

				var resultMsg string
				globalMutex.Lock()
				resultBool, resultMsg := defaultSettingValidators["."][apiPath](argumentList...)
				globalMutex.Unlock()
				if !resultBool {
					badReq(w, r, resultMsg)
				} else {
				if _, handlerExists = serverRestartRequiredSettings[apiPath]; handlerExists { // serverRestartRequiredSettings: List of settings that use restartServers
						w.Write([]byte(resultMsg))
						//time.AfterFunc(50*time.Millisecond, func() {
						resetSettings()
						updateSettings(true)
						//})
					} else {
						w.Write([]byte(resultMsg))
					}
				}
			} else {
				badReq(w, r, stringStore["Z"])
			}
			return true
		}
		return false

	case "add":
		apiPath = apiPath[3:]
		switch apiPath {
		case "Rewrite", "MIME", "Header", "Preprocessor":
			r.ParseForm()
			_, sourceParamExists := r.Form["s"]
			_, destinationParamExists := r.Form["d"]
			_, argumentParamExists := r.Form["a"]
			_, valueParamExists := r.Form["b"]
			if sourceParamExists && destinationParamExists && argumentParamExists && valueParamExists {
				resultMsg := "="
				c := make(map[string]interface{})
				c[r.Form["a"][0]] = r.Form["b"][0]
				if apiPath[0] == 'M' {
					resultMsg = "$"
				} else if apiPath[0] == 'H' {
					resultMsg = "."
				} else if apiPath[0] == 'P' {
					resultMsg = "?"
				}
				globalMutex.Lock()
				resultBool, resultMsg := subdomainContentCheckers[resultMsg](true, c, false, r.Form["s"][0], r.Form["d"][0])
				globalMutex.Unlock()
				if !resultBool {
					badReq(w, r, resultMsg)
				} else {
					w.Write([]byte(resultMsg))
				}
			} else {
				badReq(w, r, stringStore["Z"])
			}
			return true

		case "Index", "Alias":
			r.ParseForm()
			_, destinationParamExists := r.Form["d"]
			_, sourceParamExists := r.Form["s"]
			_, argumentParamExists := r.Form["a"]
			if destinationParamExists && sourceParamExists && argumentParamExists {
				argumentValues := make(map[string]interface{})
				argumentValues[r.Form["a"][0]] = false
				resultMsg := "-"
				if apiPath[0] == 'A' {
					resultMsg = "&"
				}
				globalMutex.Lock()
				resultBool, resultMsg := subdomainContentCheckers[resultMsg](true, argumentValues, false, r.Form["s"][0], r.Form["d"][0])
				globalMutex.Unlock()
				if !resultBool {
					badReq(w, r, resultMsg)
				} else {
					w.Write([]byte(resultMsg))
				}
			} else {
				badReq(w, r, stringStore["Z"])
			}
			return true

		case "Subdomain":
			r.ParseForm()
			_, sourceParamExists := r.Form["s"]
			_, destinationParamExists := r.Form["d"]
			if sourceParamExists && destinationParamExists {
				if _, handlerExists := sitesMap[r.Form["s"][0]]; handlerExists {
					resultBool, resultMsg := hostOk(r.Form["d"][0]+"."+changeWildcards(r.Form["s"][0], "x"), false) // Because wildcard is only accepted on begining
					if resultBool {
						globalMutex.RLock()
						_e := siteExists(r.Form["s"][0], r.Form["d"][0])
						globalMutex.RUnlock()
						if _e {
							badReq(w, r, "Subdominio existente")
							return true
						}

						/* Domains map keys coincidence detection */
						resultBool, _, _, resultMsg = detectWildcards(r.Form["d"][0]+"."+r.Form["s"][0], "")
						if resultBool && resultMsg != r.Form["s"][0] {
							badReq(w, r, "Coincidencia con sitio: "+resultMsg)
							return true
						}

						resultMsg = stringStore["A"] + changeWildcards(r.Form["s"][0]) + "/" + changeWildcards(r.Form["d"][0]) + "/" + stringStore["F"] + "/"
						if os.MkdirAll(resultMsg, 0755) != nil {
							badReq(w, r, "Error al crear")
							return true
						}
						constructSite(r.Form["s"][0], r.Form["d"][0])
						w.Write([]byte("Subdominio agregado"))
					} else {
						badReq(w, r, resultMsg)
					}
				} else {
					badReq(w, r, "Sitio inexistente")
				}
			} else {
				badReq(w, r, stringStore["Z"])
			}
			return true

		case "Site":
			r.ParseForm()
			_, sourceParamExists := r.Form["s"]
			if sourceParamExists {
				globalMutex.RLock()
				_e := siteExists(r.Form["s"][0], "")
				globalMutex.RUnlock()
				if _e {
					badReq(w, r, "Sitio existente.")
					return true
				}
				var resultBool bool
				var resultMsg string
				if resultBool, resultMsg = hostOk(r.Form["s"][0], false); !resultBool {
					badReq(w, r, resultMsg)
					return true
				}

				/* Subdomains map keys coincidence detection */
				var matchedSite string
				resultBool, matchedSite, _, resultMsg = detectWildcards(r.Form["s"][0], "")
				if resultBool {
					resultBool, _, _, matchedSite = detectWildcards(matchedSite, resultMsg)
					if resultBool {
						badReq(w, r, "Coincidencia con sitio: "+matchedSite+"."+resultMsg)
						return true
					}
				}

				resultMsg = stringStore["A"] + changeWildcards(r.Form["s"][0]) + "/" + stringStore["F"] + "/"
				if os.MkdirAll(resultMsg, 0755) != nil {
					badReq(w, r, "Error al crear")
					return true
				}
				constructSite(r.Form["s"][0], "")
				w.Write([]byte("Sitio agregado"))
				return true
			} else {
				badReq(w, r, stringStore["Z"])
			}
			return true

		case "Denied", "HttpCodeResponse", "CharsReplace":
			r.ParseForm()
			_, sourceParamExists := r.Form["s"]
			_, destinationParamExists := r.Form["d"]
			if sourceParamExists && destinationParamExists {
				resultMsg := "#"
				switch apiPath[0] {
				case 'C':
					resultMsg = "_"
				case 'D':
					resultMsg = "@"
				}

				globalMutex.Lock()
				resultBool, resultMsg := adminAddHandlers[resultMsg](r.Form["s"][0], r.Form["d"][0])
				globalMutex.Unlock()

				if !resultBool {
					badReq(w, r, resultMsg)
					return true
				}
				w.Write([]byte(resultMsg))
				return true
			} else {
				badReq(w, r, stringStore["Z"])
			}
			return true
		}
		return false

		case "del":
		apiPath = apiPath[3:]
		switch apiPath {
		case "Index", "Alias", "Preprocessor", "Header", "MIME", "Rewrite":
			r.ParseForm()
			_, destinationParamExists := r.Form["d"]
			_, sourceParamExists := r.Form["s"]
			_, argumentParamExists := r.Form["a"]
			if destinationParamExists && sourceParamExists && argumentParamExists {
				argumentValues := make(map[string]interface{})
				argumentValues[r.Form["a"][0]] = false
				resultMsg := "="
				if apiPath[0] == 'A' {
					resultMsg = "&"
				} else if apiPath[0] == 'I' {
					resultMsg = "-"
				} else if apiPath[0] == 'P' {
					resultMsg = "?"
				} else if apiPath[0] == 'H' {
					resultMsg = "."
				} else if apiPath[0] == 'M' {
					resultMsg = "$"
				}

				globalMutex.Lock()
				resultBool, resultMsg := subdomainContentDeleters[resultMsg](true, argumentValues, r.Form["s"][0], r.Form["d"][0])
				globalMutex.Unlock()

				if !resultBool {
					badReq(w, r, resultMsg)
				} else {
					w.Write([]byte(resultMsg))
				}
			}
			return true

		case "Site":
			r.ParseForm()
			_, sourceParamExists := r.Form["s"]
			_, destinationParamExists := r.Form["d"]
			if sourceParamExists && destinationParamExists {
				resultMsg := "Sitio"
				resultBool := r.Form["d"][0] != ""
				if resultBool {
					resultMsg = "Subdominio"
				}

				globalMutex.RLock()
				_e := siteExists(r.Form["s"][0], r.Form["d"][0])
				globalMutex.RUnlock()

				if !_e {
					badReq(w, r, resultMsg+" inexistente")
					return true
				}

				s := stringStore["A"] + changeWildcards(r.Form["s"][0])
				if resultBool {
					s += "/" + changeWildcards(r.Form["d"][0])
				}
				s += "/"
				if os.RemoveAll(s) != nil {
					badReq(w, r, "Error al borrar")
					return true
				}

				deleteSite(r.Form["s"][0], r.Form["d"][0])
				w.Write([]byte(resultMsg + " borrado"))
			} else {
				badReq(w, r, stringStore["Z"])
			}
			return true

		case "Denied", "HttpCodeResponse", "CharsReplace":
			r.ParseForm()
			_, sourceParamExists := r.Form["s"]
			if sourceParamExists {
				resultMsg := "#"
				switch apiPath[0] {
				case 'C':
					resultMsg = "_"
				case 'D':
					resultMsg = "@"
				}

				globalMutex.Lock()
				resultBool, resultMsg := adminDeleteHandlers[resultMsg](r.Form["s"][0])
				globalMutex.Unlock()

				if !resultBool {
					badReq(w, r, resultMsg)
					return true
				}
				w.Write([]byte(resultMsg))
				return true
			} else {
				badReq(w, r, stringStore["Z"])
			}
			return true
		}
		return false

	case "cfg":
		apiPath = apiPath[3:]
		if _, handlerExists := siteSSLSettingCheckers[apiPath]; handlerExists {
			r.ParseForm()
			_, argumentParamExists := r.Form["a"]
			_, sourceParamExists := r.Form["s"]
			_, destinationParamExists := r.Form["d"]
			_, zParamExists := r.Form["z"]
			_, yParamExists := r.Form["y"]
			z := ""
			y := ""
			if zParamExists {
				z = r.Form["z"][0]
			}
			if yParamExists {
				y = r.Form["y"][0]
			}
			if argumentParamExists && sourceParamExists && destinationParamExists {
				var resultMsg string
				globalMutex.Lock()
				resultBool, resultMsg := siteSSLSettingCheckers[apiPath](false, r.Form["a"][0], r.Form["s"][0], r.Form["d"][0], z, y)
				globalMutex.Unlock()

				if !resultBool {
					badReq(w, r, resultMsg)
					return true
				}
				w.Write([]byte(resultMsg))
			} else {
				badReq(w, r, stringStore["Z"])
			}
			return true
		}
		return false

	default:
		switch apiPath {
		case "hardUpload":
			r.ParseForm()
			_, sourceParamExists := r.Form["s"]
			_, destinationParamExists := r.Form["d"]
			if sourceParamExists && destinationParamExists {
				globalMutex.RLock()
				_e := siteExists(r.Form["s"][0], r.Form["d"][0])
				globalMutex.RUnlock()

				if !_e {
					if r.Form["d"][0] != "" {
						badReq(w, r, "Subdominio inexistente")
					} else {
						badReq(w, r, "Sitio inexistente")
					}
					return true
				}

				readErr := r.ParseMultipartForm(maxBodySize)
				if readErr != nil {
					badReq(w, r, "Longitud máxima de contenidos excedida")
					return true
				}
				if _, paramExists := r.MultipartForm.File["f"]; !paramExists {
					badReq(w, r, "No hay datos")
					r.MultipartForm.RemoveAll()
					return true
				}

				globalMutex.RLock()
				r.Form["s"][0] = stringStore["A"] + changeWildcards(r.Form["s"][0])
				if r.Form["d"][0] != "" {
					r.Form["s"][0] += "/" + changeWildcards(r.Form["d"][0])
				}
				r.Form["s"][0] += "/" + stringStore["F"] + "/"
				globalMutex.RUnlock()

				dirEntries, readErr := os.ReadDir(r.Form["s"][0])
				if readErr != nil {
					badReq(w, r, "Directorio inaccesible")
					return true
				}

				for _, f := range dirEntries {
					os.Remove(r.Form["s"][0] + f.Name())
				}

				for _, uploadedFile := range r.MultipartForm.File["f"] {
					_, fileMetadata, readErr := mime.ParseMediaType(uploadedFile.Header["Content-Disposition"][0]) // Maybe exists a concise function for this
					if readErr != nil {
						continue
					}
					filenameIndex := strings.IndexByte(fileMetadata["filename"], '/')
					if filenameIndex != -1 {
						fileMetadata["filename"] = fileMetadata["filename"][filenameIndex+1:]
					}
					filenameIndex = strings.LastIndexByte(fileMetadata["filename"], '/')
					if filenameIndex != -1 {
						fileMetadata["filename"] = fileMetadata["filename"][:filenameIndex+1]
						if strings.Contains(fileMetadata["filename"], "..") || os.MkdirAll(r.Form["s"][0]+fileMetadata["filename"], 0755) != nil {
							continue
						}
					} else {
						fileMetadata["filename"] = ""
					}

					srcFile, readErr := uploadedFile.Open()
					if readErr != nil {
						continue
					}

					dstFile, readErr := os.OpenFile(r.Form["s"][0]+fileMetadata["filename"]+filepath.Base(uploadedFile.Filename), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
					if readErr != nil {
						continue
					}

					io.Copy(dstFile, srcFile)
					srcFile.Close()
					dstFile.Close()
				}
				r.MultipartForm.RemoveAll()
				w.Write([]byte("Datos volcados"))
			} else {
				badReq(w, r, "Faltan fatos")
			}
			return true

		case "sites":
			globalMutex.RLock()
			w.Write([]byte(createDefaultConfig(false, true)))
			globalMutex.RUnlock()
			return true

		case "subdomains":

			r.ParseForm()
			_, paramExists := r.Form["s"]
			if paramExists {
				globalMutex.RLock()
				_e := siteExists(r.Form["s"][0], "")
				globalMutex.RUnlock()

				if !_e {
					badReq(w, r, "Sitio inexistente")
					return true
				}

				globalMutex.RLock()
				w.Write([]byte(createSubdomainsList(false, r.Form["s"][0])))
				globalMutex.RUnlock()
			} else {
				badReq(w, r, stringStore["Z"])
			}
			return true

		case "subdomainData":
			r.ParseForm()
			_, sourceParamExists := r.Form["s"]
			_, destinationParamExists := r.Form["d"]
			if sourceParamExists && destinationParamExists {
				globalMutex.RLock()
				_e := siteExists(r.Form["s"][0], r.Form["d"][0])
				globalMutex.RUnlock()

				if !_e {
					badReq(w, r, "Subdominio inexistente")
					return true
				}

				globalMutex.RLock()
				w.Write([]byte(createSubdomainData(r.Form["s"][0], r.Form["d"][0])))
				globalMutex.RUnlock()
			} else {
				badReq(w, r, stringStore["Z"])
			}
			return true
		}
	}
	return false
}
