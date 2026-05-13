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
	"fmt"
	"net/url"
	"os"
	"strconv"
)

func saveDefaultConfig() bool {
	e := os.WriteFile(S_["A"]+S_["N"], []byte(createDefaultConfig(true, false)), 0600)
	if e != nil {
		fmt.Println("Saving config file:", e)
		return false
	}
	return true
}

func createDefaultConfig(a bool, b bool) string {
	// a: to not include subdomains list on response
	// b: to set as objects fixed keys on B_ and Y on response
	o := ""
	k := "\""
	for l, _ := range O {
		o += k + l + "\":"
		if !a {
			o += "{" + createSiteSettingsList(l) + "}"
		} else {
			o += createSubdomainsList(true, l)
		}
		k = ",\""
	}

	o += k + "_\":{" // Chars to encode list
	k = "\""
	for j, l := range B_ {
		o += k + changeChars(true, j, C_['J']) + "\":"
		if _, a := BF[j]; a && b {
			o += "{\"f\":\"" + changeChars(true, l, C_['J']) + "\"}"
		} else {
			o += "\"" + changeChars(true, l, C_['J']) + "\""
		}
		k = ",\""
	}

	o += "},\"@\":{" // Denied IPs list
	k = "\""
	for j, l := range J {
		o += k + changeChars(true, j, C_['J']) + "\":\"" + changeChars(true, strconv.FormatInt(l, 10), C_['J']) + "\""
		k = ",\""
	}

	o += "},\"#\":{" // Http codes responses list
	k = "\""
	for j, l := range Y {
		o += k + changeChars(true, strconv.Itoa(j), C_['J']) + "\":"
		if _, a := YF[j]; a && b {
			o += "{\"f\":\"" + changeChars(true, l, C_['J']) + "\"}"
		} else {
			o += "\"" + changeChars(true, l, C_['J']) + "\""
		}
		k = ",\""
	}

	return "{" + o + "},\".\":{\"M\":\"" + changeChars(true, S_["A"], C_['J']) + "\",\"RT\":\"" + V["RT"].String() + "\",\"RHT\":\"" + V["RHT"].String() + "\",\"WT\":\"" + V["WT"].String() + "\",\"IT\":\"" + V["IT"].String() + "\",\"MUB\":\"" + strconv.Itoa(YU) + "\",\"MHB\":\"" + strconv.Itoa(YH) + "\",\"MBB\":\"" + strconv.FormatInt(L_, 10) + "\",\"CIL\":\"" + strconv.FormatInt(G[0]/10000000, 10) + "\",\"CIS\":\"" + strconv.FormatInt(G[1]/10000000, 10) + "\",\"CII\":\"" + strconv.FormatInt(G[2], 10) + "\"}}"
}

func createSubdomainsList(a bool, s string) string {
	o := ""
	k := "\""
	for l, _ := range O[s] {
		o += k + l + "\":"
		if !a {
			if l != "" {
				l += "." + s
				o += "{" + createSiteSettingsList(l) + "}" // All subdomains & domains in the frontend need to show if SSL is on
			} else {
				l = s
				o += "{" + createSiteAliasList(l) + "," + createSiteSettingsList(l) + "}"
			}
		} else {
			o += createSubdomainData(s, l)
		}
		k = ",\""
	}
	return "{" + o + "}"
}

func createSubdomainData(s string, d string) string {
	var k string
	var l string
	var m string
	var n string
	if d != "" {
		l = d + "." + s
	} else {
		l = s
	}

	o := "\"=\":{"
	m = "\""
	for n, _ = range O[s][d] {
		switch O[s][d][n][0] {
		case 'H':
			k = "http://"
		case 'S':
			k = "https://"
		default:
			k = ""
		}
		o += m + changeChars(true, n, C_['J']) + "\":\"" + k + changeChars(true, O[s][d][n][1:], C_['J']) + "\""
		m = ",\""
	}

	o += "},\"$\":{"
	m = "\""
	for k, _ = range T[l] {
		o += m + k + "\":\"" + changeChars(true, T[l][k], C_['J']) + "\""
		m = ",\""
	}
	o += "},\".\":{"
	m = "\""
	for k, _ = range Q[l] {
		o += m + k + "\":\"" + changeChars(true, Q[l][k], C_['J']) + "\""
		m = ",\""
	}
	o += "},\"?\":{"
	m = "\""
	for k, _ = range D[l] {
		o += m + k + "\":\"" + changeChars(true, D[l][k], C_['J']) + "\""
		m = ",\""
	}
	o += "},\"-\":{"
	m = "\""
	for k, _ = range H[l] {
		o += m + changeChars(true, k, C_['J']) + "\":\"\""
		m = ",\""
	}
	o += "}," + createSiteAliasList(l)
	o += "," + createSiteSettingsList(l)
	return "{" + o + "}"
}

func createSiteAliasList(l string) string {
	o := "{"
	m := "\""
	for n, k := range A {
		if l == k {
			o += m + n + "\":\"\""
			m = ",\""
		}
	}
	o += "}"
	return "\"&\":" + o
}

func createSiteSettingsList(l string) string {
	o := "{"
	m := "\""
	var n string
	for r, p := range W[l] {
		s, e := p.(bool)
		if !e {
			t, e := p.(int)
			if !e {
				u, e := p.(string)
				if !e {
					continue
				}
				n = url.QueryEscape(u)
			} else {
				n = strconv.Itoa(t)
			}
		} else {
			if s {
				n = "1"
			} else {
				n = "0"
			}
		}
		o += m + r + "\":\"" + n + "\""
		m = ",\""
	}
	o += "}"
	return "\"!\":" + o
}
