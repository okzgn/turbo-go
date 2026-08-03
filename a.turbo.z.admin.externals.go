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
	e := os.WriteFile(stringStore["A"]+stringStore["N"], []byte(createDefaultConfig(true, false)), 0600)
	if e != nil {
		fmt.Println("Saving config file:", e)
		return false
	}
	return true
}

func createDefaultConfig(excludeSubdomains bool, includeFixedKeys bool) string {
	// a: to not include subdomains list on response
	// b: to set as objects fixed keys on charReplacements and httpResponses
	jsonBuilder := ""
	delimiter := "\""
	for siteKey, _ := range sitesMap {
		jsonBuilder += delimiter + siteKey + "\":"
		if !excludeSubdomains {
			jsonBuilder += "{" + createSiteSettingsList(siteKey) + "}"
		} else {
			jsonBuilder += createSubdomainsList(true, siteKey)
		}
		delimiter = ",\""
	}

	jsonBuilder += delimiter + "_\":{" // Chars to encode list
	delimiter = "\""
	for mapKey, l := range charReplacements {
		jsonBuilder += delimiter + changeChars(true, mapKey, charEscapeLists['J']) + "\":"
		if _, a := fixedCharReplacements[mapKey]; a && includeFixedKeys {
			jsonBuilder += "{\"f\":\"" + changeChars(true, l, charEscapeLists['J']) + "\"}"
		} else {
			jsonBuilder += "\"" + changeChars(true, l, charEscapeLists['J']) + "\""
		}
		delimiter = ",\""
	}

	jsonBuilder += "},\"@\":{" // Denied IPs list
	delimiter = "\""
	for mapKey, l := range persistentIPs {
		jsonBuilder += delimiter + changeChars(true, mapKey, charEscapeLists['J']) + "\":\"" + changeChars(true, strconv.FormatInt(l, 10), charEscapeLists['J']) + "\""
		delimiter = ",\""
	}

	jsonBuilder += "},\"#\":{" // Http codes responses list
	delimiter = "\""
	for mapKey, l := range httpResponses {
		jsonBuilder += delimiter + changeChars(true, strconv.Itoa(mapKey), charEscapeLists['J']) + "\":"
		if _, a := fixedHTTPResponses[mapKey]; a && includeFixedKeys {
			jsonBuilder += "{\"f\":\"" + changeChars(true, l, charEscapeLists['J']) + "\"}"
		} else {
			jsonBuilder += "\"" + changeChars(true, l, charEscapeLists['J']) + "\""
		}
		delimiter = ",\""
	}

	return "{" + jsonBuilder + "},\".\":{\"M\":\"" + changeChars(true, stringStore["A"], charEscapeLists['J']) + "\",\"RT\":\"" + serverTimeLimits["RT"].String() + "\",\"RHT\":\"" + serverTimeLimits["RHT"].String() + "\",\"WT\":\"" + serverTimeLimits["WT"].String() + "\",\"IT\":\"" + serverTimeLimits["IT"].String() + "\",\"MUB\":\"" + strconv.Itoa(maxURILength) + "\",\"MHB\":\"" + strconv.Itoa(maxHeaderBytes) + "\",\"MBB\":\"" + strconv.FormatInt(maxBodySize, 10) + "\",\"CIL\":\"" + strconv.FormatInt(serverRequestLimits[0]/10000000, 10) + "\",\"CIS\":\"" + strconv.FormatInt(serverRequestLimits[1]/10000000, 10) + "\",\"CII\":\"" + strconv.FormatInt(serverRequestLimits[2], 10) + "\"}}"
}

func createSubdomainsList(excludeSettings bool, domain string) string {
	jsonBuilder := ""
	delimiter := "\""
	for subdomain, _ := range sitesMap[domain] {
		jsonBuilder += delimiter + subdomain + "\":"
		if !excludeSettings {
			if subdomain != "" {
				subdomain += "." + domain
				jsonBuilder += "{" + createSiteSettingsList(subdomain) + "}" // All subdomains & domains in the frontend need to show if SSL is on
			} else {
				subdomain = domain
				jsonBuilder += "{" + createSiteAliasList(subdomain) + "," + createSiteSettingsList(subdomain) + "}"
			}
		} else {
			jsonBuilder += createSubdomainData(domain, subdomain)
		}
		delimiter = ",\""
	}
	return "{" + jsonBuilder + "}"
}

func createSubdomainData(domain string, subdomain string) string {
	var extKey string
	var siteKey string
	var delimiter string
	var routeKey string
	if subdomain != "" {
		siteKey = subdomain + "." + domain
	} else {
		siteKey = domain
	}

	jsonBuilder := "\"=\":{"
	delimiter = "\""
	for routeKey, _ = range sitesMap[domain][subdomain] {
		switch sitesMap[domain][subdomain][routeKey][0] {
		case 'H':
			extKey = "http://"
		case 'S':
			extKey = "https://"
		default:
			extKey = ""
		}
		jsonBuilder += delimiter + changeChars(true, routeKey, charEscapeLists['J']) + "\":\"" + extKey + changeChars(true, sitesMap[domain][subdomain][routeKey][1:], charEscapeLists['J']) + "\""
		delimiter = ",\""
	}

	jsonBuilder += "},\"$\":{"
	delimiter = "\""
	for extKey, _ = range mimeTypes[siteKey] {
		jsonBuilder += delimiter + extKey + "\":\"" + changeChars(true, mimeTypes[siteKey][extKey], charEscapeLists['J']) + "\""
		delimiter = ",\""
	}
	jsonBuilder += "},\".\":{"
	delimiter = "\""
	for extKey, _ = range customHeaders[siteKey] {
		jsonBuilder += delimiter + extKey + "\":\"" + changeChars(true, customHeaders[siteKey][extKey], charEscapeLists['J']) + "\""
		delimiter = ",\""
	}
	jsonBuilder += "},\"?\":{"
	delimiter = "\""
	for extKey, _ = range preprocessors[siteKey] {
		jsonBuilder += delimiter + extKey + "\":\"" + changeChars(true, preprocessors[siteKey][extKey], charEscapeLists['J']) + "\""
		delimiter = ",\""
	}
	jsonBuilder += "},\"-\":{"
	delimiter = "\""
	for extKey, _ = range indexFiles[siteKey] {
		jsonBuilder += delimiter + changeChars(true, extKey, charEscapeLists['J']) + "\":\"\""
		delimiter = ",\""
	}
	jsonBuilder += "}," + createSiteAliasList(siteKey)
	jsonBuilder += "," + createSiteSettingsList(siteKey)
	return "{" + jsonBuilder + "}"
}

func createSiteAliasList(siteKey string) string {
	jsonBuilder := "{"
	delimiter := "\""
	for aliasName, mappedSite := range domainAliases {
		if siteKey == mappedSite {
			jsonBuilder += delimiter + aliasName + "\":\"\""
			delimiter = ",\""
		}
	}
	jsonBuilder += "}"
	return "\"&\":" + jsonBuilder
}

func createSiteSettingsList(siteKey string) string {
	jsonBuilder := "{"
	delimiter := "\""
	//var settingName string
	var encodedValue string
	for settingName, settingVal := range siteSSLConfig[siteKey] {
		s, e := settingVal.(bool)
		if !e {
			t, e := settingVal.(int)
			if !e {
				u, e := settingVal.(string)
				if !e {
					continue
				}
			encodedValue = url.QueryEscape(u)
			} else {
				encodedValue = strconv.Itoa(t)
			}
		} else {
			if s {
				encodedValue = "1"
			} else {
				encodedValue = "0"
			}
		}
		jsonBuilder += delimiter + settingName + "\":\"" + encodedValue + "\""
		delimiter = ",\""
	}
	jsonBuilder += "}"
	return "\"!\":" + jsonBuilder
}
