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

package customNetHttp

import (
	"crypto/tls"
	"os"
	"time"
)

var (
	N = make([]*Server, 2) // Current servers

	I = make(map[string]int64) // Signed in tokens
	J = make(map[string]int64) // Persistent IPs

	S_ = make(map[string]string) // Strings list
	B_ = make(map[string]string) // Chars to encode
	BF = make(map[string]bool)   // Fixed chars to encode

	O = make(map[string]map[string]map[string]string) // Sites map & rewrites
	W = make(map[string]map[string]interface{})       // Sites with SSL
	T = make(map[string]map[string]string)            // MIMEs
	Q = make(map[string]map[string]string)            // Headers
	D = make(map[string]map[string]string)            // Preprocessors
	H = make(map[string]map[string]bool)              // Indexes

	A = make(map[string]string) // Alias

	V        = make(map[string]time.Duration)        // Server time limits
	G        = []int64{10000000000, 1000000000, 100} // Server requests limits
	L_ int64 = 1048576                               // Server upload/body limit
	YH       = 5000                                  // Server max header length to read
	YU       = 1000                                  // Server max URI length
	YX       = 10000                                 // Serves max files in upload
	YY int64 = 1000                                  // Servers max number of headers
	Za int64 = 0                                     // Reference of time lapses between requests
	Zb int64 = 0                                     // Reference of requests between time lapses

	Pa = time.NewTicker(30 * time.Second)
	Pb = time.NewTicker(60 * time.Second)

	U = &tls.Config{NextProtos: []string{"h2", "http/1.1"}, Certificates: []tls.Certificate{}}

	CC  string                                           // For getting certificates in order
	CD  time.Duration             = 30000                // Elapsed milliseconds between each new certificate attempt, increasing by 100 per intent
	Y                             = make(map[int]string) // HTTP responses
	YF                            = make(map[int]bool)   // Fixed http response codes
	A_  int64                                            // Config file mod time reference
	C_  = make(map[rune][]string)                        // Character lists
	LV  *os.File                                         // Visits log file pointer
	LD  *os.File                                         // Denials log file pointer
	H1_ = 48                                             // Headers key max length
	H2_ = 512                                            // Headers values max length
)
