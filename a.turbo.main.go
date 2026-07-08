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
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"turbo/customNetHttp"

	//"net/http/cgi" // If you want to deactivate custom cgi library, just turn this on and delete (or rename) server.net.cgi...go files
	//"runtime/debug"

	"encoding/json"
	"sync/atomic"
)

var (
	N  = customNetHttp.N  // Current servers
	I  = customNetHttp.I  // Signed in tokens
	J  = customNetHttp.J  // Persistent IPs
	S_ = customNetHttp.S_ // Strings list
	B_ = customNetHttp.B_ // Chars to encode
	BF = customNetHttp.BF // Fixed chars to encode

	O = customNetHttp.O // Sites map & rewrites
	W = customNetHttp.W // Sites with SSL
	T = customNetHttp.T // MIMEs
	Q = customNetHttp.Q // Headers
	D = customNetHttp.D // Preprocessors
	H = customNetHttp.H // Indexes
	A = customNetHttp.A // Alias

	V  = customNetHttp.V  // Server time limits
	G  = customNetHttp.G  // Server requests limits
	L_ = customNetHttp.L_ // Server upload/body limit
	YH = customNetHttp.YH // Server max header length to read
	YU = customNetHttp.YU // Server max URI length
	YX = customNetHttp.YX // Serves max files in upload
	YY = customNetHttp.YY // Servers max number of headers

	Za = customNetHttp.Za // Reference of time lapses between requests
	Zb = customNetHttp.Zb // Reference of requests between time lapses

	Pa = customNetHttp.Pa
	Pb = customNetHttp.Pb

	U = customNetHttp.U

	CC = customNetHttp.CC // For getting certificates in order
	CD = customNetHttp.CD // Elapsed milliseconds between each new certificate attempt, increasing by 100 per intent
	Y  = customNetHttp.Y  // HTTP responses
	YF = customNetHttp.YF // Fixed http response codes
	A_ = customNetHttp.A_ // Config file mod time reference
	C_ = customNetHttp.C_ // Character lists

	LV = customNetHttp.LV // Visits log file pointer
	LD = customNetHttp.LD // Denials log file pointer

	L   sync.RWMutex        // Global mutex, for logs, ...
	J_  sync.Map            // References per IP
	H1_ = customNetHttp.H1_ // Headers key max length
	H2_ = customNetHttp.H2_ // Headers values max length
)

type J_I struct {
	x sync.Mutex
	b int64
	l int64
	c int64
}

func main() {
	// Compile and compress: go build -ldflags "-s -w"
	// debug.SetGCPercent(1000) // Change frequency of GC

	Za = time.Now().UnixNano()

	S_["T"] = "OKZGN Turbo"
	fmt.Println(S_["T"])

	S_["B"] = "admin"
	S_["H"] = "inside"

	S_["U"] = "Turbo"
	k, e := os.LookupEnv("TURBO_USER")
	if e {
		fmt.Println("Username env var set.")
		S_["U"] = k
	}

	S_["P"] = "Admin"
	k, e = os.LookupEnv("TURBO_PASSWORD")
	if e {
		fmt.Println("Password env var set.")
		S_["P"] = k
	}

	S_["A"] = currentDir()
	k, e = os.LookupEnv("TURBO_DIR")
	if e {
		fmt.Println("Start dir env var set.")
		S_["A"] = putSlash(k)
	}

	S_["M"] = "ok"
	S_["S"] = "turbo.certificates"
	S_["F"] = "@"
	S_["C"] = "fullchain.pem"
	S_["K"] = "privkey.pem"
	S_["N"] = "turbo.config"
	S_["X"] = "turbo.denials"
	S_["G"] = "turbo.visits"
	S_["J"] = "#.html"
	S_["D"] = "Content-Type"
	S_["Z"] = "Faltan datos"
	S_["Y"] = "turbo.dev"

	Y[0] = S_["T"] + `\n{TURBO_RESPONSE_CODE}`
	YF = map[int]bool{0: true}

	B_[";"] = "-.-" // This group of replacements can't be part of C_ because it need to be transferred to frontend
	B_["#"] = "-,-"
	B_["&"] = "-_-"
	BF = map[string]bool{";": true, "#": true, "&": true}

	C_['J'] = []string{
		"\\", "\"", "\t", "\r", "\n", "\f", "\b",
		`\\`, `\\"`, `\\t`, `\\r`, `\\n`, `\\f`, `\\b`,
	}

	updateSettings(false)
	N[0] = createSafeServer(U)
	N[1] = createHttpServer()
	for {
		select {
		case <-Pa.C:
			updateSettings(true)
		case <-Pb.C:
			cleanOldValues(&I)
			cleanOldValues(&J)
		}
	}
}

func createSafeServer(j *tls.Config) *customNetHttp.Server {
	t := &customNetHttp.Server{
		ReadHeaderTimeout: V["RHT"],
		ReadTimeout:       V["RT"],
		WriteTimeout:      V["WT"],
		IdleTimeout:       V["IT"],
		MaxHeaderBytes:    YH,
		ConnState:         connHandler,
		Handler:           customNetHttp.HandlerFunc(serverHandlerFn("s")),
		TLSConfig:         j,
	}

	if len(j.Certificates) > 0 {
		return safeServerStart(t, j)
	}

	return t
}

func safeServerStart(t *customNetHttp.Server, j *tls.Config) *customNetHttp.Server {
	l, e := tls.Listen("tcp", ":443", j)
	if e != nil {
		fmt.Println(e)
		return t
	}

	go func() {
		if e = t.Serve(l); e != nil {
			fmt.Println(e)
			l.Close()
			return
		}
	}()

	return t
}

func createHttpServer() *customNetHttp.Server {
	s := &customNetHttp.Server{
		ReadHeaderTimeout: V["RHT"],
		ReadTimeout:       V["RT"],
		WriteTimeout:      V["WT"],
		IdleTimeout:       V["IT"],
		MaxHeaderBytes:    YH,
		ConnState:         connHandler,
		Handler:           customNetHttp.HandlerFunc(serverHandlerFn("")),
	}

	return httpServerStart(s)
}

func httpServerStart(t *customNetHttp.Server) *customNetHttp.Server {
	l, e := net.Listen("tcp", ":80")
	if e != nil {
		fmt.Println(e)
		return t
	}

	go func() {
		if e = t.Serve(l); e != nil {
			fmt.Println(e)
			l.Close()
			return
		}
	}()

	return t
}

func serverSetLogState(t string, l *os.File) {
	L.Lock()
	defer L.Unlock()

	switch t {
	case S_["G"]:
		if LV == l {
			return
		}
		if LV != nil {
			LV.Close()
		}
		LV = l
	case S_["X"]:
		if LD == l {
			return
		}
		if LD != nil {
			LD.Close()
		}
		LD = l
	}
}

func serverGetLogState(t string) *os.File {
	L.RLock()
	defer L.RUnlock()

	switch t {
	case S_["G"]:
		return LV
	case S_["X"]:
		return LD
	}
	return nil
}

func serverWriteLogs(t string, r *customNetHttp.Request, _t int64, p string) {
	l := serverGetLogState(t)

	if l != nil {
		c := ""
		if r == nil {
			c = p + " " + "\n"
		} else {
			c = p + " " + r.RemoteAddr + " " + strconv.FormatInt(_t, 10) + " " + r.Method + " " + r.Host + " " + r.RequestURI + " " + "\n"
		}
		_, e := l.WriteString(c)
		if e == nil {
			return
		}
	}

	if _, e := os.Stat(S_["A"] + t); e == nil {
		p, _e := os.OpenFile(S_["A"]+t, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if _e == nil {
			serverSetLogState(t, p)
		}
	} else {
		serverSetLogState(t, nil)
	}
}

func serverHandlerFn(a string) func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
	return func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		_t := time.Now().Unix()

		/* New deny method */
		_y := ipAddr(r.RemoteAddr)

		if perIpNotAvailable(_y, true) == true {
			reqMsg(w, r, 429)
			return
		}
		/* End new deny method */

		serverWriteLogs(S_["G"], r, _t, "Visit")

		if console(w, r) {
			return
		}

		L.RLock()
		defer L.RUnlock()

		var f bool
		e, b, s, d := host(r.Host)

		k := d
		l := s
		c := s
		if c != "" {
			c += "." + d
		} else {
			c = d
		}

		if _, f = A[c]; f {
			e, b, s, d = host(A[c])
			c = s
			if c != "" {
				c += "." + d
			} else {
				c = d
			}
		}

		if !f && b == "" { // Reset {FIRST_SITE} & {FIRST_SUBDOMAIN} if no Alias or Wildcard
			k = ""
			l = ""
		}

		m := d
		if b != "" { // Change domain & site reference if wildcard is detected
			m = b
			if s != "" {
				c = s + "." + b
			} else {
				c = b
			}
		}

		if !e {
			reqMsg(w, r, 404)
			return
		}

		if s == "" && W[m]["W"] == true {
			redir(a, d, "www", w, r, 301)
			return
		}

		if s == "www" && W[m]["R"] == true {
			redir(a, d, "", w, r, 301)
			return
		}

		if a == "" && W[c]["S"] != 0 {
			redir("s", d, s, w, r, 301)
		}

		serve(a, d, m, s, k, l, w, r)
	}
}

func resetSettings() {
	L.Lock()
	defer L.Unlock()

	O = make(map[string]map[string]map[string]string) // Sites map & rewrites
	W = make(map[string]map[string]interface{})       // Sites with SSL
	T = make(map[string]map[string]string)            // MIMEs
	Q = make(map[string]map[string]string)            // Headers
	D = make(map[string]map[string]string)            // Preprocessors
	H = make(map[string]map[string]bool)              // Indexes
	A = make(map[string]string)                       // Alias
	U.Certificates = []tls.Certificate{}
	U.NameToCertificate = nil
	LV = nil
	LD = nil
}

func updateSettings(a bool) {
	if a {
		checkSites()
	}

	L.RLock()
	_a := S_["A"]
	_n := S_["N"]
	_f := S_["F"]
	a_ := A_
	L.RUnlock()

	g, e := os.ReadDir(_a)
	if e != nil {
		fmt.Println("Start dir:", _a, e)
		return
	}

	h, e := os.Stat(_a + _n)
	var t int64
	if e != nil {
		t = 1
	} else {
		t = h.ModTime().UnixNano()
	}

	if a_ != t {
		L.Lock()
		A_ = t
		readSiteConfigFrom(_a + _n)
		L.Unlock()
		if t == 1 {
			fmt.Println("Default settings applied.")
		} else {
			fmt.Println("Config file updated, readed and settings applied.")
		}
	}

	for _, f := range g { // This is used when input is like: #.domain.com
		n := f.Name()
		_n := putWildcards(n)
		if m, _ := hostOk(_n, false); !m {
			continue
		}

		_, e = os.ReadDir(_a + n + "/" + _f)
		if e != nil {
			continue
		}

		d, e := os.ReadDir(_a + n)
		if e != nil {
			continue
		}

		L.RLock()
		_e := siteExists(_n, "")
		L.RUnlock()

		if !_e {
			constructSite(_n, "")
			L.Lock()
			C["!"](false, W[_n], true, _n, "") // Set first true if you want to fmt.Println errors
			L.Unlock()
			if a {
				fmt.Println("Site \"" + _n + "\" added to filesystem and enabled on server.")
			}
		}

		for _, f = range d {
			z := f.Name()
			_z := putWildcards(z)
			if m, _ := hostOk(_z+"."+changeWildcards(_n, "x"), false); !m {
				continue
			}

			b, e := os.Stat(_a + n + "/" + z + "/" + _f)

			if e != nil {
				continue
			}

			L.RLock()
			_e = siteExists(_n, _z)
			L.RUnlock()

			if b.IsDir() && !_e {
				constructSite(_n, _z)
				L.Lock()
				C["!"](false, W[_z+"."+_n], true, _n, _z)
				L.Unlock()
				if a {
					fmt.Println("Site \"" + _z + "." + _n + "\" added to filesystem and enabled on server.")
				}
			}
		}
	}
}

func connHandler(a net.Conn, b customNetHttp.ConnState) {
	if !isConn(b) {
		return
	}

	c := ipAddr(a.RemoteAddr().String())

	if perIpNotAvailable(c, true) == true || globalAndPerIpControl(c) == true {
		a.Close()
		return
	}
}

func perIpNotAvailable(c string, m bool) bool {
	v, _ := J_.LoadOrStore(c, &J_I{l: time.Now().UnixNano()})
	t := v.(*J_I)

	t.x.Lock()
	defer t.x.Unlock()

	if t.b > time.Now().Unix() {
		return true
	}

	n := time.Now().UnixNano()
	if m {
		t.c++
	}

	d := n - t.l
	l := atomic.LoadInt64(&G[0])
	b := atomic.LoadInt64(&G[1])
	e := atomic.LoadInt64(&G[2])

	if d > l {
		t.l = n
		t.c = 1
	}

	if (d > b && t.c < e) || b == 0 || e == 0 {
		return false
	}

	_d := t.c / e
	_l := d / b

	if _d > _l {
		L.RLock()
		_, z := J[c]
		L.RUnlock()

		t.b = time.Now().Unix()
		m := c + " conn denial"

		if z {
			t.b += 10
			m += " persistent"
		} else {
			t.b += 5
		}

		serverWriteLogs(S_["X"], nil, 0, m)

		return true
	}

	return false
}

func globalAndPerIpControl(a string) bool {
	var l int64 = atomic.LoadInt64(&G[0])
	var b int64 = atomic.LoadInt64(&G[1])
	var e int64 = atomic.LoadInt64(&G[2])

	s := atomic.LoadInt64(&Za)
	h := atomic.LoadInt64(&Zb)
	atomic.AddInt64(&Zb, 1)

	c := time.Now().UnixNano()
	d := c - s
	h++

	if (d > b && h < e) || b == 0 || e == 0 { // Continue with unnecessary checking
		return false
	}

	_d := (h / e)
	_l := (d / b)

	// Shows details
	// fmt.Println(_d, _l)

	z := false

	if _d > _l {
		L.Lock()
		J[a] = time.Now().Unix() + 59 // Time to preserve on cleanOldValues
		L.Unlock()
		serverWriteLogs(S_["X"], nil, 0, a+" rate limit exceed at: "+strconv.FormatInt(J[a], 10))
		z = true
	}

	if d > l {
		atomic.StoreInt64(&Za, c)
		atomic.StoreInt64(&Zb, 1)
	}

	return z
}

func _constructSite(s string, d string) {
	if _, e := O[s]; !e {
		O[s] = make(map[string]map[string]string)
	}
	O[s][d] = make(map[string]string) // Rewrites
	if d != "" {
		s = d + "." + s
	}
	D[s] = make(map[string]string)      // Preprocessors
	H[s] = make(map[string]bool)        // Indexes
	T[s] = make(map[string]string)      // MIMEs
	Q[s] = make(map[string]string)      // Headers
	W[s] = make(map[string]interface{}) // Site config.
	W[s]["S"] = 0
	W[s]["C"] = false
	W[s]["R"] = false
	W[s]["W"] = false
	W[s]["E"] = ""
	W[s]["A"] = ""
}

func constructSite(s string, d string) {
	L.Lock()
	defer L.Unlock()
	_constructSite(s, d)
}

func deleteSite(s string, d string) {
	L.Lock()
	defer L.Unlock()

	var k string
	if d != "" {
		delete(O[s], d)
		s = d + "." + s
		deleteCertificate(s)
	} else {
		for k, _ = range O[s] {
			if k != "" {
				deleteCertificate(k + "." + s)
			}
		}
		delete(O, s)
	}
	delete(D, s)
	delete(H, s)
	delete(W, s)
	delete(T, s)
	delete(Q, s)
	for k, d = range A {
		if d == s {
			delete(A, k)
		}
	}
}

func checkSites() {
	type _d struct{ s, d string }
	var _l []_d

	L.RLock()
	for d := range O {
		for s := range O[d] {
			if b, _ := E["/"](false, d, s); !b { // E["/"] is used when input is like: *.domain.com
				_l = append(_l, _d{s, d})
			}
		}
	}
	L.RUnlock()

	for _, i := range _l {
		deleteSite(i.d, i.s)

		s := i.s
		if s != "" {
			s += "."
		}
		fmt.Println("Site \"" + s + i.d + "\" deleted from filesystem and disabled on server.")
	}
}

func redir(z string, h string, s string, w customNetHttp.ResponseWriter, r *customNetHttp.Request, j int) {
	if s != "" {
		s += "."
	}
	customNetHttp.Redirect(w, r, "http"+z+"://"+s+h+r.RequestURI, j)
}

func serve(z string, g string, h string, s string, k string, l string, w customNetHttp.ResponseWriter, r *customNetHttp.Request) { //i, n, o
	a, _, _, b := detectWildcards(s, h)

	// fmt.Println("SUBDOMAIN", a, i, o, b)
	if !a {
		// Without 404 response: b = s
		reqMsg(w, r, 404)
		return
	}

	// fmt.Println("REQUEST", r.RequestURI)
	if z == "" && s != "" && W[b+"."+h]["S"] != 0 {
		redir("s", g, s, w, r, 301)
		return
	}

	var c bool
	x, f, c := choose(w, r, g, h, b, s, k, l)
	if !c {
		return
	}
	r.RequestURI = x

	z = S_["A"] + changeWildcards(h) + "/"
	if s != "" {
		if a {
			s = changeWildcards(b)
		}
		z += s + "/" + S_["F"]
	} else {
		z += S_["F"]
	}

	d, e := os.Stat(z + x)
	if e != nil {
		reqMsg(w, r, 404)
		return
	}

	if s != "" {
		s = b + "." + h
	} else {
		s = h
	}

	if d.IsDir() {
		t := "/"
		if x == t || x[len(x)-1] == '/' {
			t = ""
		}
		y := " " // Hide default indexes when H is empty

		for u := range H[s] {
			y = t + u
			i, e := os.Stat(z + x + y)
			if e == nil && !i.IsDir() { // Make sure this is the best error handling for Indexes, before: !os.IsNotExist(e)
				x += y
				y = ""
				break
			}
		}

		if y != "" {
			reqMsg(w, r, 404)
			return
		}
	}

	h = ext(x)
	j := w.Header()

	if _, c = Q[s]; c {
		for u := range Q[s] {
			j.Set(u, Q[s][u])
		}
	} // Headers inclution

	if _, c = D[s][h]; c && D[s][h] != "" { // Preprocessors verify
		i, e := os.Stat(D[s][h])
		if e == nil && !i.IsDir() { // Before: !os.IsNotExist(e)
			dynamic(z, x, f, D[s][h], w, r, &j)
			return
		}
	}

	if _, c = T[s][h]; c {
		j.Set(S_["D"], T[s][h])
	}
	customNetHttp.ServeFile(w, r, z+x)
	// fmt.Println(j) Show headers
}

func dynamic(z string, x string, f string, p string, w customNetHttp.ResponseWriter, r *customNetHttp.Request, _ *customNetHttp.Header) {
	l := new(customNetHttp.CgiHandler) // Before: new(cgi.Handler)
	l.Path = p
	l.Root = z
	l.Env = append(l.Env, "REDIRECT_STATUS=CGI") // This is need for execution of scripts (it will not executed if isn't set). Also depends of 'cgi.force-redirect' on php.ini.
	if r.URL.RawQuery != "" {
		f = r.URL.RawQuery + "&" + f
	}
	l.Env = append(l.Env, "QUERY_STRING="+f) // If not set, not includes rewrite query string
	l.Env = append(l.Env, "DOCUMENT_ROOT="+z)
	l.Env = append(l.Env, "SCRIPT_FILENAME="+z+x)
	l.ServeHTTP(w, r)
	// fmt.Println(j) Show headers
}

func rewrite(y string, h string, b string) (string, string) {
	var c bool
	if _, c = O[h][b][y]; c {
		return O[h][b][y], y
	}
	if y == "/" {
		return "", ""
	} // To prevent passing through 'choose' unecessary functions. Before: return y, ""
	y = y[1:]
	for {
		d := strings.LastIndexByte(y, '/')
		if d == -1 {
			break
		}
		d++
		if _, c := O[h][b]["/"+y[:d]]; c {
			return O[h][b]["/"+y[:d]], "/" + y[:d]
		} else {
			y = y[:d-1]
		}
	}
	if _, c = O[h][b]["/"]; c {
		return O[h][b]["/"], "/"
	} // At the end of large unmatched string is obligatory to check if match with a top level rewrite
	return "", ""
}

func choose(w customNetHttp.ResponseWriter, r *customNetHttp.Request, g string, h string, b string, s string, n string, m string) (string, string, bool) {
	k := cutAt(r.RequestURI, '?')
	y, c := rewrite(k, h, b) // h is reference to site map key, and b is reference to site subdomain map key, both in O
	if y == "" {
		return k, "", true
	} // This is for unmatched URIs for rewrite
	y = shortcutWords(r, y, h, b, g, s, n, m, c)
	j := strings.IndexByte(y, '?')
	if j != -1 {
		k = y[j+1:]
		y = y[:j]
	} else {
		k = ""
	}
	switch y[0] {
	case 'H':
		redir("", y[1:]+k, "", w, r, 302)
		return "", "", false
	case 'S':
		redir("s", y[1:]+k, "", w, r, 302)
		return "", "", false
	case 'N':
		y = y[1:]
	}
	return y, k, true
}

func shortcutWords(r *customNetHttp.Request, u string, h string, i string, g string, s string, k string, l string, c string) string {
	d := u
	e := ""
	f := ""
	var z bool
	for {
		a := strings.IndexByte(d, '{')
		b := strings.IndexByte(d, '}')
		if d == "" || a == -1 || b == -1 || b < a {
			break
		}
		e = d[a+1 : b]
		if _, z = _R[e]; z {
			f += d[:a] + _R[e](r, h, i, g, s, k, l, c)
		} else {
			f += d[:a]
		}
		if b < len(d) {
			d = d[b+1:]
		} else {
			d = ""
		}
	}
	f += d
	return f
}

func readSiteConfigFrom(p string) {
	// Probably need to check file permissions, because can't read and generate an err.
	if fileExists(p) {
		f, e := os.ReadFile(p)
		if e != nil || !json.Valid([]byte(f)) {
			fmt.Println("Config file:", p, e)
			setDefaultSettings()
			return
		}
		json.Unmarshal(f, &X)
		var a bool
		var b string
		var d string
		var k string
		for k, _ = range _MX {
			if _, a = X[k]; a { // This is for another kind of lists in config file
				for z, l := range X[k] {
					b, a = l.(string)
					if a {
						_MX[k](z, b)
					}
				}
				continue
			}
		}
		for k, _ = range M { // Default settings check
			if _, a = X[k]; a {
				for _, l := range _MO[k] {
					if _, a = X[k][l]; a {
						b, a = X[k][l].(string)
						var z string
						if a {
							if a, z = M[k][l](b, S_["P"]); a {
								continue
							}
							if _, a = _ME[k][l][z]; a { // ME (E, for exceptions) There are some exceptions on errors, some cause unnecessary resets
								continue
							}
						}
					}
					R_[k][l]()
				}
			} else {
				for m, _ := range R_[k] {
					R_[k][m]()
				} // Reset specific defaults if doesn't exists
			}
		}
		for s, _ := range X { // Site & subdomains existence check
			if _, a = M[s]; a {
				continue
			}
			if !siteExistenceCheck(s, "") {
				continue
			}
			for d, _ = range X[s] {
				if _, a = C[d]; a || (d != "" && !siteExistenceCheck(s, d)) {
					continue
				}
				c, a := X[s][d].(map[string]interface{})
				if !a {
					continue
				}
				for n, _ := range C { // Subdomains content check
					if _, a = c[n]; a {
						C[n](false, c[n], true, s, d) // Returns something like: a, _
					}
				}
			}
		}
		X = make(map[string]map[string]interface{})
		return
	}
	setDefaultSettings()
}

func setDefaultSettings() {
	for k, _ := range R_ {
		for m, _ := range R_[k] {
			R_[k][m]()
		}
	}
}

func siteExistenceCheck(s string, d string) bool {
	var c bool
	var m string
	for m, _ = range E {
		if c, _ = E[m](true, s, d); !c {
			F[m](s, d)
			return false
		}
	}
	return true
}
