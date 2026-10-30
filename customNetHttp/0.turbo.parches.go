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

// Funciones que usan los parches de Turbo sobre el código de Go (ver
// PATCHES.md). Viven aquí, y no en los archivos regenerados, para que los
// parches se limiten a llamarlas.

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

// turboPlantillaError devuelve el Content-Type y el cuerpo de una respuesta de
// error con la plantilla de Turbo para el código (Y; la 0 si no hay una
// propia): {TURBO_RESPONSE_CODE} se sustituye por el código, una plantilla que
// empieza por '<' se sirve como HTML y en las de texto `\n` es un salto de
// línea. El detalle va en la línea siguiente. turbo:P1 turbo:P9
func turboPlantillaError(code int, detalle string) (contentType, cuerpo string) {
	plantillas := *TurboErrorTemplates.Load()
	v, ok := plantillas[code]
	if !ok {
		v = plantillas[0]
	}
	tipo := "plain"
	if strings.HasPrefix(v, "<") {
		tipo = "html"
	} else {
		v = strings.ReplaceAll(v, `\n`, "\n")
	}
	return "text/" + tipo + "; charset=utf-8", strings.ReplaceAll(v, "{TURBO_RESPONSE_CODE}", strconv.Itoa(code)) + "\n" + detalle + "\n"
}

// turboEscribirError responde con la plantilla de error de Turbo. Como Error
// de Go, fija las cabeceras antes de WriteHeader y borra Content-Length.
// turbo:P2 turbo:P9
func turboEscribirError(w ResponseWriter, detalle string, code int) {
	tipo, cuerpo := turboPlantillaError(code, detalle)
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", tipo)
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	io.WriteString(w, cuerpo)
}

// turboErrorManejador devuelve un manejador que responde con la plantilla de
// error del código. turbo:P3
func turboErrorManejador(code int) HandlerFunc {
	return func(w ResponseWriter, r *Request) { turboEscribirError(w, "", code) }
}

// errTurboURILarga es el error de readRequest cuando la URI supera
// TurboMaxURILength (ajuste MUB); conn.serve responde 414. turbo:P3
var errTurboURILarga = errors.New("http: request URI too large")

// turboMaxRSTStreamPorSegundo es el máximo de RST_STREAM por segundo y
// conexión de HTTP/2; por encima, la conexión se cierra con GOAWAY
// (ENHANCE_YOUR_CALM). Se suma a la mitigación de Go del ataque Rapid Reset
// (CVE-2023-44487), que limita los manejadores pendientes. turbo:P11
const turboMaxRSTStreamPorSegundo = 50

// turboLimiteRST cuenta los RST_STREAM de una conexión en ventanas de un
// segundo. Solo lo usa la goroutine de la conexión. turbo:P11
type turboLimiteRST struct {
	ventana   time.Time
	recibidos int
}

func (l *turboLimiteRST) excedido(ahora time.Time) bool {
	if ahora.Sub(l.ventana) > time.Second {
		l.ventana = ahora
		l.recibidos = 0
	}
	l.recibidos++
	return l.recibidos > turboMaxRSTStreamPorSegundo
}

// turboErrorConexion escribe en la conexión una respuesta de error completa de
// HTTP/1.1 con la plantilla de Turbo y cierra la conexión, para los errores
// que se producen antes de llegar a ningún manejador. turbo:P1
func turboErrorConexion(w io.Writer, detalle string, code int) {
	tipo, cuerpo := turboPlantillaError(code, detalle)
	io.WriteString(w, "HTTP/1.1 "+strconv.Itoa(code)+" "+StatusText(code)+"\r\nContent-Type: "+tipo+"\r\nX-Content-Type-Options: nosniff\r\nServer: "+TurboServerName+"\r\nConnection: close\r\n\r\n"+cuerpo)
}
