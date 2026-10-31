package main

// A4 (H9, H46): el login solo por POST /admin:, con las credenciales en el
// cuerpo y un cuerpo pequeño; el cierre de sesión solo por POST.

import (
	"bufio"
	"bytes"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// loginRequest envía un login con el método, la ruta, el cuerpo y el tipo de
// contenido dados y devuelve el código, el cuerpo y si fijó la cookie.
func loginRequest(t *testing.T, base, method, path string, body io.Reader, contentType string) (int, string, bool) {
	t.Helper()
	req, _ := http.NewRequest(method, base+path, body)
	req.Host = "localhost"
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), strings.Contains(res.Header.Get("Set-Cookie"), sessionCookieName+"=")
}

func multipartCredentials(user, password string) (*bytes.Buffer, string) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("u", user)
	w.WriteField("p", password)
	w.Close()
	return &buf, w.FormDataContentType()
}

// H9: con las credenciales en la URL, por GET o fuera de /admin: no se inicia
// sesión; por POST /admin: con las credenciales en el cuerpo, sí.
func TestA4_LoginOnlyByPostBody(t *testing.T) {
	initForTest(t)
	base := startServer(t)

	code, body, cookie := loginRequest(t, base, "GET", "/admin:?u=Turbo&p=Admin", nil, "")
	if cookie || strings.HasPrefix(body, "ok") || code != 200 || !strings.Contains(body, `name="u"`) {
		t.Errorf("GET con credenciales en la URL: %d cookie=%v %.40q; se esperaba la página de login", code, cookie, body)
	}
	code, body, cookie = loginRequest(t, base, "POST", "/admin:?u=Turbo&p=Admin", nil, "")
	if cookie || strings.HasPrefix(body, "ok") {
		t.Errorf("POST con credenciales en la URL: %d cookie=%v %.40q", code, cookie, body)
	}
	buf, contentType := multipartCredentials("Turbo", "Admin")
	code, body, cookie = loginRequest(t, base, "POST", "/admin:x:", buf, contentType)
	if cookie || strings.HasPrefix(body, "ok") {
		t.Errorf("POST /admin:x: con credenciales: %d cookie=%v %.40q", code, cookie, body)
	}
	for _, path := range []string{"/admin::", "/admin::x"} { // H60: only /admin: itself
		buf, contentType = multipartCredentials("Turbo", "Admin")
		code, body, cookie = loginRequest(t, base, "POST", path, buf, contentType)
		if cookie || strings.HasPrefix(body, "ok") {
			t.Errorf("POST %s con credenciales: %d cookie=%v %.40q", path, code, cookie, body)
		}
	}
	buf, contentType = multipartCredentials("Turbo", "Admin")
	code, body, cookie = loginRequest(t, base, "PUT", "/admin:", buf, contentType)
	if cookie || strings.HasPrefix(body, "ok") {
		t.Errorf("PUT /admin: con credenciales: %d cookie=%v %.40q", code, cookie, body)
	}

	buf, contentType = multipartCredentials("Turbo", "Admin")
	if code, body, cookie = loginRequest(t, base, "POST", "/admin:", buf, contentType); !cookie || !strings.HasPrefix(body, "ok") {
		t.Errorf("login multipart: %d cookie=%v %.40q", code, cookie, body)
	}
	form := url.Values{"u": {"Turbo"}, "p": {"Admin"}}.Encode()
	if code, body, cookie = loginRequest(t, base, "POST", "/admin:", strings.NewReader(form), "application/x-www-form-urlencoded"); !cookie || !strings.HasPrefix(body, "ok") {
		t.Errorf("login urlencoded: %d cookie=%v %.40q", code, cookie, body)
	}
	// Body and URL mixed: only the body counts.
	if code, body, cookie = loginRequest(t, base, "POST", "/admin:?p=Admin", strings.NewReader("u=Turbo"), "application/x-www-form-urlencoded"); cookie || strings.HasPrefix(body, "ok") {
		t.Errorf("contraseña en la URL y usuario en el cuerpo: %d cookie=%v %.40q", code, cookie, body)
	}
}

// H46: el cuerpo del login se limita a 4 KiB antes de leerlo: con 1 MB se
// responde 413 sin esperar al resto.
func TestA4_LoginBodyLimit(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	bodies := map[string]string{
		"application/x-www-form-urlencoded": "u=Turbo&p=",
		"multipart/form-data; boundary=X":   "--X\r\nContent-Disposition: form-data; name=\"p\"\r\n\r\n",
	}
	for contentType, start := range bodies {
		conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		head := "POST /admin: HTTP/1.1\r\nHost: localhost\r\nContent-Type: " + contentType + "\r\nContent-Length: 1048576\r\n\r\n"
		conn.Write([]byte(head + start + strings.Repeat("A", 8192)))
		conn.SetReadDeadline(time.Now().Add(clientTimeout()))
		res, err := http.ReadResponse(bufio.NewReader(conn), nil)
		conn.Close()
		if err != nil {
			t.Errorf("%s: sin respuesta con el cuerpo a medias (el servidor espera el resto): %v", contentType, err)
			continue
		}
		res.Body.Close()
		if res.StatusCode != 413 {
			t.Errorf("%s: login con 1 MB: %d; se esperaba 413", contentType, res.StatusCode)
		}
	}
}

// H9: cerrar sesión solo por POST; un GET (un enlace o una imagen de otra
// página) no la cierra.
func TestA4_SignoutOnlyByPost(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	req, _ := http.NewRequest("GET", base+"/admin:signout:", nil)
	req.Host = "localhost"
	req.Header.Set("ok", tok)
	if res, err := (&http.Client{Timeout: clientTimeout()}).Do(req); err == nil {
		res.Body.Close()
	}
	if code, body, _ := post(base, "/admin:inside:sites", tok); code != 200 || !strings.HasPrefix(body, "{") {
		t.Errorf("tras GET /admin:signout: la sesión se cerró: %d %.40q", code, body)
	}
	post(base, "/admin:signout:", tok)
	if code, body, _ := post(base, "/admin:inside:sites", tok); strings.HasPrefix(body, "{") {
		t.Errorf("tras POST /admin:signout: la sesión sigue abierta: %d", code)
	}
}
