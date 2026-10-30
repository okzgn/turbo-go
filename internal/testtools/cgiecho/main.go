// CGI de eco: devuelve variables de entorno relevantes y los bytes leídos del cuerpo.
// Con sleep=<ms> en la consulta espera antes de responder y, si además lleva
// mark=<ruta>, crea ese archivo al terminar la espera.
package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	q, _ := url.ParseQuery(os.Getenv("QUERY_STRING"))
	if ms, err := strconv.Atoi(q.Get("sleep")); err == nil {
		time.Sleep(time.Duration(ms) * time.Millisecond)
		if mark := q.Get("mark"); mark != "" {
			os.WriteFile(mark, nil, 0644)
		}
	}
	n, _ := io.Copy(io.Discard, os.Stdin)
	fmt.Print("Content-Type: text/plain\r\n\r\n")
	keys := []string{"QUERY_STRING", "REDIRECT_STATUS", "SCRIPT_FILENAME", "DOCUMENT_ROOT", "REQUEST_URI", "CONTENT_LENGTH", "HTTP_HOST", "PATH_INFO", "HTTP_COOKIE"}
	for _, k := range keys {
		fmt.Printf("%s=%s\n", k, os.Getenv(k))
	}
	env := os.Environ()
	sort.Strings(env)
	var names []string
	for _, e := range env {
		names = append(names, strings.SplitN(e, "=", 2)[0])
	}
	fmt.Printf("ENV_NAMES=%s\n", strings.Join(names, ","))
	fmt.Printf("BODY_BYTES=%d\n", n)
}
