package server

// Review of 6046dbe (R6), P-14: the current password of hardUpload goes before its files, and is checked before they
// are read.

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// uploadRequest is the start of a request of hardUpload, with the headers and the first parts of its body.
func uploadRequest(tok string, length int64, boundary string, parts string) string {
	return "POST /admin:inside:hardUpload?s=localhost&d= HTTP/1.1\r\nHost: localhost\r\nok: " + tok +
		"\r\nContent-Type: multipart/form-data; boundary=" + boundary + "\r\nContent-Length: " + strconv.FormatInt(length, 10) +
		"\r\nConnection: close\r\n\r\n" + parts
}

// R6 P-14: hardUpload checks the current password before it reads the files, which go after it. The whole body, up
// to MBB, was read into memory first, so with a wrong password a client still made Turbo read up to 100 MB.
func TestR6_P14_PasswordBeforeTheFiles(t *testing.T) {
	dir := initForTest(t)
	maxBodySize.Store(100 << 20)
	if ok, msg := setting("RT", "60s"); !ok { // The time to read a body: the answer has to come long before it
		t.Fatal(msg)
	}
	addr := strings.TrimPrefix(startServer(t), "http://")
	tok := login(t, "http://"+addr)
	const boundary = "b0undary"
	field := func(name, value string) string {
		return "--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + value + "\r\n"
	}
	fileHeader := "--" + boundary + "\r\nContent-Disposition: form-data; name=\"f\"; filename=\"big.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
	// A wrong password, and 50 MiB announced of which only 64 KiB are sent: the answer comes without the rest
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := field("s", "localhost") + field("b", "wrong-password") + fileHeader
	sent := time.Now()
	fmt.Fprint(conn, uploadRequest(tok, 50<<20, boundary, start))
	conn.Write(bytes.Repeat([]byte("x"), 64<<10))
	conn.SetReadDeadline(time.Now().Add(40 * time.Second))
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer before the rest of the body: %v", err)
	}
	body := new(strings.Builder)
	bufio.NewReader(res.Body).WriteTo(body)
	// Long before RT (60 s here): the answer came only when the time to read the body ran out. The margin is for the
	// check of the password itself, which is slow on purpose, and more so with the race detector.
	if res.StatusCode != 400 || !strings.Contains(body.String(), "Wrong current password") || time.Since(sent) > 20*time.Second {
		t.Errorf("a wrong password with the files still to come: %d %q after %v; expected 400 without waiting for them", res.StatusCode, body.String(), time.Since(sent))
	}
	// The password after the files: refused, without reading them
	small := fileHeader + "data\r\n" + field("b", "Admin") + "--" + boundary + "--\r\n"
	code, answer := hardUploadBody(t, "http://"+addr, tok, "multipart/form-data; boundary="+boundary, []byte(small))
	if code != 400 || !strings.Contains(answer, "must come before the files") {
		t.Errorf("the password after the files: %d %q", code, answer)
	}
	if fileExists(dir + "localhost/@/big.bin") {
		t.Error("a refused upload wrote its file")
	}
	// The fields before the password, and the password before the files: uploaded, as always
	ordered := field("s", "localhost") + field("d", "") + field("b", "Admin") + fileHeader + "uploaded\r\n" + "--" + boundary + "--\r\n"
	if code, answer := hardUploadBody(t, "http://"+addr, tok, "multipart/form-data; boundary="+boundary, []byte(ordered)); code != 200 {
		t.Errorf("an upload in order: %d %q", code, answer)
	}
	if data, _ := os.ReadFile(dir + "localhost/@/big.bin"); string(data) != "uploaded" {
		t.Errorf("the uploaded file: %q", data)
	}
	// Without a password at all
	none := fileHeader + "data\r\n" + "--" + boundary + "--\r\n"
	if code, answer := hardUploadBody(t, "http://"+addr, tok, "multipart/form-data; boundary="+boundary, []byte(none)); code != 400 || !strings.Contains(strings.ToLower(answer), "the current password (b)") {
		t.Errorf("without the password: %d %q", code, answer)
	}
}
