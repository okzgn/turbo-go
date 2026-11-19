// Echo worker of the protocol DX 3 (the mode dx of the preprocessors): it greets with "DX3\n", and answers each request
// with the pairs it got, one "NAME=value" line each, and BODY_LENGTH, after the id of the request. Its behavior for a
// request comes from the query (the pair QUERY_STRING): pid=1 adds PID=<its process ID>; sleep=<ms> waits before
// answering; status=<code> answers with that status; empty=1 without a body; header=<Name: value> (repeatable) adds
// that header; chunks=<n>&size=<bytes> answers n chunks of that many bytes, pause=<ms> apart; echo=body answers the body itself;
// die=before ends before the answer, die=after in the middle of it; exit=after ends after a whole answer, and closein=1
// closes its input after one; garbage=1 answers what isn't the protocol; extra=1 writes bytes after the end of its
// answer; late=1 writes, 50 ms after its answer, a whole second answer with the same id and the body LATE; badid=1
// answers with an id that isn't the request's; stderr=<n> writes n lines to its standard error.
// Its behavior when it starts comes from the name of its executable: with "nogreet" it never greets, with "badgreet"
// it greets wrong, with "greetplus" it writes a whole answer right after its greeting, with "slowgreet" it greets after
// 2.5 s, with "crash" it ends at once, and with "stubborn" it goes on 60 s after its input closes.
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	name := strings.ToLower(filepath.Base(os.Args[0]))
	switch {
	case strings.Contains(name, "crash"):
		os.Exit(1)
	case strings.Contains(name, "nogreet"):
		io.Copy(io.Discard, os.Stdin)
		return
	case strings.Contains(name, "slowgreet"):
		time.Sleep(2500 * time.Millisecond)
	}
	out := bufio.NewWriter(os.Stdout)
	if strings.Contains(name, "badgreet") {
		out.WriteString("DX9\n")
	} else {
		out.WriteString("DX3\n")
	}
	if strings.Contains(name, "greetplus") { // A whole answer, before any request
		out.Write(make([]byte, 8))
		out.Write(head(200, nil))
		out.Write(u32(4))
		out.WriteString("FAKE")
		out.Write(u32(0))
	}
	out.Flush()
	in := bufio.NewReader(os.Stdin)
	for {
		id, pairs, body, err := readRequest(in)
		if err != nil { // The input closed: Turbo let go of the worker
			if strings.Contains(name, "stubborn") {
				time.Sleep(60 * time.Second)
			}
			return
		}
		answer(out, id, pairs, body)
	}
}

func readRequest(in *bufio.Reader) ([]byte, [][2]string, []byte, error) {
	id := make([]byte, 8)
	if _, err := io.ReadFull(in, id); err != nil {
		return nil, nil, nil, err
	}
	size, err := readU32(in)
	if err != nil {
		return nil, nil, nil, err
	}
	block := make([]byte, size)
	if _, err := io.ReadFull(in, block); err != nil {
		return nil, nil, nil, err
	}
	count := binary.LittleEndian.Uint32(block)
	rest := block[4:]
	pairs := make([][2]string, 0, count)
	length := 0
	for i := uint32(0); i < count; i++ {
		var pair [2]string
		for j := range pair {
			n := binary.LittleEndian.Uint32(rest)
			pair[j] = string(rest[4 : 4+n])
			rest = rest[4+n:]
		}
		if pair[0] == "CONTENT_LENGTH" {
			length, _ = strconv.Atoi(pair[1])
		}
		pairs = append(pairs, pair)
	}
	body := make([]byte, length)
	_, err = io.ReadFull(in, body)
	return id, pairs, body, err
}

func readU32(in io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(in, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func u32(n int) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(n))
	return b[:]
}

// head is the head of an answer: its status and headers, after their size.
func head(status int, headers [][2]string) []byte {
	var head []byte
	head = append(head, u32(status)...)
	head = append(head, u32(len(headers))...)
	for _, header := range headers {
		head = append(head, u32(len(header[0]))...)
		head = append(head, header[0]...)
		head = append(head, u32(len(header[1]))...)
		head = append(head, header[1]...)
	}
	return append(u32(len(head)), head...)
}

func answer(out *bufio.Writer, id []byte, pairs [][2]string, body []byte) {
	query := url.Values{}
	for _, pair := range pairs {
		if pair[0] == "QUERY_STRING" {
			query, _ = url.ParseQuery(pair[1])
		}
	}
	if ms, err := strconv.Atoi(query.Get("sleep")); err == nil {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
	if n, err := strconv.Atoi(query.Get("stderr")); err == nil { // Lines on the standard error
		for i := 0; i < n; i++ {
			fmt.Fprintf(os.Stderr, "dxecho: a line %d of the standard error\n", i)
		}
	}
	if query.Get("die") == "before" {
		os.Exit(3)
	}
	if query.Get("badid") == "1" {
		other := append([]byte(nil), id...)
		other[0]++
		id = other
	}
	out.Write(id)
	if query.Get("garbage") == "1" {
		out.Write(u32(1 << 30))
		out.WriteString("not the protocol")
		out.Flush()
		return
	}
	status := 200
	if code, err := strconv.Atoi(query.Get("status")); err == nil {
		status = code
	}
	headers := [][2]string{{"Content-Type", "text/plain; charset=utf-8"}}
	for _, line := range query["header"] {
		if name, value, found := strings.Cut(line, ":"); found {
			headers = append(headers, [2]string{strings.TrimSpace(name), strings.TrimSpace(value)})
		}
	}
	out.Write(head(status, headers))
	chunk := func(b []byte) { // In chunks of 1 MiB at most, as the protocol says
		for len(b) > 0 {
			n := min(len(b), 1<<20)
			out.Write(u32(n))
			out.Write(b[:n])
			b = b[n:]
		}
	}
	switch {
	case query.Get("empty") == "1":
	case query.Get("echo") == "body":
		chunk(body)
	case query.Get("chunks") != "":
		n, _ := strconv.Atoi(query.Get("chunks"))
		size, _ := strconv.Atoi(query.Get("size"))
		pause, _ := strconv.Atoi(query.Get("pause"))
		for i := 0; i < n; i++ {
			if i > 0 && pause > 0 { // An answer that stops after it started
				time.Sleep(time.Duration(pause) * time.Millisecond)
			}
			chunk([]byte(strings.Repeat("x", size)))
			out.Flush()
		}
	default:
		var text strings.Builder
		for _, pair := range pairs {
			text.WriteString(pair[0] + "=" + pair[1] + "\n")
		}
		text.WriteString("BODY_LENGTH=" + strconv.Itoa(len(body)) + "\n")
		if query.Get("pid") == "1" {
			text.WriteString("PID=" + strconv.Itoa(os.Getpid()) + "\n")
		}
		chunk([]byte(text.String()))
	}
	if query.Get("die") == "after" {
		out.Flush()
		os.Exit(3)
	}
	out.Write(u32(0))
	if query.Get("exit") == "after" { // A whole answer, and the worker ends, as one that ends after some requests
		out.Flush()
		os.Exit(0)
	}
	if query.Get("closein") == "1" { // A whole answer, and its input closed: the next request can't be written to it
		out.Flush()
		os.Stdin.Close()
		time.Sleep(time.Minute)
	}
	if query.Get("extra") == "1" {
		out.Write(u32(7))
		out.WriteString("leftover")
	}
	out.Flush()
	if query.Get("late") == "1" { // A second answer, as a script that writes after its own could
		time.Sleep(50 * time.Millisecond)
		out.Write(id)
		out.Write(head(200, [][2]string{{"Content-Type", "text/plain; charset=utf-8"}}))
		chunk([]byte("LATE"))
		out.Write(u32(0))
		out.Flush()
	}
}
