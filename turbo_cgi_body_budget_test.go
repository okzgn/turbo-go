package main

// R3-03 (production reviews of 2026-11-04): the request bodies of the CGIs were read whole into memory, up to 1 MiB
// each, before their CGI got a slot, and kept there while it waited for one and while it ran: with nothing that bounded
// how many there were, a burst of POSTs took the memory of the machine. Now all of them may take cgiBodyBudget in
// memory; the rest go to temporary files.

import (
	"bytes"
	"io"
	"testing"
)

// withBodyBudget lowers cgiBodyBudget for the test.
func withBodyBudget(t *testing.T, budget int64) {
	t.Helper()
	previous := cgiBodyBudget
	cgiBodyBudget = budget
	t.Cleanup(func() { cgiBodyBudget = previous })
}

// readBody reads a body that bufferedRequestBody kept, and says whether it is in a temporary file.
func readBody(t *testing.T, body io.ReadCloser) (content []byte, inFile bool) {
	t.Helper()
	_, inFile = body.(cgiFileBody)
	content, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	return content, inFile
}

func TestRP3_R303_BodiesWithinTheBudget(t *testing.T) {
	withBodyBudget(t, 64<<10)
	first := bytes.Repeat([]byte("a"), 48<<10)
	second := bytes.Repeat([]byte("b"), 48<<10)
	bodyA, sizeA, cleanupA, err := bufferedRequestBody(bytes.NewReader(first), int64(len(first)))
	if err != nil {
		t.Fatal(err)
	}
	if used := cgiBodyInUse.Load(); used != 48<<10+1 {
		t.Errorf("a body of 48 KiB, with its length: %d bytes counted in memory; expected 48 KiB and one", used)
	}
	bodyB, sizeB, cleanupB, err := bufferedRequestBody(bytes.NewReader(second), int64(len(second)))
	if err != nil {
		t.Fatal(err)
	}
	contentA, fileA := readBody(t, bodyA)
	contentB, fileB := readBody(t, bodyB)
	if fileA || !fileB {
		t.Errorf("two bodies of 48 KiB with a budget of 64 KiB: the first in a file %v, the second %v; expected the second in a file", fileA, fileB)
	}
	if !bytes.Equal(contentA, first) || !bytes.Equal(contentB, second) || sizeA != int64(len(first)) || sizeB != int64(len(second)) {
		t.Error("a body changed on the way")
	}
	cleanupA()
	cleanupB()
	if used := cgiBodyInUse.Load(); used != 0 {
		t.Errorf("after the requests: %d bytes counted in memory; expected none", used)
	}

	// Without a length, longer than the budget lets it have: in a file, and nothing counted once it is.
	third := bytes.Repeat([]byte("c"), 200<<10)
	bodyC, sizeC, cleanupC, err := bufferedRequestBody(bytes.NewReader(third), -1)
	if err != nil {
		t.Fatal(err)
	}
	if used := cgiBodyInUse.Load(); used != 0 {
		t.Errorf("a body in a file: %d bytes still counted in memory", used)
	}
	contentC, fileC := readBody(t, bodyC)
	if !fileC || !bytes.Equal(contentC, third) || sizeC != int64(len(third)) {
		t.Errorf("a body of 200 KiB without a length: in a file %v, intact %v; expected it whole in a file", fileC, bytes.Equal(contentC, third))
	}
	cleanupC()
}
