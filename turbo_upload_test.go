package main

// T27 (N24): hardUpload validates every name before touching anything, writes
// into a separate folder and puts it in place of @ in one go, without bringing
// back a site deleted in the meantime.

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// hardUploadFiles uploads the given files (name -> content) to localhost.
func hardUploadFiles(t *testing.T, base, tok string, files [][2]string) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("b", "Admin") // The current password, in the body (T28)
	for _, file := range files {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="f"; filename="%s"`, file[0]))
		p, _ := w.CreatePart(h)
		p.Write([]byte(file[1]))
	}
	w.Close()
	return hardUploadBody(t, base, tok, w.FormDataContentType(), buf.Bytes())
}

func hardUploadBody(t *testing.T, base, tok, contentType string, body []byte) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", base+"/admin:inside:hardUpload?s=localhost&d=", bytes.NewReader(body))
	req.Host = "localhost"
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("ok", tok)
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res.StatusCode, string(b)
}

// siteEntries lists what is in the folder of the site localhost (not in @).
func siteEntries(dir string) []string {
	entries, _ := os.ReadDir(dir + "localhost")
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestN24_HardUploadAllInvalidKeepsContent(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	code, body := hardUploadFiles(t, base, tok, [][2]string{{"site/../outside.txt", "x"}, {"site/a/../../b.txt", "x"}})
	if code != 400 || !strings.Contains(body, "No valid file") {
		t.Errorf("all names invalid: %d %q; expected 400 \"No valid file\"", code, body)
	}
	if data, _ := os.ReadFile(dir + "localhost/@/index.html"); string(data) != "hello" {
		t.Errorf("@ changed: index.html = %q", data)
	}
	if names := siteEntries(dir); len(names) != 1 {
		t.Errorf("work folders are left in the site: %v", names)
	}
}

func TestN24_HardUploadMalformed(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	code, body := hardUploadBody(t, base, tok, "multipart/form-data; boundary=X", []byte("--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nunclosed"))
	if code != 400 {
		t.Errorf("malformed multipart: %d %q; expected 400", code, body)
	}
	if data, _ := os.ReadFile(dir + "localhost/@/index.html"); string(data) != "hello" {
		t.Errorf("@ changed: index.html = %q", data)
	}
}

func TestN24_HardUploadReplacesWhole(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	code, body := hardUploadFiles(t, base, tok, [][2]string{{"site/index.html", "new"}, {"site/css/a.css", "css"}, {"site/CON.txt", "x"}})
	if code != 200 || !strings.Contains(body, "CON.txt") {
		t.Fatalf("upload: %d %q", code, body)
	}
	if data, _ := os.ReadFile(dir + "localhost/@/index.html"); string(data) != "new" {
		t.Errorf("index.html = %q", data)
	}
	if data, _ := os.ReadFile(dir + "localhost/@/css/a.css"); string(data) != "css" {
		t.Errorf("css/a.css = %q", data)
	}
	if names := siteEntries(dir); len(names) != 1 {
		t.Errorf("work folders are left in the site: %v", names)
	}
}

// A site deleted during the upload doesn't come back.
func TestN24_HardUploadSiteDeletedMeanwhile(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	beforeUploadSwap = func() {
		os.RemoveAll(dir + "localhost/")
		deleteSite("localhost", "")
	}
	t.Cleanup(func() { beforeUploadSwap = func() {} })
	code, body := hardUploadFiles(t, base, tok, [][2]string{{"site/index.html", "new"}})
	if code == 200 {
		t.Errorf("upload to a deleted site: %d %q", code, body)
	}
	beforeUploadSwap = func() {}
	updateSettings(true)
	globalMutex.RLock()
	exists := siteExists("localhost", "")
	globalMutex.RUnlock()
	if exists || dirExists(dir+"localhost") {
		t.Error("the deleted site came back")
	}
}

// folderMark stands for a folder among file contents: no uploaded content has a NUL, which separates the
// fuzzing input.
const folderMark = "\x00"

// treeContents lists the files and folders under root (relative path -> content, or folderMark), leaving
// out the subtree skip. With fold, paths are taken in lower case, as a file system that ignores case sees them.
func treeContents(root, skip string, fold bool) map[string]string {
	contents := map[string]string{}
	filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || path == root {
			return nil
		}
		if filepath.ToSlash(path) == strings.TrimSuffix(skip, "/") {
			return filepath.SkipDir
		}
		relative, _ := filepath.Rel(root, path)
		relative = filepath.ToSlash(relative)
		if fold {
			relative = strings.ToLower(relative)
		}
		if entry.IsDir() {
			contents[relative] = folderMark
		} else {
			data, _ := os.ReadFile(path)
			contents[relative] = string(data)
		}
		return nil
	})
	return contents
}

// FuzzHardUpload: whatever the names and contents of an upload (pairs separated by NUL in the input), as the
// fork's multipart reader gives them, hardUpload answers 200 or 400 (413 for the size is the HTTP layer's),
// writes nothing outside @, and either @ holds exactly the accepted files (the last one of a repeated name) or
// it is left as it was.
func FuzzHardUpload(f *testing.F) {
	for _, seed := range []string{
		"site/index.html\x00new\x00site/css/a.css\x00css",
		"site/../outside.txt\x00x",
		"site/a\x00one\x00site/a/b\x00two",
		"site/a/b\x00one\x00site/a\x00two",
		"site/A.txt\x00one\x00site/a.txt\x00two",
		"site\\x\\y.txt\x00z\x00site/CON.txt\x00w",
		"x.txt\x00alone",
		"site/a<b.txt\x00x",
		"site/c:d\x00x\x00site/e.txt\x00y",
	} {
		f.Add([]byte(seed))
	}
	dir := initForTest(f)
	siteDir := dir + "localhost/"
	fold := runtime.GOOS == "windows" || runtime.GOOS == "darwin"
	f.Fuzz(func(t *testing.T, spec []byte) {
		parts := strings.Split(string(spec), "\x00")
		if len(parts) > 40 {
			return
		}
		os.RemoveAll(siteDir + publicDirName)
		os.MkdirAll(siteDir+publicDirName, 0755)
		os.WriteFile(siteDir+publicDirName+"/index.html", []byte("hello"), 0644)
		outside := treeContents(dir, siteDir+publicDirName, false)

		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		for i := 0; i < len(parts); i += 2 {
			part, err := writer.CreateFormFile("f", parts[i])
			if err != nil {
				return
			}
			if i+1 < len(parts) {
				io.WriteString(part, parts[i+1])
			}
		}
		writer.Close()
		request, err := customNetHttp.NewRequest("POST", "http://localhost/", bytes.NewReader(body.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", writer.FormDataContentType())
		if err := request.ParseMultipartForm(maxBodySize.Load()); err != nil || request.MultipartForm == nil || len(request.MultipartForm.File["f"]) == 0 {
			return // Not a form the panel would get to hardUpload
		}
		uploaded := request.MultipartForm.File["f"]
		expected := map[string]string{}
		var names []string
		for _, file := range uploaded {
			name := file.Filename
			if _, params, err := mime.ParseMediaType(file.Header.Get("Content-Disposition")); err == nil {
				name = params["filename"]
			}
			names = append(names, name)
			relative, ok := uploadedFilePath(name)
			if !ok {
				continue
			}
			if fold {
				relative = strings.ToLower(relative)
			}
			// A file where an earlier one made a folder, or inside an earlier file, is discarded (N79).
			if expected[relative] == folderMark {
				continue
			}
			var folders []string
			for folder := relative; strings.Contains(folder, "/"); {
				folder = folder[:strings.LastIndex(folder, "/")]
				folders = append(folders, folder)
			}
			conflict := false
			for _, folder := range folders {
				if content, exists := expected[folder]; exists && content != folderMark {
					conflict = true
				}
			}
			if conflict {
				continue
			}
			content, _ := file.Open()
			data, _ := io.ReadAll(content)
			content.Close()
			for _, folder := range folders { // Its folders, as the tree lists them
				expected[folder] = folderMark
			}
			expected[relative] = string(data)
		}

		code, message := hardUpload("localhost", "", siteDir, uploaded)
		if code != 200 && code != 400 {
			t.Errorf("upload of %q: %d %q; expected 200 or 400", names, code, message)
		}
		if after := treeContents(dir, siteDir+publicDirName, false); fmt.Sprint(after) != fmt.Sprint(outside) {
			t.Errorf("upload of %q: what is outside @ changed:\nbefore %v\nafter  %v", names, outside, after)
		}
		public := treeContents(siteDir+publicDirName, "", fold)
		switch {
		case code == 200 && fmt.Sprint(public) != fmt.Sprint(expected):
			t.Errorf("upload of %q: 200 %q, but @ has %v; expected %v", names, message, public, expected)
		case code != 200 && fmt.Sprint(public) != fmt.Sprint(map[string]string{"index.html": "hello"}):
			t.Errorf("upload of %q: %d %q, but @ changed: %v", names, code, message, public)
		}
	})
}

// N80: the characters Windows doesn't allow in a name (<, >, ", |, ?, * and control characters) are discarded
// from an upload on every system, like the other names Windows treats specially, so the site can be moved; on
// Windows they made the whole upload fail with 500.
func TestN80_UploadNamesWindowsRefuses(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("b", "Admin")
	for _, name := range []string{"site/good.txt", "site/a<b.txt", "site/c>d.txt", `site/e"f.txt`, "site/g|h.txt", "site/i?j.txt", "site/k*l.txt", "site/p<q/r.txt"} {
		part, _ := w.CreateFormFile("f", name) // Quotes escaped, as browsers send them
		part.Write([]byte(map[bool]string{true: "yes", false: "no"}[name == "site/good.txt"]))
	}
	w.Close()
	code, body := hardUploadBody(t, base, tok, w.FormDataContentType(), buf.Bytes())
	if code != 200 {
		t.Fatalf("upload: %d %q; expected 200 with the names discarded", code, body)
	}
	if data, _ := os.ReadFile(dir + "localhost/@/good.txt"); string(data) != "yes" {
		t.Errorf("good.txt = %q", data)
	}
	if entries, _ := os.ReadDir(dir + "localhost/@"); len(entries) != 1 {
		t.Errorf("@ has %d entries; expected only good.txt", len(entries))
	}
	for _, name := range []string{"a<b.txt", "i?j.txt", "p<q/r.txt"} {
		if !strings.Contains(body, name) {
			t.Errorf("the response %q doesn't list %q as discarded", body, name)
		}
	}
}

// N79: a file and a folder with the same name can't both be uploaded: the later one is discarded and listed, as
// other names that can't be written are (before, the whole upload failed with 500).
func TestN79_UploadFileAndFolderSameName(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	code, body := hardUploadFiles(t, base, tok, [][2]string{{"site/a", "one"}, {"site/a/b", "two"}, {"site/c/d", "three"}, {"site/c", "four"}, {"site/e.txt", "five"}})
	if code != 200 {
		t.Fatalf("upload: %d %q; expected 200 with the conflicting names discarded", code, body)
	}
	for name, want := range map[string]string{"a": "one", "c/d": "three", "e.txt": "five"} {
		if data, err := os.ReadFile(dir + "localhost/@/" + name); err != nil || string(data) != want {
			t.Errorf("%s = %q %v; expected %q", name, data, err, want)
		}
	}
	if !strings.Contains(body, "site/a/b") || !strings.Contains(body, "site/c,") && !strings.HasSuffix(body, "site/c") {
		t.Errorf("the response %q doesn't list site/a/b and site/c as discarded", body)
	}
}

// N82: a name with a segment longer than 255 bytes (what ext4 and NTFS allow) or longer than 1,024 bytes in all
// is discarded and listed, as other names that can't be written are (before, the whole upload failed with 500).
func TestN82_UploadNamesTooLong(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	longest := strings.Repeat("s", 255)
	tooLong := strings.Repeat("l", 256)
	deep := strings.Repeat(strings.Repeat("p", 200)+"/", 6) + "x.txt" // 1 211 bytes
	code, body := hardUploadFiles(t, base, tok, [][2]string{{"site/" + longest, "fits"}, {"site/" + tooLong, "no"}, {"site/" + deep, "no"}, {"site/good.txt", "yes"}})
	if code != 200 {
		t.Fatalf("upload: %d %q; expected 200 with the long names discarded", code, body)
	}
	for name, want := range map[string]string{longest: "fits", "good.txt": "yes"} {
		if data, err := os.ReadFile(dir + "localhost/@/" + name); err != nil || string(data) != want {
			t.Errorf("%.20s… = %q %v; expected %q", name, data, err, want)
		}
	}
	if !strings.Contains(body, tooLong) || !strings.Contains(body, deep) {
		t.Errorf("the response doesn't list the names that are too long as discarded: %.200q", body)
	}
}

// N93: a site whose @ is missing while checkSites looks at the disk, but is back before it deactivates the site
// (hardUpload swaps @ with two renames, holding the lock), stays active with its settings. Before, it was
// deactivated, and the next scan of the disk brought it back with the defaults: without its preprocessor, its
// scripts were served as text.
func TestN93_SiteBackBeforeDeactivationStays(t *testing.T) {
	dir := initForTest(t)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	if err := os.Rename(dir+"localhost/@", dir+"localhost/@.away"); err != nil {
		t.Fatal(err)
	}
	beforeMissingSitesDeleted = func() { os.Rename(dir+"localhost/@.away", dir+"localhost/@") }
	t.Cleanup(func() { beforeMissingSitesDeleted = func() {} })
	checkSites()
	globalMutex.RLock()
	exists := siteExists("localhost", "")
	preprocessor := preprocessors["localhost"]["cgi"]
	globalMutex.RUnlock()
	if !exists || preprocessor == "" {
		t.Errorf("site with its @ back before it is deactivated: active %v, preprocessor %q; expected it to keep its preprocessor", exists, preprocessor)
	}
}
