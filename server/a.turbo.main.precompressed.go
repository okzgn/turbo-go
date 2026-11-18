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

package server

// Precompressed files: a site with "Z" on answers the request of a file with file.br or file.gz, when one of them is
// there and the request accepts it.

import (
	"io"
	"mime"
	pathpkg "path"
	"strconv"
	"strings"

	"turbo/customNetHttp"
)

// acceptedEncodings returns which of the encodings of the precompressed files the request accepts, by its
// Accept-Encoding (RFC 9110, 12.5.3): "br" and "gzip", the one with the higher q first and br first if they have the
// same; "" for one it doesn't accept. An encoding is accepted with a q above 0, its own or else that of "*". Without
// the header, or with one that can't be read as it should be, none is: the file is served as it is.
func acceptedEncodings(header []string) (first string, second string) {
	const unlisted = -1
	brotli, gzip, others := unlisted, unlisted, unlisted
	for _, line := range header {
		for line != "" {
			var element string
			element, line, _ = strings.Cut(line, ",")
			coding, parameters, _ := strings.Cut(element, ";")
			var listed *int
			switch strings.ToLower(strings.TrimSpace(coding)) {
			case "br":
				listed = &brotli
			case "gzip":
				listed = &gzip
			case "*":
				listed = &others
			default:
				continue
			}
			if quality := qualityThousandths(parameters); *listed == unlisted || quality < *listed {
				*listed = quality // Listed twice: the lower one
			}
		}
	}
	if brotli == unlisted {
		brotli = max(others, 0)
	}
	if gzip == unlisted {
		gzip = max(others, 0)
	}
	switch {
	case brotli > 0 && gzip > brotli:
		return "gzip", "br"
	case brotli > 0 && gzip > 0:
		return "br", "gzip"
	case brotli > 0:
		return "br", ""
	case gzip > 0:
		return "gzip", ""
	}
	return "", ""
}

// qualityThousandths reads the parameter of an element of Accept-Encoding, "q=" and a number from 0 to 1 with up
// to three decimals, in thousandths: 1000 without a parameter, and 0, not accepted, for anything else.
func qualityThousandths(parameters string) int {
	parameters = strings.TrimSpace(parameters)
	if parameters == "" {
		return 1000
	}
	name, value, found := strings.Cut(parameters, "=")
	if name = strings.TrimSpace(name); !found || name != "q" && name != "Q" {
		return 0
	}
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 5 || value[0] != '0' && value[0] != '1' || len(value) > 1 && value[1] != '.' {
		return 0
	}
	quality, scale := int(value[0]-'0')*1000, 100
	for i := 2; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0
		}
		quality += int(value[i]-'0') * scale
		scale /= 10
	}
	if quality > 1000 {
		return 0
	}
	return quality
}

// precompressedSuffixes are the names of the precompressed files, by their encoding.
var precompressedSuffixes = map[string]string{"br": ".br", "gzip": ".gz"}

// servePrecompressed answers the request of the file opened, of a site with precompressed files on, with its
// file.br or file.gz, and reports whether it did; if not, the file is served as always. Every answer of the site
// for a file says that it depends on Accept-Encoding (Vary).
//
// The variant is served for a GET or a HEAD without Range (a range is of the file as it is) whose Accept-Encoding
// accepts it, when it is a regular file with content, opened through the same os.Root as the file. Its dates aren't
// compared with the file's: a deployment that writes the variant a moment before the file would turn it off, so
// whoever changes a file makes its variants again. Not for a site that runs "br" or "gz" with a preprocessor, nor
// when one of its headers already sets Content-Encoding or ETag, nor for a URL that ends in "/index.html", which
// has its own treatment. The answer has the type of the file, the length of the variant and an ETag of its own.
func (plan *servePlan) servePrecompressed(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, opened *openedFileFS, filePath string) bool {
	header := responseWriter.Header()
	if !headerListHas(header.Values("Vary"), "Accept-Encoding") {
		header.Add("Vary", "Accept-Encoding")
	}
	if request.Method != customNetHttp.MethodGet && request.Method != customNetHttp.MethodHead || request.Header.Get("Range") != "" {
		return false
	}
	if plan.preprocessors["br"] != "" || plan.preprocessors["gz"] != "" || header.Get("Content-Encoding") != "" || header.Get("Etag") != "" {
		return false
	}
	if strings.HasSuffix(request.URL.Path, "/index.html") || opened.file == nil {
		return false
	}
	first, second := acceptedEncodings(request.Header["Accept-Encoding"])
	for _, encoding := range [2]string{first, second} {
		if encoding == "" {
			break
		}
		variant, err := opened.root.Open(rootName(filePath) + precompressedSuffixes[encoding])
		if err != nil {
			continue
		}
		info, err := variant.Stat()
		content, canSeek := variant.(io.ReadSeeker)
		if err != nil || !canSeek || !info.Mode().IsRegular() || info.Size() == 0 {
			variant.Close() // #nosec G104 -- read-only file
			continue
		}
		name := pathpkg.Base(filePath)
		if header.Get(contentTypeHeader) == "" && mime.TypeByExtension(pathpkg.Ext(name)) == "" {
			// Neither the site nor its extension give the type: the one of what the file has, not of its variant
			var start [512]byte
			read, _ := io.ReadFull(opened.file, start[:]) // A shorter file: what it has
			header.Set(contentTypeHeader, customNetHttp.DetectContentType(start[:read]))
		}
		header.Set("Content-Encoding", encoding)
		header.Set("Etag", `"`+strconv.FormatInt(info.ModTime().UnixNano(), 36)+"-"+strconv.FormatInt(info.Size(), 36)+"-"+encoding+`"`)
		customNetHttp.ServeContent(&variantResponse{ResponseWriter: responseWriter, length: info.Size()}, request, name, info.ModTime(), content)
		variant.Close() // #nosec G104 -- read-only file
		return true
	}
	return false
}

// headerListHas reports whether one of the lines of a header that is a list has the element, whatever its case.
func headerListHas(lines []string, element string) bool {
	for _, line := range lines {
		for _, listed := range strings.Split(line, ",") {
			if listed = strings.TrimSpace(listed); strings.EqualFold(listed, element) || listed == "*" {
				return true
			}
		}
	}
	return false
}

// variantResponse is the response of a precompressed variant: ServeContent gives no Content-Length to a response
// with a Content-Encoding, in case something compresses it on its way, and this one is already compressed, so its
// length is set when the status is 200. It also doesn't offer ranges, which Turbo serves from the file as it is.
type variantResponse struct {
	customNetHttp.ResponseWriter
	length int64
}

func (response *variantResponse) WriteHeader(status int) {
	header := response.ResponseWriter.Header()
	header.Del("Accept-Ranges")
	if status == customNetHttp.StatusOK {
		header.Set("Content-Length", strconv.FormatInt(response.length, 10))
	}
	response.ResponseWriter.WriteHeader(status)
}

// ReadFrom lets the server copy the file as it does for any other (sendfile, where there is).
func (response *variantResponse) ReadFrom(source io.Reader) (int64, error) {
	if readerFrom, can := response.ResponseWriter.(io.ReaderFrom); can {
		return readerFrom.ReadFrom(source)
	}
	return io.Copy(struct{ io.Writer }{response.ResponseWriter}, source)
}

// Unwrap gives the response itself to what looks for it (ResponseController).
func (response *variantResponse) Unwrap() customNetHttp.ResponseWriter {
	return response.ResponseWriter
}
