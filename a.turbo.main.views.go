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

// The global lock counts its write locks, and what is made from the state of a site for its requests (what it serves
// them with, its rewrites whatever their capitals) is kept from one to the next.

import (
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"
)

// stateLock is the lock of the shared state (globalMutex): a sync.RWMutex that counts the times it is locked for
// writing. The count, its generation, is odd while it is write-locked and is another one after each write lock: what
// was read from the state under a read lock is still what the state says while the generation is the one it was
// read at. Nothing has to tell it that the state changed, so nothing can forget to.
type stateLock struct {
	sync.RWMutex
	generation atomic.Uint64
}

func (lock *stateLock) Lock() {
	lock.RWMutex.Lock()
	lock.generation.Add(1)
}

func (lock *stateLock) TryLock() bool {
	if !lock.RWMutex.TryLock() {
		return false
	}
	lock.generation.Add(1)
	return true
}

// Unlock counts before it releases the lock: no reader gets the changed state with the generation of before.
func (lock *stateLock) Unlock() {
	lock.generation.Add(1)
	lock.RWMutex.Unlock()
}

// siteView is what a site serves its requests with, copied from the shared state: its MIME types, its preprocessors
// and its headers (nil for none), its indexes in the order they are tried, and whether it has precompressed files
// on. Nothing changes one once it is made: the plans of the requests of the site share it, and use it without the
// lock.
type siteView struct {
	mimeTypes     map[string]string
	preprocessors map[string]string
	headers       map[string]string
	indexes       []string
	precompressed bool
}

// newSiteView copies what the site of siteKey ("sub.example.com", or "example.com" for the domain) serves with.
// Callers hold the global lock.
func newSiteView(siteKey string) *siteView {
	view := &siteView{
		mimeTypes:     cloneOrNil(mimeTypes[siteKey]),
		preprocessors: cloneOrNil(preprocessors[siteKey]),
		headers:       cloneOrNil(customHeaders[siteKey]),
		precompressed: settingsOf(siteKey).precompressed,
	}
	if len(indexFiles[siteKey]) > 0 {
		view.indexes = orderedIndexes(siteKey)
	}
	return view
}

// siteViews is what was made from the state of the sites since the last write lock, the one that left generation:
// the views by the key of their settings, and the folded rewrites by their site in sitesMap. As many as the sites
// have at most: never by the Host of a request.
type siteViews struct {
	generation     uint64
	bySiteKey      sync.Map // string → *siteView
	foldedRewrites sync.Map // rewriteSite → map[string]string
}

// rewriteSite names the rewrites of a site as sitesMap has them: by its domain and its subdomain there.
type rewriteSite struct{ domain, subdomain string }

var keptSiteViews atomic.Pointer[siteViews]

// keptViewCheck, when set, gets everything taken from what is kept, and how to make it anew from the state (for the
// tests, which compare them). It runs with the lock of the caller.
var keptViewCheck func(name string, kept any, fresh func() any)

// viewsKept returns where what is made from the state is kept until the next write lock, or nil for a caller that
// has the write lock, who may be changing the state: nothing of it is kept. Callers hold the global lock.
func viewsKept() *siteViews {
	generation := globalMutex.generation.Load()
	if generation&1 == 1 {
		return nil
	}
	kept := keptSiteViews.Load()
	if kept == nil || kept.generation != generation {
		// The first reader after a write lock leaves what was kept before; those that hold the read lock with it are
		// of its generation, and take what it left
		fresh := &siteViews{generation: generation}
		if keptSiteViews.CompareAndSwap(kept, fresh) {
			return fresh
		}
		if kept = keptSiteViews.Load(); kept.generation != generation {
			return nil
		}
	}
	return kept
}

// siteViewOf returns the view of the site of siteKey: the one kept since the last write lock, made by the first
// request that asks for it. Before, each request copied the three maps of its site and sorted its indexes. Callers
// hold the global lock, for reading or for writing.
func siteViewOf(siteKey string) *siteView {
	kept := viewsKept()
	if kept == nil {
		return newSiteView(siteKey)
	}
	if view, found := kept.bySiteKey.Load(siteKey); found {
		if keptViewCheck != nil {
			keptViewCheck("the view of "+siteKey, view, func() any { return newSiteView(siteKey) })
		}
		return view.(*siteView)
	}
	view, _ := kept.bySiteKey.LoadOrStore(siteKey, newSiteView(siteKey))
	return view.(*siteView)
}

// foldKey returns s as strings.EqualFold compares it: two texts have the same foldKey exactly when EqualFold takes
// them for equal. Each character becomes the one that stands for all those EqualFold takes for it (foldRune), and
// what isn't UTF-8 becomes U+FFFD, as EqualFold reads it. ASCII without capitals, as most paths are, is returned as it
// is.
func foldKey(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= utf8.RuneSelf || 'A' <= c && c <= 'Z' {
			var folded strings.Builder
			folded.Grow(len(s))
			folded.WriteString(s[:i])
			for _, r := range s[i:] {
				folded.WriteRune(foldRune(r))
			}
			return folded.String()
		}
	}
	return s
}

// foldRune returns the character that stands for r and for those that differ from it only in case: the ASCII
// lower-case letter among them, or else the first of them.
func foldRune(r rune) rune {
	if r < utf8.RuneSelf { // Most: without asking for those of each
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}
	first := r
	for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
		first = min(first, next)
	}
	if 'A' <= first && first <= 'Z' {
		return first + 'a' - 'A'
	}
	return first
}

// newFoldedRewrites returns, by foldKey, the rewrite that a path takes where names fold when none is written as it
// is: of those that differ only in case, the first in byte order.
func newFoldedRewrites(rewrites map[string]string) map[string]string {
	folded := make(map[string]string, len(rewrites))
	for candidate := range rewrites {
		key := foldKey(candidate)
		if current, taken := folded[key]; !taken || candidate < current {
			folded[key] = candidate
		}
	}
	return folded
}

// foldedRewritesOf returns the rewrites of a site by foldKey (newFoldedRewrites): those kept since the last write
// lock, made by the first request that needs them. Before, each lookup compared the path with every rewrite of the
// site, and a request makes several. Callers hold the global lock, for reading or for writing.
func foldedRewritesOf(domain string, subdomain string) map[string]string {
	kept := viewsKept()
	if kept == nil {
		return newFoldedRewrites(sitesMap[domain][subdomain])
	}
	site := rewriteSite{domain, subdomain}
	if folded, found := kept.foldedRewrites.Load(site); found {
		if keptViewCheck != nil {
			keptViewCheck("the folded rewrites of "+subdomain+"/"+domain, folded, func() any { return newFoldedRewrites(sitesMap[domain][subdomain]) })
		}
		return folded.(map[string]string)
	}
	folded, _ := kept.foldedRewrites.LoadOrStore(site, newFoldedRewrites(sitesMap[domain][subdomain]))
	return folded.(map[string]string)
}
