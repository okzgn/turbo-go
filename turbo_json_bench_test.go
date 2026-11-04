package main

// O5: the JSON of the configuration ("sites", turbo.config) with 500 sites.

import (
	"strconv"
	"testing"
)

func BenchmarkSitesJSON500(b *testing.B) {
	initForTest(b)
	globalMutex.Lock()
	for i := 0; i < 500; i++ {
		site := "site-" + strconv.Itoa(i) + ".test"
		constructSiteWithoutIndex(site, "")
		constructSiteWithoutIndex(site, "www")
		customHeaders[site]["X-Site"] = site
	}
	globalMutex.Unlock()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		globalMutex.RLock()
		createDefaultConfig(false, true, false)
		createDefaultConfig(true, false, true)
		globalMutex.RUnlock()
	}
}
