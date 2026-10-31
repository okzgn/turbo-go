package main

// O5: el JSON de la configuración ("sites", turbo.config) con 500 sitios.

import (
	"strconv"
	"testing"
)

func BenchmarkSitesJSON500(b *testing.B) {
	initForTest(b)
	globalMutex.Lock()
	for i := 0; i < 500; i++ {
		site := "sitio-" + strconv.Itoa(i) + ".test"
		_constructSite(site, "")
		_constructSite(site, "www")
		customHeaders[site]["X-Sitio"] = site
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
