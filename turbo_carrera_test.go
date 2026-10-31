package main

// A6 (H10): las acciones del panel no leen estado compartido sin el lock, ni
// siquiera mientras la recarga periódica da de alta sitios encontrados en disco.

import (
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

// panelLoops ejecuta, hasta que se cierre stop, acciones del panel que leen y
// escriben los mapas compartidos: alta y baja de sitios, de subdominios y de
// reemplazos de caracteres, y un ajuste (setRT) cuyos parámetros pasan por los
// reemplazos.
func panelLoops(base, tok string, stop chan struct{}, wg *sync.WaitGroup) {
	loops := []func(i int){
		func(i int) {
			site := "a6-" + strconv.Itoa(i%4) + ".test"
			post(base, "/admin:inside:addSite?s="+site, tok)
			post(base, "/admin:inside:delSite?s="+site+"&d=", tok)
		},
		func(i int) {
			sub := "s" + strconv.Itoa(i%4)
			post(base, "/admin:inside:addSubdomain?s=localhost&d="+sub, tok)
			post(base, "/admin:inside:delSite?s=localhost&d="+sub, tok)
		},
		func(i int) {
			post(base, "/admin:inside:addCharsReplace?"+url.Values{"s": {"!"}, "d": {"zz" + strconv.Itoa(i%9)}}.Encode(), tok)
			post(base, "/admin:inside:delCharsReplace?s=!", tok)
		},
		func(i int) {
			post(base, "/admin:inside:setRT?b=Admin&a="+strconv.Itoa(5+i%2)+"s", tok)
		},
	}
	for _, loop := range loops {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
					loop(i)
				}
			}
		}()
	}
}

// H10: cuatro clientes del panel dan de alta y de baja sitios, subdominios y
// reemplazos mientras la recarga periódica corre en bucle: sin -race no debe
// abortar ("concurrent map read and map write"), y con -race no debe avisar.
func TestA6_PanelActionsDuringReload(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	panelLoops(base, tok, stop, &wg)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		updateSettings(true)
	}
	close(stop)
	wg.Wait()
}
