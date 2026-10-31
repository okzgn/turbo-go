# customNetHttp: `net/http` de Go con los parches de Turbo

`customNetHttp` es el código de `net/http` de la versión de Go que indica [`UPSTREAM`](UPSTREAM), fusionado en un solo paquete y con los parches de Turbo. Existe porque varias personalizaciones de Turbo solo se pueden hacer dentro de `net/http`: por ejemplo, la respuesta a una petición mal formada se escribe antes de llegar a ningún manejador y la biblioteca estándar no permite cambiarla.

## Qué contiene

| Archivos | Origen (en `GOROOT/src`) |
|---|---|
| `1.net.http.*.go` | `net/http`, `net/http/internal`, `net/http/internal/ascii`, `net/http/internal/httpcommon` |
| `a.server.cgi.host.go` | `net/http/cgi/host.go` (`cgi.Handler` pasa a llamarse `CgiHandler`) |
| `c.mime.*.go` | `mime/multipart` |
| `x.net.http2.hpack.*.go`, `z.x.net.*.go`, `y.x.text.*.go` | `vendor/golang.org/x/net` (`http2/hpack`, `http/httpguts`, `http/httpproxy`, `idna`) y `vendor/golang.org/x/text` (lo que necesita `idna`) |
| `0.turbo.shared.globals.go` | Propio: lo que Turbo comparte con el servidor (`TurboTimeLimits`, `TurboErrorTemplates`, `TurboMaxURILength`, `TurboMaxHeaderBytes`, `TurboMaxBodySize`, `TurboMaxFormParts`, `TurboMaxFormHeaders`, `TurboServerName`) |
| `0.turbo.parches.go` | Propio: funciones a las que llaman los parches |
| `0.turbo.godebug.go` | Propio: sustituto de `internal/godebug` (no lee `GODEBUG`; cada ajuste vale `""`, el valor por defecto de Go con `go 1.26` en `go.mod`) |

Los archivos que empiezan por `0.` son de Turbo; todos los demás `*.go` los genera [`regenerar`](regenerar/main.go) y no se editan a mano: un cambio en ellos es un parche.

Dos manifiestos (`<sha256>  <archivo>`, como `sha256sum`) fijan lo que no regenera la herramienta:

- [`PROPIOS.sha256`](PROPIOS.sha256): los archivos `0.*.go`. `regenerar` lo reescribe cuando regenera en esta carpeta; `-comprobar` falla si hay un `0.*.go` que no está en la lista o que ha cambiado, así que cualquier cambio en ellos aparece en el diff de este archivo.
- [`FUENTES.sha256`](FUENTES.sha256): cada archivo de Go del que se regenera, por su ruta bajo `GOROOT/src`. Lo escribe `-actualizar`; en el resto de modos, si el `GOROOT` no coincide con él, la herramienta se detiene. El de go1.26.10 se contrastó con el tag `go1.26.10` del repositorio de Go.

## Regenerar

Desde la raíz del repositorio, con la versión de Go de `UPSTREAM` (la herramienta lee el `GOROOT` con el que se ejecuta):

```bash
go run ./customNetHttp/regenerar -comprobar   # customNetHttp == Go de UPSTREAM + parches (lo usan release.sh y las comprobaciones del README)
go run ./customNetHttp/regenerar              # reescribe los archivos generados
```

La herramienta:

1. Copia los archivos de los paquetes de la tabla (sin pruebas; solo los que se compilan en todos los sistemas, y falla si la selección cambia de un sistema a otro).
2. Los fusiona en el paquete `customNetHttp`: comprueba los tipos de cada paquete con `go/types`, quita los calificadores entre ellos (`hpack.NewEncoder` → `NewEncoder`) y las importaciones correspondientes, y si un nombre de nivel de paquete choca con otro paquete, con un nombre propio de Turbo, con un paquete importado o con un identificador predeclarado, lo renombra a `<paquete>_<nombre>` (`multipart.Reader` → `multipart_Reader`). `net/http` conserva siempre sus nombres. `godebug.X` pasa a `godebug_X`. Cada archivo empieza con una línea `// Origen: …` que dice de dónde sale.
3. Aplica `patches/*.patch` en orden. Cada fragmento debe coincidir exactamente (solo se admite un desplazamiento de líneas, nunca contexto aproximado) y en un solo sitio del archivo; si alguno no aplica o coincide en más de un sitio, se detiene y dice cuál.

### Actualizar a otra versión de Go

Cuando una versión de Go corrige `net/http`, `mime/multipart` o `x/net/http2`:

```bash
go1.26.N run ./customNetHttp/regenerar -actualizar
```

Regenera con esa versión, aplica los parches y escribe la versión en `UPSTREAM` y los hashes de sus fuentes en `FUENTES.sha256`. Antes, contraste esas fuentes con las oficiales (el tag de la versión en el repositorio de Go, o el `go1.26.N.src.tar.gz` de go.dev con su SHA-256 publicado). Si un parche no aplica, hay que rehacerlo (ver abajo) sobre la base nueva. Después: `go build ./...`, `go vet ./...` y la batería completa, incluida `turbo_parches_test.go`.

### Cambiar o añadir un parche

Los parches son diffs unificados de los archivos de `customNetHttp` (rutas `a/<archivo>` y `b/<archivo>`, relativas a esa carpeta), uno por personalización, y se aplican en orden. `-parches N` aplica solo los N primeros. Para cambiar, por ejemplo, el parche 06:

```bash
go run ./customNetHttp/regenerar -parches 5 -salida /tmp/base    # base con los parches 01-05
go run ./customNetHttp/regenerar -parches 6 -salida /tmp/nuevo   # editar aquí el resultado
cd /tmp && git diff --no-index base nuevo -- '*.go'              # nuevo 06: cambiar las rutas a/base/ y b/nuevo/ por a/ y b/
```

Los parches posteriores deben seguir aplicando; si no, se rehacen igual.

Con un repositorio limpio basta con editar los archivos generados y guardar `git diff --relative=customNetHttp -- ':(glob)customNetHttp/[1-9a-z]*.go'` como parche nuevo al final. Cada cambio en el código de Go lleva un comentario `turbo:Pn`; lo que se pueda escribir fuera del código de Go va en `0.turbo.parches.go`. Los archivos parcheados deben quedar como los deja `gofmt` (regenerar falla si no) y `regenerar -comprobar` debe terminar sin diferencias.

## Parches

Cada parche cita sus pruebas con el archivo en el que están (en la raíz del repositorio).

### P1. Errores previos al manejador en HTTP/1 con la plantilla de Turbo

- **Qué hace:** las respuestas que `conn.serve` escribe antes de llegar a ningún manejador (400 de petición mal formada o de `statusError`, 431, 501 por `Transfer-Encoding` desconocido; y el 414 de P3) usan la plantilla de error de Turbo (`TurboErrorTemplates`) y llevan `Server`, `X-Content-Type-Options: nosniff` y `Connection: close`.
- **Dónde:** `1.net.http.server.go`, `(*conn).serve`; `turboErrorConexion` y `turboPlantillaError` en `0.turbo.parches.go`.
- **Motivo:** las respuestas de error de Turbo usan una plantilla configurable desde el panel; Go escribe un texto fijo que no se puede cambiar desde fuera.
- **Parche:** `patches/01-P1-errores-http1.patch`. **Prueba:** `TestT21_P1_ErroresHTTP1` (`turbo_parches_test.go`).

### P2. 431 de HTTP/2 con la plantilla

- **Qué hace:** `http2handleHeaderListTooLong` responde con la plantilla (`turboEscribirError`) en lugar del HTML fijo de Go.
- **Dónde:** `1.net.http.h2_bundle.go`; `turboEscribirError` en `0.turbo.parches.go`.
- **Motivo:** el de P1, en HTTP/2.
- **Parche:** `patches/02-P2-errores-http2.patch`. **Prueba:** `TestT21_P2_LimitesHTTP2` (`turbo_parches_test.go`).

### P3. Límite de longitud de la URI (`TurboMaxURILength`, ajuste `MUB`)

- **Qué hace:** en HTTP/1, `readRequest` devuelve `errTurboURILarga` en cuanto lee la línea de petición si la URI supera `TurboMaxURILength`, y `conn.serve` responde 414 con la plantilla. En HTTP/2, `processHeaders` sustituye el manejador por un 414 con la plantilla si `:path` supera `TurboMaxURILength` (un 431 por cabeceras truncadas tiene prioridad).
- **Dónde:** `1.net.http.request.go` (`readRequest`), `1.net.http.server.go` (`(*conn).serve`), `1.net.http.h2_bundle.go` (`(*http2serverConn).processHeaders`); `turboErrorManejador` y `errTurboURILarga` en `0.turbo.parches.go`.
- **Motivo:** Go no limita la URI por separado.
- **Parche:** `patches/03-P3-limite-uri.patch`. **Pruebas:** `TestT21_P1_ErroresHTTP1` (`turbo_parches_test.go`), `TestT21_P2_LimitesHTTP2` (`turbo_parches_test.go`), `TestP25_LimitsValueCopy` (`turbo_limites_test.go`).

### P4. Tamaño máximo de cabeceras de HTTP/1 exacto (`TurboMaxHeaderBytes`, ajuste `MHB`)

- **Qué hace:** `(*Server).maxHeaderBytes` devuelve `TurboMaxHeaderBytes`, leído una vez por petición (`conn.turboReadLimit`, que usa también la comprobación de `StateActive`), sin mirar `Server.MaxHeaderBytes`; `initialReadLimitSize` no suma los 4096 bytes de margen de Go.
- **Dónde:** `1.net.http.server.go`.
- **Motivo:** que `MHB` sea el número exacto de bytes de la cabecera y se aplique sin reiniciar.
- **Parche:** `patches/04-P4-cabeceras-http1.patch`. **Pruebas:** `TestT21_P1_ErroresHTTP1` (`turbo_parches_test.go`), `TestP25_LimitsValueCopy` (`turbo_limites_test.go`).

### P5. Límites de cabeceras de HTTP/2 (`TurboMaxHeaderBytes`)

- **Qué hace:** `readMetaFrame` limita la lista de cabeceras a `TurboMaxHeaderBytes`, contada como en Go y en HTTP/2 (nombre y valor más 32 bytes por campo, `HeaderField.Size`; así una lista de muchos campos pequeños no cabe en el mismo presupuesto que en HTTP/1), y cada campo HPACK a `TurboMaxHeaderBytes` (`SetMaxStringLength`), leído una vez por bloque de cabeceras. Conserva el presupuesto aparte de Go para `Trailer`, también con `TurboMaxHeaderBytes`. En `SETTINGS_MAX_HEADER_LIST_SIZE` el servidor anuncia ese mismo límite, `TurboMaxHeaderBytes` (`http2turboMaxHeaderBytes`), sin el margen de `http2adjustHTTP1MaxHeaderSize`: como ya se cuenta en unidades de HTTP/2, un cliente que respeta lo anunciado no recibe 431.
- **Dónde:** `1.net.http.h2_bundle.go`: `(*http2Framer).readMetaFrame`, `(*http2serverConn).maxHeaderListSize`. (El fork anterior modificaba además `hpack.go`; ya no hace falta.)
- **Motivo:** el mismo límite que en HTTP/1, aplicable sin reiniciar.
- **Parche:** `patches/05-P5-cabeceras-http2.patch`. **Pruebas:** `TestT21_P2_LimitesHTTP2` (`turbo_parches_test.go`), `TestC6_HTTP2FieldOverhead`, `TestH54_HTTP2AnnouncedHeaderLimit` (`turbo_parches_test.go`).

### P6. Timeouts (`RT`, `RHT`, `WT`, `IT`) leídos en cada conexión

- **Qué hace:** los plazos de HTTP/1 y HTTP/2 salen de `TurboTimeLimits` (`atomic.Pointer[Timeouts]`) en cada conexión, petición o stream, no de los campos de `Server`, para que un cambio en el panel se aplique sin reiniciar. 0 es sin límite, salvo en `RHT` e `IT`, que con 0 usan `RT`, como Go con `ReadHeaderTimeout` e `IdleTimeout` (`turboIdleTimeout` en `0.turbo.parches.go`). En HTTP/2, si `IT` se activa con la conexión abierta, el temporizador de inactividad se crea al cerrar el último stream.
- **Dónde:** `1.net.http.server.go`: `tlsHandshakeTimeout`, `(*conn).readRequest`, `idleTimeout`, `readHeaderTimeout`. `1.net.http.h2_bundle.go`: `(*http2Server).serveConn`, `(*http2serverConn).serve`, `closeStream`, `processHeaders`, `upgradeRequest`, `newStream`.
- **Motivo:** que los ajustes del panel se apliquen en caliente, sin reiniciar el servidor.
- **Parche:** `patches/06-P6-timeouts.patch`. **Pruebas:** `TestT21_P6_TimeoutsHTTP1` (`turbo_parches_test.go`), `TestB4_ZeroTimeoutsUseRT` (`turbo_parches_test.go`), `TestT04_HTTP2IdleTimeoutEnabledLater` (`turbo_fork_test.go`).

### P7. No vaciar el cuerpo sin leer

- **Qué hace:** `maxPostHandlerReadBytes = 0`, y el cuerpo se considera demasiado grande solo si quedan más bytes sin leer que ese límite (Go compara con `>=`): si el manejador dejó datos sin leer, la conexión se cierra en lugar de leer y descartar hasta 256 KiB; si leyó el cuerpo entero, la conexión se reutiliza, como en Go.
- **Dónde:** `1.net.http.server.go`.
- **Motivo:** no gastar ancho de banda en cuerpos que nadie va a usar.
- **Parche:** `patches/07-P7-cuerpo-sin-leer.patch`. **Prueba:** `TestT21_P7_CuerpoSinLeer` (`turbo_parches_test.go`).

### P8. Cabecera `Server`

- **Qué hace:** todas las respuestas llevan una sola cabecera `Server: OKZGN Turbo` (`TurboServerName`), también las internas (errores, redirecciones de `ServeFile`): sustituye a la que fije el manejador (las cabeceras de un sitio, un CGI) y no depende de que el manejador fije `Date`. En HTTP/2 no se añade a los trailers. Las respuestas informativas 1xx de HTTP/1 (`103 Early Hints`) salen con las cabeceras del manejador tal cual, como en Go; Turbo no las envía.
- **Dónde:** `1.net.http.server.go` (`extraHeader.Write`, `(*chunkWriter).writeHeader`), `1.net.http.h2_bundle.go` (`(*http2writeResHeaders).writeFrame`).
- **Parche:** `patches/08-P8-cabecera-server.patch`. **Pruebas:** `TestT21_P8_CabeceraServer` (`turbo_parches_test.go`), `TestC3_OneServerHeader` (`turbo_parches_test.go`).

### P9. `Error` y `NotFound` con la plantilla de Turbo

- **Qué hace:** `Error` responde con la plantilla del código (`{TURBO_RESPONSE_CODE}`; HTML si empieza por `<`) y el detalle en la línea siguiente, escapado con `html.EscapeString` si la plantilla es HTML; `NotFound` no añade texto propio. Lo usan también las respuestas internas de `ServeFile` y `ServeContent` (400, 403, 404, 416, 500). Las cabeceras se fijan antes de `WriteHeader`, para que lleguen a la respuesta.
- **Dónde:** `1.net.http.server.go`: `Error`, `NotFound`; `turboPlantillaError` en `0.turbo.parches.go`.
- **Parche:** `patches/09-P9-plantilla-error.patch`. **Pruebas:** `TestT21_P9_PlantillaError` (`turbo_parches_test.go`), `TestC8_HTMLTemplateDetailEscaped` (`turbo_parches_test.go`), `TestW_ErrorHeaders` (`turbo_servido_test.go`).

### P10. Formularios con `MBB` (`TurboMaxBodySize`), `TurboMaxFormParts` y `TurboMaxFormHeaders`; multipart solo en memoria

- **Qué hace:** el cuerpo `x-www-form-urlencoded`, que se guarda entero en memoria, se limita a `TurboMaxBodySize` y como mucho a 10 MiB, como en Go, y se deja de leer al pasar ese límite también cuando el cuerpo ya es un `MaxBytesReader` mayor (Go no limita en ese caso); `FormValue`, `PostFormValue` y `FormFile` analizan el multipart con `TurboMaxBodySize` (Go: 32 MB); `readForm` admite como mucho `TurboMaxFormParts` partes (1000, como Go) y `TurboMaxFormHeaders` cabeceras (1000; Go: 10 000, en `maxMIMEHeaders`), salvo que la petición lleve otros máximos con `TurboWithFormLimits` (en `0.turbo.parches.go`; lo usa la subida de archivos autenticada, `hardUpload`), y todo el formulario, archivos incluidos, debe caber en `maxMemory`, sin los 10 MB adicionales de Go ni archivos temporales. Un `maxMemory` de 0 o menos (que en Go es "todo a archivos temporales") vale `TurboMaxBodySize`.
- **Dónde:** `1.net.http.request.go` (`parsePostForm`, `ParseMultipartForm`, `FormValue`, `PostFormValue`, `FormFile`), `c.mime.formdata.go` (`readForm`), `c.mime.multipart.go` (`maxMIMEHeaders`, campos `turboMaxParts` y `turboMaxHeaders` de `multipart_Reader`).
- **Motivo:** el tamaño de la subida lo fija `MBB` y Turbo no escribe archivos temporales (`hardUpload`).
- **Parche:** `patches/10-P10-formularios.patch`. **Pruebas:** `TestT21_P10_Formularios` (`turbo_parches_test.go`), `TestC4_ParseMultipartFormZero` (`turbo_parches_test.go`), `TestC7_URLEncodedFormLimit`, `TestH53_URLEncodedLimitWithMaxBytesReader` (`turbo_parches_test.go`), `TestC5_FormPartsLimit` (`turbo_partes_test.go`), `TestC5_HardUploadManyFiles` (`turbo_partes_test.go`), `TestP_HardUpload` (`turbo_panel_test.go`).

### P11. Límite propio de 50 `RST_STREAM` por segundo y conexión

- **Qué hace:** `processResetStream` cuenta los `RST_STREAM` de la conexión en ventanas de un segundo (`turboLimiteRST`) y, por encima de `turboMaxRSTStreamPorSegundo` (50), cierra la conexión con `GOAWAY` (`ENHANCE_YOUR_CALM`). Se suma a la mitigación de Go del ataque Rapid Reset (CVE-2023-44487).
- **Dónde:** `1.net.http.h2_bundle.go`: campo `turboRST` de `http2serverConn`, `processResetStream`; `0.turbo.parches.go`.
- **Parche:** `patches/11-P11-limite-rst-stream.patch`. **Prueba:** `TestT21_P11_RSTStream` (`turbo_parches_test.go`).

### P12. `CgiHandler` con timeout y errores con la plantilla

- **Qué hace:** campo `Timeout`: el proceso se lanza con `exec.CommandContext` y termina con la petición o al pasar `Timeout` (Turbo usa `WT`), con `WaitDelay` de 1 s; si vence antes de las cabeceras, 504 con la plantilla. Un fallo al lanzarlo responde 500 con la plantilla y deja el detalle solo en el log.
- **Dónde:** `a.server.cgi.host.go`: `CgiHandler`, `(*CgiHandler).ServeHTTP`.
- **Motivo:** acotar los CGI: su cuerpo y su tiempo de ejecución.
- **Parche:** `patches/12-P12-cgi.patch`. **Pruebas:** `TestW_CGIBodyAndEnv` (`turbo_servido_test.go`), `TestP27_CGIErrorDisclosure` (`turbo_servido_test.go`), `TestW_CGITimeout` (`turbo_servido_test.go`).

### P13. Plazos de 1 s para el prefacio y los primeros SETTINGS de HTTP/2

- **Qué hace:** `http2prefaceTimeout` y `http2firstSettingsTimeout` valen 1 s (Go: 10 s y 2 s): una conexión HTTP/2 que no envía el prefacio o sus primeros SETTINGS se cierra al segundo. En ese tramo no se aplica `RHT`, así que este plazo es lo que limita una conexión TLS que no llega a pedir nada.
- **Dónde:** `1.net.http.h2_bundle.go`, constantes de `http2serverConn`.
- **Motivo:** el fork anterior ya los tenía así; se conservan como parche documentado.
- **Parche:** `patches/13-P13-prefacio-http2.patch`. **Prueba:** `TestT21_P13_PrefacioHTTP2` (`turbo_parches_test.go`).

## Sin parche

- **Máximo de 50 streams HTTP/2 por conexión:** lo fija el servidor HTTPS de Turbo con `Server.HTTP2.MaxConcurrentStreams` (`a.turbo.main.go`).

## Personalizaciones del fork anterior que se descartaron

| Personalización | Motivo |
|---|---|
| No cerrar la conexión tras un panic del manejador | Se vuelve al comportamiento de Go |
| `charset=UTF-8` en mayúsculas; restos de depuración (`tax`, `fmt.Println` comentados) | Sin efecto funcional |
| Cambios en el cliente HTTP/2 (`pingTimeout` de 5 s, `idleTimer` con `V`) | Turbo no usa el cliente |
| Generadores y tablas de `x/text` sin uso | Enlazaban el `net/http` real |
| Constante `http2defaultMaxStreams` = 50 | Sustituida por configuración (ver arriba) |
| Parches de seguridad portados a mano al fork anterior | Ya están en Go 1.26 |
