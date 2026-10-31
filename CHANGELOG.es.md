# Cambios de Turbo

[English](CHANGELOG.md)

v2.4 es la versión siguiente a v2.3.rc3. Si actualiza desde **v2.3.rc3**, se aplican todas las etapas de v2.4: lea antes [Actualizar desde v2.3.rc3](#actualizar-desde-v23rc3).

## Actualizar desde v2.3.rc3

**Recomendación: actualice cuanto antes.** Esta versión corrige fallos de seguridad y de estabilidad: algunos podían exponer archivos de fuera de un sitio o dejar el servidor sin servicio o colgado, y otros afectaban al panel, a los certificados y a la configuración de TLS. Los detalles se publican en el aviso de seguridad del repositorio.

Antes de actualizar:

1. **Haga una copia de la carpeta de sitios**, incluido `turbo.config`. Turbo también guarda una copia automática (punto siguiente), pero no cubre los certificados ni el contenido de los sitios.
2. **`turbo.config` cambia de formato.** Turbo lee los archivos antiguos y los convierte en memoria. La primera vez que guarde la configuración desde el panel, conserva el original como `turbo.config.v1.bak`, con permisos `0600`, y escribe el nuevo formato, marcado con `"^": {"v": "2"}`.
3. **Volver a una versión anterior no es transparente.** Para hacerlo, restaure `turbo.config.v1.bak` como `turbo.config`. Si conserva el archivo nuevo:
   - la versión antigua lee `CIL` y `CIS` como unidades de 10 ms, así que los intervalos serían 10 veces más largos;
   - ignora la contraseña guardada (`PH`) y vuelve a `Admin` o a `TURBO_PASSWORD`;
   - prueba los índices en orden aleatorio;
   - no aplica la restricción del panel (`PA`).
4. **Dé al panel un host propio** en `PA`, que no sirva ningún sitio (vea el README), y cambie las credenciales por defecto.
5. **Revise los cambios incompatibles** de cada etapa, sobre todo:
   - Turbo no arranca si `turbo.config` no es JSON válido, y dice dónde está el error;
   - el panel solo inicia sesión por `POST /admin:`, y `PA` combina hosts y redes con AND;
   - el origen de las reescrituras se compara con la ruta decodificada;
   - TLS 1.2 como mínimo;
   - Certbot ya no se ejecuta solo;
   - la sesión del panel pasa a una cookie;
   - "IP denegada" ahora bloquea;
   - el proceso termina si no puede abrir el puerto 80;
   - la unidad systemd de referencia corre sin root.

Los binarios publicados son estáticos y se compilan con el último parche de Go 1.26. Compruebe la descarga con `SHA256SUMS`, por ejemplo `sha256sum -c SHA256SUMS`.

---

## v2.4

La primera versión publicada después de v2.3.rc3. Reúne cuatro etapas de trabajo, ninguna publicada por separado: se enumeran abajo, de la más reciente a la más antigua, con sus cambios. Al actualizar desde v2.3.rc3 se aplican todas.

### Etapa 4: revisión integral de seguridad y robustez

#### Correcciones
- **Las rutas no salen del sitio:** la ruta pedida se decodifica y se limpia, y los archivos se buscan y se abren solo a través de la carpeta `@` del sitio (`os.Root`), así que ninguna ruta, reescritura ni enlace simbólico llega a un archivo o un preprocesador de fuera. Lea el aviso de seguridad.
- **Rutas con codificación porcentual:** `/a%20b.txt` o `/caf%C3%A9.txt` sirven ahora los archivos `a b.txt` y `café.txt` (respondían 404).
- **`turbo.config` siempre es JSON válido:** se escribe con un codificador de JSON y se sustituye de forma atómica (un archivo temporal y después un cambio de nombre), así que un fallo al guardar deja el archivo anterior. El archivo nuevo tiene permisos `0600` y pertenece al usuario que ejecuta Turbo; si `turbo.config` es un enlace simbólico, se sustituye su destino y el enlace se mantiene. Si al guardar el archivo del disco no es JSON válido, antes se copia a `turbo.config.invalido.<fecha>.bak`.
- **Concurrencia:** algunas acciones del panel (añadir un sitio o un subdominio) leían estado compartido sin el bloqueo mientras se podía escribir, lo que podía detener el proceso; un cliente lento del panel ya no retiene el bloqueo que necesitan todas las peticiones; el hash de la contraseña de `setP` se calcula fuera del bloqueo, y dos sesiones ya no pueden compartir clave. Un certificado no se pide dos veces a la vez.
- **Redirecciones y puertos:** la redirección a HTTPS va al puerto de `TURBO_HTTPS_ADDR` si no es 443, y las redirecciones `W`/`R` conservan el puerto del `Host`.
- **Keep-alive tras un POST:** una conexión cuyo cuerpo se leyó hasta el final se mantiene abierta (se cerraba).
- **IPs denegadas en forma canónica:** `2001:DB8::1` y `::ffff:192.0.2.1` coinciden ahora con `2001:db8::1` y `192.0.2.1`; las claves de `@` en `turbo.config` se escriben así al guardar.

#### Cambios incompatibles
- **Rutas pedidas:** una ruta con `..`, `\`, `%00`, caracteres de control, un escape `%` mal formado, UTF-8 inválido (`%FF`), una `/` codificada (`%2F`) o una `\` codificada (`%5C`) se responde con 404, exista el archivo o no (antes, algunas recibían 400). Una `/` codificada ya no separa carpetas.
- **Extensiones sin mayúsculas:** los preprocesadores y los MIME coinciden con la extensión en mayúsculas o minúsculas (`.PHP`, `.Php` se ejecutan como `.php`), en todos los sistemas, y se guardan en minúsculas (también los de un `turbo.config` antiguo).
- **Nombres de archivo especiales:** un segmento de ruta que acaba en `.` o en espacio se responde con 404, y también un archivo pedido con `/` al final (`/x.php/`); en Windows, también un segmento con `:` (flujos alternativos), un nombre de dispositivo reservado (`CON`, `NUL`, `COM1`…) o `~` seguido de un dígito (los nombres cortos 8.3, como `INDEX~1.PHP`). La subida de archivos descarta esos nombres en todos los sistemas.
- **Reescrituras:** el origen de una reescritura se compara con la ruta decodificada, así que un origen guardado con escapes `%` (`/a%20b`) hay que volver a guardarlo decodificado (`/a b`). Un destino interno también se decodifica (un `%` literal se escribe `%25`), y `{REWRITE_COMPLEMENT}` es lo que sigue al origen en la ruta decodificada (más la consulta).
- **Caracteres de control:** el panel rechaza con 400 "Caracteres de control no admitidos" cualquier valor con caracteres de control, y con "Texto UTF-8 incorrecto" el UTF-8 inválido. Las plantillas de respuesta pueden seguir teniendo tabuladores y saltos de línea. Esos valores en `turbo.config` se descartan al cargarlo, con un aviso en el log.
- **`turbo.config` inválido:** Turbo ya no arranca con los valores por defecto (y la contraseña `Admin`) cuando `turbo.config` no es JSON válido o no se puede leer. Termina con código 1 y muestra el archivo, la línea y la columna del error, la propia línea y las copias que hay junto a él. Si el archivo se rompe con Turbo en marcha, se mantiene la configuración en uso y el mismo mensaje va al log. `setM` rechaza un directorio de sitios cuyo `turbo.config` no es válido.
- **Límite global de peticiones:** el limitador de todo el servidor ya no reutiliza los ajustes por IP, que podían responder 429 a todos los clientes en cuanto el servidor recibía unas 100 peticiones por segundo. Tiene su propio ajuste, `CGL` (peticiones por segundo entre todos los clientes), **desactivado por defecto**; por encima, las peticiones nuevas reciben 503 con `Retry-After: 1` y no se bloquea ninguna IP. Los bloqueos por IP duran siempre 5 segundos (desaparece el bloqueo "persistente", más largo).
- **Host del panel (`PA`):** las entradas de host y las redes se combinan ahora con AND: con las dos, una petición necesita uno de los hosts **y** una de las redes (antes bastaba cualquiera, así que desde una red permitida el panel respondía también en los hosts de los sitios). Se rechaza un host de `PA` que sirva un sitio, y un sitio, subdominio o alias nuevo que serviría un host de `PA`. Un `turbo.config` con un `PA` así se carga igual, con un aviso. Sin un host en `PA` (vacío, o solo con redes), Turbo avisa al arrancar de que el panel comparte origen con los sitios: dele un host propio (vea el README).
- **Logins fallidos:** tras 5 logins fallidos desde la misma IP en 10 minutos, los logins desde esa IP reciben 429 con `Retry-After` (1 minuto, después 2, 4… hasta 15) sin comprobar la contraseña. Los intentos que se están comprobando cuentan para esos 5, así que los simultáneos que los superan reciben 429 con `Retry-After: 2`. Si la contraseña no se puede comprobar en 2 segundos porque hay demasiadas comprobaciones en curso, el login (y la contraseña actual de los `set*`) recibe 503 con `Retry-After: 2`. Las credenciales por defecto siguen siendo `Turbo`/`Admin`, y Turbo avisa al arrancar mientras se usen.
- **`RHT` e `IT` a 0:** ahora usan `RT`, como Go, en lugar de dejar sin límite la lectura de cabeceras y las conexiones keep-alive inactivas. Con `RT` también a 0, sigue sin haber límite.
- **Una sola cabecera `Server`:** todas las respuestas llevan una sola `Server: OKZGN Turbo`. Una cabecera `Server` fijada por un sitio (cabeceras propias) o un CGI se sustituye en lugar de enviarse junto a la de Turbo, y una respuesta cuyo manejador fija `Date` ya no sale sin `Server`.
- **Límite de cabeceras en HTTP/2 (`MHB`):** cada campo cuenta ahora 32 bytes además de su nombre y su valor, como cuentan HTTP/2 y Go, así que con el mismo `MHB` una petición HTTP/2 admite menos cabeceras que antes (una lista larga de campos diminutos ya no cabe).
- **Formularios `application/x-www-form-urlencoded`:** como mucho 10 MiB, aunque `MBB` sea mayor (se guardan enteros en memoria). Las subidas multipart siguen llegando hasta `MBB`.
- **Parámetros de la API del panel que no se pueden leer:** 400 "Parámetros incorrectos" si su codificación está mal formada, y 413 si son demasiado grandes. Antes se ignoraba el error y la acción se ejecutaba con lo que se hubiera decodificado, o respondía "Faltan datos".
- **`cfgR` y `cfgW`:** se configuran en la raíz del sitio (`d` vacío), que es donde se aplican (`cfgR` redirige `www.<sitio>` al sitio); con un subdominio responden 400. El panel solo los ofrece en la raíz.
- **`cfgC` en curso:** mientras se emite un certificado, `cfgC` responde 202 (antes, 400) con el mismo JSON `"status":"WAIT"`.
- **"Borrar SSL" (`cfgC a=0`):** borra también un certificado de más de 75 días (respondía "Sin certificado" y dejaba los archivos).
- **Reemplazo de caracteres en todos los parámetros:** como dice la especificación de la API, los reemplazos de §2.1 (`-,-` por `#` y los demás) se deshacen en todos los parámetros de la API del panel (salvo el sitio y el subdominio de `hardUpload`, que no pueden contener esos caracteres), también en la plantilla de respuesta, el nombre de una cabecera, la extensión de un MIME, el alias y el sitio de `addSite` y `addDenied`.
- **Formularios multipart:** como mucho 1 000 partes, como en Go (eran 10 000). La subida de archivos (`hardUpload`), ya autenticada, admite hasta 10 000 archivos de una vez (antes, el límite de cabeceras de las partes la paraba en unos 500).
- **Login solo por `POST /admin:`:** las credenciales se leen solo del cuerpo, nunca de la URL, y el cuerpo puede tener como máximo 4 KiB (si no, 413). Un `GET`, otro método u otra ruta bajo `/admin:` no inician sesión. `/admin:signout:` cierra la sesión solo por `POST`.

### Etapa 3: base técnica, documentación y despliegue

#### Novedades
- **`net/http` actualizado:** `customNetHttp` es ahora el `net/http` de Go 1.26 más los parches de Turbo, documentados en [`customNetHttp/PATCHES.md`](customNetHttp/PATCHES.md). Trae todas las correcciones de seguridad de Go publicadas hasta esa versión. El rendimiento sirviendo archivos sube de forma notable respecto a v2.3.rc3.
- **Puertos configurables:** las variables `TURBO_HTTP_ADDR` y `TURBO_HTTPS_ADDR` cambian dónde escucha Turbo, por ejemplo para usarlo detrás de un proxy.
- **Unidad systemd de referencia:** [`deploy/turbo.service`](deploy/turbo.service) corre con un usuario sin privilegios, con `CAP_NET_BIND_SERVICE`, registra en el journal y se reinicia si falla.
- **Mensajes con nivel y hora:** los mensajes de la consola usan `log/slog` (`time=… level=… msg=…`) y están en español.
- **GUI embebida desde `turbo.dev/`:** una sola copia de la GUI, embebida con `//go:embed`.
- **Comprobaciones antes de publicar:** el README enumera las comprobaciones que hay que pasar a mano antes de cada cambio o versión: formato, `vet`, `staticcheck`, `govulncheck`, `gosec`, `regenerar -comprobar`, pruebas, `-race`, fuzzing y compilación cruzada.

#### Cambios incompatibles
- **Panic en un manejador:** cierra la conexión, como en Go.
- **`charset`:** las respuestas de error dicen `charset=utf-8`, en minúsculas.
- **Formato de los mensajes de la consola:** cambia; los scripts que lean los textos antiguos deben adaptarse.
- **Logs en una copia nueva:** una copia recién clonada del repositorio ya no trae `turbo.visits` ni `turbo.denials`, así que no registra nada hasta crearlos.
- **`TURBO_HTTP_ADDR` y `TURBO_HTTPS_ADDR`:** un valor no válido termina el proceso.
- **Unidad systemd de referencia:** usa un usuario `turbo` sin privilegios en lugar de root.
- **API del panel:**
  - `addDenied` rechaza con 400 "IP actual" la IP desde la que se usa el panel.
  - Los `del*` sin todos sus parámetros responden 400 "Faltan datos" (antes, 200 vacío).
  - `setU` y `setP` con el valor actual responden 400 "Usuario sin cambios" o "Contraseña sin cambios".
  - `hardUpload` responde 400 sin subir nada si no puede vaciar `@`. Antes mezclaba archivos nuevos con los que no se podían borrar.
  - "IP denegada" rechaza la dirección sin especificar (`0.0.0.0`, `::`).
- **El panel envía sus parámetros en el cuerpo de la petición:** la contraseña ya no aparece en la URL ni en `turbo.visits`. Un cliente de la API que la ponga en la URL sí la dejaría en el log.

### Etapa 2: corrección funcional y endurecimiento

#### Novedades
- **Sesión del panel por cookie:** `turbo_session` es `HttpOnly`, `SameSite=Strict` y `Secure` en HTTPS, está ligada a la IP y caduca tras 10 minutos de inactividad. El token ya no viaja en la URL.
- **Contraseña guardada con hash:** "Guardar configuración" guarda el usuario y el hash de la contraseña (PBKDF2-HMAC-SHA256). Si había una contraseña en texto plano en `turbo.config`, se convierte.
- **Renovación automática de certificados:** se renuevan los certificados emitidos por Turbo cuando les quedan menos de 30 días.
- **Certificados por nombre:** cada nombre recibe su certificado por SNI.
- **Restricción del panel (`PA`):** se puede limitar el panel a ciertos hosts o redes; vacío por defecto. Las entradas de host comparan la cabecera `Host`, que elige el cliente, así que solo las redes CIDR limitan quién accede.
- **Cabeceras de seguridad:** el panel no se puede incrustar en un `iframe` ni se guarda en caché, y las respuestas de error llevan `nosniff`.
- **Índice por defecto:** los sitios nuevos traen `index.html` como índice.

#### Cambios incompatibles
- **Límites que antes no se aplicaban:** `MUB`, `MHB` y `MBB` limitan de verdad la URI, las cabeceras y el cuerpo. Revise si tiene valores guardados más bajos de lo que necesita.
- **CGI:** el cuerpo enviado a un CGI se limita a `MBB` y los CGI tienen tiempo máximo de ejecución. Un fallo al lanzarlos responde 500 sin detalles.
- **Limitador de frecuencia:**
  - responde 429 en lugar de cerrar la conexión;
  - cuenta una vez por petición, así que el límite efectivo sube unas 3 veces;
  - `CIL` y `CIS` pasan a milisegundos reales (la migración multiplica por 10 los valores guardados).
- **API del panel:**
  - `b` (la contraseña actual) es obligatoria en todos los `set*`;
  - un POST autenticado con la cookie tiene que venir del mismo origen (403 si no); con la cabecera `ok` no hace falta;
  - el token deja de aceptarse en la URL.
- **Cookie de sesión:** usa `Path=/`. Turbo la quita de la cabecera `Cookie` antes de lanzar un CGI.
- **Preprocesadores:** si falta el ejecutable, responden 500 en vez de servir el archivo tal cual.
- **Reescrituras e índices:**
  - una reescritura a `http(s)://` con ruta o consulta redirige al destino exacto; si es solo un dominio, se añade el URI original;
  - los índices se prueban en el orden en que se añadieron.
- **Subida de archivos:** borra todo `@`, subcarpetas incluidas, e informa de los nombres descartados.
- **HTTPS:**
  - se rechaza la conexión para nombres sin certificado, sin SNI o por IP;
  - un alias necesita un certificado que cubra su nombre.
- **Puerto 80:** el proceso termina si no puede abrirlo, para que systemd lo vea y lo reinicie.
- **`turbo.certificates`:** Certbot trabaja en una carpeta por sitio.

### Etapa 1: estabilidad y seguridad inmediata

#### Correcciones
- **Bloqueos y caídas:**
  - ciertos valores de configuración ya no dejan el servidor colgado ni terminan el proceso;
  - ya no hay accesos concurrentes sin sincronizar que podían abortarlo;
  - una descarga lenta ya no deja sin respuesta a los demás clientes.
- **TLS:** la versión mínima es TLS 1.2.
- **IPs denegadas:** "IP denegada" bloquea de verdad.
- **Certbot:** solo se ejecuta cuando el administrador lo pide.
- **Redirección a HTTPS:** solo se redirigen los sitios que la tienen activada.
- **Parches de Go:** se portan a `customNetHttp` las correcciones de seguridad del servidor HTTP de Go (chunked, Range, CONNECT y HTTP/2).
- **Binarios:** se publican estáticos (el de Linux funciona sin depender de la versión de glibc), compilados con el último parche de Go y etiquetados en el commit exacto.

#### Cambios incompatibles
- **TLS:** se rechazan TLS 1.0, TLS 1.1, 3DES y el intercambio de claves RSA. Con Go 1.26 también se rechazan certificados con número de serie negativo y claves RSA de menos de 1024 bits, y se activa ML-KEM.
- **Redirección a HTTPS:** los hosts sin sitio configurado ya no se redirigen a HTTPS, y un host solo se redirige cuando su sitio tiene HTTPS activado y un certificado cubre ese host; si no, se sirve por HTTP.
- **"IP denegada":** bloquea. `"@"` guarda solo las IPs denegadas a mano, no las marcas temporales del limitador.
- **Certbot:**
  - ya no se lanza solo;
  - "Borrar SSL" sin certificado no hace nada;
  - el email es obligatorio;
  - solo se aceptan adaptadores `dns-<proveedor>`.
- **Reescrituras:** se rechazan las que no empiezan por `/`, `http://` o `https://`. Las que había en `turbo.config` se descartan al cargar, con aviso en el log.
- **Logs:** `turbo.visits` y `turbo.denials` se detectan en la comprobación periódica, así que el registro empieza hasta 30 s después de crear el archivo.
