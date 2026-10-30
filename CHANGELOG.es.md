# Cambios de Turbo

[English](CHANGELOG.md)

Cada versión incluye las anteriores. Si actualiza directamente desde **v2.3.rc3**, se aplican todas las secciones de este archivo: lea antes [Actualizar desde v2.3.rc3](#actualizar-desde-v23rc3).

## Actualizar desde v2.3.rc3

**Recomendación: actualice cuanto antes.** Estas versiones corrigen fallos de seguridad y de estabilidad: algunos permitían dejar el servidor sin servicio o colgado, y otros afectaban al panel, a los certificados y a la configuración de TLS. Los detalles se publican en el aviso de seguridad del repositorio.

Antes de actualizar:

1. **Haga una copia de la carpeta de sitios**, incluido `turbo.config`. Turbo también guarda una copia automática (punto siguiente), pero no cubre los certificados ni el contenido de los sitios.
2. **`turbo.config` cambia de formato.** Turbo lee los archivos antiguos y los convierte en memoria. La primera vez que guarde la configuración desde el panel, conserva el original como `turbo.config.v1.bak`, con permisos `0600`, y escribe el nuevo formato, marcado con `"^": {"v": "2"}`.
3. **Volver a una versión anterior no es transparente.** Para hacerlo, restaure `turbo.config.v1.bak` como `turbo.config`. Si conserva el archivo nuevo:
   - la versión antigua lee `CIL` y `CIS` como unidades de 10 ms, así que los intervalos serían 10 veces más largos;
   - ignora la contraseña guardada (`PH`) y vuelve a `Admin` o a `TURBO_PASSWORD`;
   - prueba los índices en orden aleatorio;
   - no aplica la restricción del panel (`PA`).
4. **Revise los cambios incompatibles** de cada versión, sobre todo:
   - TLS 1.2 como mínimo;
   - Certbot ya no se ejecuta solo;
   - la sesión del panel pasa a una cookie;
   - "IP denegada" ahora bloquea;
   - el proceso termina si no puede abrir el puerto 80;
   - la unidad systemd de referencia corre sin root.

Los binarios publicados son estáticos y se compilan con el último parche de Go 1.26. Compruebe la descarga con `SHA256SUMS`, por ejemplo `sha256sum -c SHA256SUMS`.

---

## v2.4

Base técnica, documentación y despliegue.

### Novedades
- **`net/http` actualizado:** `customNetHttp` es ahora el `net/http` de Go 1.26 más los parches de Turbo, documentados en [`customNetHttp/PATCHES.md`](customNetHttp/PATCHES.md). Trae todas las correcciones de seguridad de Go publicadas hasta esa versión. El rendimiento sirviendo archivos sube de forma notable respecto a v2.3.rc3.
- **Puertos configurables:** las variables `TURBO_HTTP_ADDR` y `TURBO_HTTPS_ADDR` cambian dónde escucha Turbo, por ejemplo para usarlo detrás de un proxy.
- **Unidad systemd de referencia:** [`deploy/turbo.service`](deploy/turbo.service) corre con un usuario sin privilegios, con `CAP_NET_BIND_SERVICE`, registra en el journal y se reinicia si falla.
- **Mensajes con nivel y hora:** los mensajes de la consola usan `log/slog` (`time=… level=… msg=…`) y están en español.
- **GUI embebida desde `turbo.dev/`:** una sola copia de la GUI, embebida con `//go:embed`.
- **CI:** cada cambio pasa formato, `vet`, `staticcheck`, `govulncheck`, pruebas, `-race`, fuzzing y compilación cruzada.

### Cambios incompatibles
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

---

## v2.3

Corrección funcional y endurecimiento.

### Novedades
- **Sesión del panel por cookie:** `turbo_session` es `HttpOnly`, `SameSite=Strict` y `Secure` en HTTPS, está ligada a la IP y caduca tras 10 minutos de inactividad. El token ya no viaja en la URL.
- **Contraseña guardada con hash:** "Guardar configuración" guarda el usuario y el hash de la contraseña (PBKDF2-HMAC-SHA256). Si había una contraseña en texto plano en `turbo.config`, se convierte.
- **Renovación automática de certificados:** se renuevan los certificados emitidos por Turbo cuando les quedan menos de 30 días.
- **Certificados por nombre:** cada nombre recibe su certificado por SNI.
- **Restricción del panel (`PA`):** se puede limitar el panel a ciertos hosts o redes; vacío por defecto. Las entradas de host comparan la cabecera `Host`, que elige el cliente, así que solo las redes CIDR limitan quién accede.
- **Cabeceras de seguridad:** el panel no se puede incrustar en un `iframe` ni se guarda en caché, y las respuestas de error llevan `nosniff`.
- **Índice por defecto:** los sitios nuevos traen `index.html` como índice.

### Cambios incompatibles
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

---

## v2.3.rc4

Estabilidad y seguridad inmediata.

### Correcciones
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

### Cambios incompatibles
- **TLS:** se rechazan TLS 1.0, TLS 1.1, 3DES y el intercambio de claves RSA. Con Go 1.26 también se rechazan certificados con número de serie negativo y claves RSA de menos de 1024 bits, y se activa ML-KEM.
- **Redirección a HTTPS:** los hosts sin sitio configurado ya no se redirigen a HTTPS, y los subdominios wildcard se sirven por HTTP.
- **"IP denegada":** bloquea. `"@"` guarda solo las IPs denegadas a mano, no las marcas temporales del limitador.
- **Certbot:**
  - ya no se lanza solo;
  - "Borrar SSL" sin certificado no hace nada;
  - el email es obligatorio;
  - solo se aceptan adaptadores `dns-<proveedor>`.
- **Reescrituras:** se rechazan las que no empiezan por `/`, `http://` o `https://`. Las que había en `turbo.config` se descartan al cargar, con aviso en el log.
- **Logs:** `turbo.visits` y `turbo.denials` se detectan en la comprobación periódica, así que el registro empieza hasta 30 s después de crear el archivo.
