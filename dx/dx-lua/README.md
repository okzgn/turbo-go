# dx-lua

A worker of Turbo's mode dx that runs Lua scripts with LuaJIT (Lua 5.1), in a sandbox: a script has the language, its
request and the capabilities that Turbo granted to it (none in this version), and nothing else. No files, no network,
no system.

In Turbo: a site's preprocessor with the extension `lua`, the mode **DX** and the path of `dx-lua`. Examples:
[`examples/www`](../examples/www).

## A script

It returns its answer:

| It returns | The answer |
|---|---|
| a text | 200, `text/html; charset=utf-8` if it starts with `<` (after spaces), else `text/plain; charset=utf-8` |
| `nil`, `false` or `""` | 204, without a body |
| a number from 200 to 599 | that status without a body: 400 or more gets the site's template (`return 404`) |
| `{ status = 201, headers = { ... }, body = "..." }` | each one optional: 200, no headers, no body. A header may have a list of values: `["Set-Cookie"] = { "a=1", "b=2" }`. The headers take 64 KiB at most, as Turbo takes them |

Anything else, or an error, is answered 500, with the site's template. The text of the error, with its file and line, goes to the worker's standard
error, which Turbo writes to its log, never to the client.

The type of a text is chosen by its first character, so a script that returns what a client sent
(`return REQUEST.params.q`) lets the client choose it: a `<script>` of theirs would run as a page of the site. Escape
what comes from the request (`turbox.html_escape`), or return a table with its `Content-Type`.

## What it gets

`REQUEST`:

| Field | What it has |
|---|---|
| `method`, `uri`, `query` | `GET`, `/a%20b?x=1`, `x=1`: as they came |
| `path` | The path asked for, decoded (`/a b`): with a rewrite, the one before it; the script's is `vars.SCRIPT_NAME` |
| `host`, `remote_addr` | The `Host` of the request and the client's IP |
| `params` | The query, decoded: `REQUEST.params.x`. When a name repeats, the first wins |
| `headers` | The headers, by their names in lower case (`REQUEST.headers["user-agent"]`) |
| `cookies` | The cookies (the session of Turbo's panel never arrives) |
| `form` | The fields of a form, `application/x-www-form-urlencoded` or `multipart/form-data` |
| `files` | The files of a form `multipart/form-data`, a list of `{ field, filename, content_type, size, data }`: `data` is the file, in memory |
| `body` | The body as it came; empty for a form `multipart/form-data` (it is in `form` and `files`) |
| `vars` | Every variable Turbo gives the request: those of a CGI (`SCRIPT_NAME`, `HTTPS`, `SERVER_NAME`...), and `DX_TIMEOUT_MS` |

And the short names `METHOD`, `URI`, `QUERY` and `BODY`.

`turbox`: `urldecode(text)`, `parse_query(text)`, `html_escape(text)`, `json_escape(text)` (without the quotes; it also
escapes `<`, `>` and `&`), `now_ms()`; and the capabilities granted to the request, `turbox.<capability>.<function>(...)`.
What `html_escape` and `json_escape` give counts in the memory of the state, and is checked before it is built.

## The sandbox

- **A new Lua state for each request.** Nothing of one request reaches another.
- **Only the language:** `table`, `string`, `math`, `bit`, and the basic functions (`pairs`, `pcall`, `tostring`,
  `setmetatable`...). There is no `io`, `os`, `require`, `load`, `loadstring`, `dofile`, `loadfile`, `debug`, `ffi`,
  `jit`, `package`, `coroutine`, `module`, `newproxy`, `gcinfo`, `setfenv` or `getfenv`. LuaJIT's compiler stays off:
  the time of a script is looked at between its steps, which compiled code would skip.
- **`print`** writes to the worker's standard error, a line each (64 KiB in a request at most, each line counted with
  its start, `[dx-lua] <site>/<script>: ` with the script's path in its site, and its end), never to the answer. Turbo
  writes those lines, and those of the errors, to its log grouped: the first of each kind (the script and the first
  words of the line) at once, and those that follow within a minute counted, and written with the last of them.
- **`math.random`** gives each request another sequence, but it isn't a secure source: never for tokens, passwords or
  anything a visitor mustn't guess.
- **Only text:** a script that is LuaJIT bytecode is refused.
- **Only scripts of the site:** the script, resolved, must be a file inside the folder of the site, resolved: a link
  that leads out of it is answered 404.
- **Limits:** 16 MiB of memory for each state; 64 KiB for a script (the 256 used last are kept in memory, while
  the size, the date and, on Unix, the inode of their file don't change); the time Turbo gives the request (its setting `WT`). When it is over, the script is stopped and the answer
  is a 500; catching the error with `pcall` or `xpcall` doesn't keep it going. The time is looked at between the
  steps of the script: one held inside a single call of the library (a pattern that backtracks, a sort) goes on until
  Turbo kills the worker at `WT` (504). With `WT` 0 nothing stops a script, as nothing stops a CGI.
- **Bodies of 8 MiB at most,** half the memory of a state: a larger one is answered 413 (dx-core reads it and drops
  it, without keeping it).
- **The request counts in the memory of the state:** its body, its form and its files are in it, so a form
  `application/x-www-form-urlencoded` near 8 MiB, whose body and fields are both in it, answers 500. Of a query, a form or the cookies,
  1000 pairs are read at most.
- **What crosses to a capability** in a call: 100 000 values, 16 MiB of texts and 32 levels of tables at most.

## Not yet

- Writing the answer as it is made (`turbox.write`): the protocol allows it, the script returns its answer whole.
- Capabilities: the abstraction is in `dx-core`, and Turbo grants none yet.
