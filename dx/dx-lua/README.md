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
| `{ status = 201, headers = { ... }, body = "..." }` | each one optional: 200, no headers, no body. A header may have a list of values: `["Set-Cookie"] = { "a=1", "b=2" }`. The headers take 64 KiB at most, as Turbo takes them; a `Content-Length` is dropped: the length is the body's |

Anything else, or an error, is answered 500, with the site's template. The text of the error, with its file and line, goes to the worker's standard
error, which Turbo writes to its log, never to the client.

A body, or the value of a header, may be a number: it is written as Lua writes it (`tostring`, 14 digits at most), so
`1.5` is `1.5`, `1e300` is `1e+300` and `2^53` is `9.007199254741e+15`; `print` writes its numbers the same way. For
every digit of a large integer, format it: `string.format("%d", n)`.

The type of a text is chosen by its first character, so a script that returns what a client sent
(`return REQUEST.params.q`) lets the client choose it: a `<script>` of theirs would run as a page of the site. Escape
what comes from the request (`turbox.html_escape`), or return a table with its `Content-Type`.

## What it gets

`REQUEST`:

| Field | What it has |
|---|---|
| `method`, `uri`, `query` | `GET`, `/a%20b?x=1`, `x=1`: as they came; through a rewrite whose target has a query, as Turbo gives `REQUEST_URI` and `QUERY_STRING` (the parameters it sets are in `query` only) |
| `path` | The path asked for, decoded (`/a b`): with a rewrite, the one before it; the script's is `vars.SCRIPT_NAME` |
| `host`, `remote_addr` | The `Host` of the request and the client's IP |
| `params` | The query, decoded: `REQUEST.params.x`. `&` separates the parameters (`;` doesn't), `+` is a space and a `%` without two hexadecimal digits stays as it is, as `QUERY()` of Turbo's expressions reads them. When a name repeats, the first wins (`QUERY()` gives `''` when the values differ, as PHP takes the last) |
| `headers` | The headers, by their names in lower case (`REQUEST.headers["user-agent"]`) |
| `cookies` | The cookies, as they came: `;` separates them, a name and a value lose the spaces around them, and a value its double quotes; nothing is decoded. When a name repeats, the first wins (`COOKIE()` of Turbo's expressions gives `''` where PHP would read something else: a `%XX` that it decodes, double quotes or spaces that it keeps). The session of Turbo's panel never arrives |
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
  that leads out of it is answered 404. Once opened, its path is resolved again and must still be that file: a folder
  of the site changed in between (a link put in its place) is answered 404 too. On a volume where the system can't
  resolve a path (some virtual or network drives on Windows), the scripts there can't be run.
- **Limits:** 16 MiB of memory for each state; 64 KiB for a script (the 256 used last, up to 16 MiB, are kept in memory, while
  the size, the date, the file (its inode, or its index on Windows) and the time of its last change, which no program
  sets, don't change: a script written again in place with its date put back is read again); the time Turbo gives the request (its setting `WT`). When it is over, the script is stopped and the answer
  is a 500; catching the error with `pcall` or `xpcall` doesn't keep it going. The time is looked at between the
  steps of the script: one held inside a single call of the library (a pattern that backtracks, a sort) goes on until
  Turbo kills the worker at `WT` (504). With `WT` 0 nothing stops a script, as nothing stops a CGI. `table.insert`
  with a position checks it first, as Lua 5.3 does: one that isn't an integer of 1 to `#t + 1` is an error (LuaJIT
  moved the elements up to it in a single call, 2^31 of them for `2^31`), and a move of 65 536 elements or more is
  done between the steps of the script, where its time stops it (`#t` of a table with a few keys at powers of two is
  up to 2^30).
- **The depth of the calls** is LuaJIT's: a recursion too deep ends in the error `stack overflow`, answered 500 as
  any other error (or caught by `pcall`), and the worker goes on. That holds for a recursion through functions of the
  library too (`string.gsub` with a function, `table.sort` with a comparator, `string.format` with a `__tostring`),
  which take the stack of the program and not only Lua's: the worker runs the scripts in a thread with a stack of
  256 MiB, more than such a recursion reaches before LuaJIT's limit. That stack is only reserved, and is memory only as
  far as a script has gone into it, which the worker keeps while it lives (some 116 MiB on Linux after the deepest of
  them, `string.gsub` as a tail call, `return string.gsub(s, p, f)`; a few MiB after the others). Where the system
  counts what is reserved (Linux with `vm.overcommit_memory=2`), each worker counts the 256 MiB, and Turbo may keep as
  many workers as its turns (`CGP`).
- **Bodies of 8 MiB at most,** half the memory of a state: a larger one is answered 413 (dx-core reads it and drops
  it, without keeping it).
- **The request counts in the memory of the state:** its body, its form and its files are in it, so a form
  `application/x-www-form-urlencoded` near 8 MiB, whose body and fields are both in it, answers 500. Of a query, a form or the cookies,
  1000 pairs are read at most.
- **What crosses to a capability** in a call: 100 000 values, 16 MiB of texts and 32 levels of tables at most.

## Not yet

- Writing the answer as it is made (`turbox.write`): the protocol allows it, the script returns its answer whole.
- Capabilities: the abstraction is in `dx-core`, and Turbo grants none yet.
