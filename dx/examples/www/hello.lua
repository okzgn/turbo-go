-- A text that starts with "<" is answered 200, text/html.
local name = REQUEST.params.name or "world"
return "<!DOCTYPE html><meta charset=utf-8><h1>Hello, "
  .. turbox.html_escape(name)
  .. "</h1><p>Made by Lua at " .. turbox.now_ms() .. " ms (Unix time).</p>"
