-- Everything a script gets of its request, as JSON: to look at the table REQUEST.
local esc = turbox.json_escape

local function object(t)
  local keys = {}
  for k in pairs(t) do keys[#keys + 1] = k end
  table.sort(keys)
  local out = {}
  for _, k in ipairs(keys) do
    out[#out + 1] = '"' .. esc(k) .. '":"' .. esc(tostring(t[k])) .. '"'
  end
  return "{" .. table.concat(out, ",") .. "}"
end

local files = {}
for i, f in ipairs(REQUEST.files) do
  files[i] = string.format('{"field":"%s","filename":"%s","content_type":"%s","size":%d}',
    esc(f.field), esc(f.filename), esc(f.content_type), f.size)
end

local body = string.format(
  '{"method":"%s","uri":"%s","path":"%s","query":"%s","host":"%s","remote_addr":"%s",' ..
  '"params":%s,"headers":%s,"cookies":%s,"form":%s,"files":[%s],"vars":%s,"body_length":%d}',
  esc(REQUEST.method), esc(REQUEST.uri), esc(REQUEST.path), esc(REQUEST.query),
  esc(REQUEST.host), esc(REQUEST.remote_addr),
  object(REQUEST.params), object(REQUEST.headers), object(REQUEST.cookies), object(REQUEST.form),
  table.concat(files, ","), object(REQUEST.vars), #REQUEST.body)

return {
  status = 200,
  headers = { ["Content-Type"] = "application/json; charset=utf-8", ["Cache-Control"] = "no-store" },
  body = body,
}
