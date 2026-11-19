-- A form with files (multipart/form-data): the files arrive in memory, in REQUEST.files, and the other fields in
-- REQUEST.form. A script can't write them anywhere: it has no access to files.
if REQUEST.method ~= "POST" then
  return "<!DOCTYPE html><meta charset=utf-8><form method=post enctype=multipart/form-data>"
    .. "<input name=title placeholder=Title> <input type=file name=doc multiple> <button>Send</button></form>"
end

local rows = {}
for _, f in ipairs(REQUEST.files) do
  rows[#rows + 1] = string.format("<li><b>%s</b>: %s (%s, %d bytes, starting %q)</li>",
    turbox.html_escape(f.field), turbox.html_escape(f.filename),
    turbox.html_escape(f.content_type), f.size, turbox.html_escape(f.data:sub(1, 16)))
end

return "<!DOCTYPE html><meta charset=utf-8><h1>Received</h1>"
  .. "<p>Title: " .. turbox.html_escape(REQUEST.form.title or "") .. "</p>"
  .. "<ul>" .. table.concat(rows) .. "</ul><p><a href=''>Again</a></p>"
