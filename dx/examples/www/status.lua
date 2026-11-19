-- A number from 200 to 599 is answered with that status and no body: Turbo answers 400 or more with the site's
-- template, as it does for a file that isn't there.
if REQUEST.params.found ~= "yes" then
  return 404
end
return { status = 200, body = "found" }
