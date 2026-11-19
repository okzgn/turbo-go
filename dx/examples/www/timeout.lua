-- A script that doesn't end: dx-lua stops it when the time Turbo gives the request (WT) is over, and answers 500.
-- Catching the error with pcall doesn't keep it going. With WT 0 nothing stops it, as with a CGI.
while true do
  pcall(function() while true do end end)
end
