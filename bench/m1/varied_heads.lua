-- Keep-alive requests of different sizes in turn, as a browser sends them
-- (an asset fetch, then a page with cookies, then an API call): the other
-- scenarios repeat one request, which a read path sized by the previous
-- request serves as well as any (#723). Heads of about 40, 300, 1300 and
-- 2700 bytes; m1's `return 200 "hello"` answers them all.
local shapes = {
  { "/", 0 },
  { "/static/app.js?v=" .. string.rep("a", 40), 200 },
  { "/" .. string.rep("p", 300), 900 },
  { "/api/items?" .. string.rep("q", 120), 2500 },
}
local reqs = {}
init = function(args)
  for i, s in ipairs(shapes) do
    local h = {}
    if s[2] > 0 then
      h["Cookie"] = "session=" .. string.rep("c", s[2])
    end
    reqs[i] = wrk.format("GET", s[1], h)
  end
end
local n = 0
request = function()
  n = n % #reqs + 1
  return reqs[n]
end
