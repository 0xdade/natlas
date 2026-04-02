local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Fetches the HTTP title from a web server for each hostname supplied via the
<code>natlas.hostnames</code> script argument, sending a separate request
per hostname with the matching <code>Host</code> header (and SNI for HTTPS).
The IP address is always probed first.

Each result entry includes the hostname, HTTP status code, page title, and
redirect URL (if any).
]]

author = "natlas"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local function extract_title(body)
  if not body then return nil end
  local raw = string.match(
    body,
    "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</%s*[Tt][Ii][Tt][Ll][Ee]%s*>"
  )
  if not raw then return nil end
  -- Collapse whitespace and trim.
  return raw:gsub("[\n\r\t]+", " "):gsub("^%s+", ""):gsub("%s+$", "")
end

action = function(host, port)
  -- Build hostname list: IP first, then any provided names.
  local hostnames = {host.ip}
  local arg = stdnse.get_script_args("natlas.hostnames") or ""
  for name in string.gmatch(arg, "[^|]+") do
    local trimmed = name:match("^%s*(.-)%s*$")
    if trimmed ~= "" then
      table.insert(hostnames, trimmed)
    end
  end

  local results = {}
  local saved_targetname = host.targetname

  for _, hostname in ipairs(hostnames) do
    -- Set targetname so SSL connections use the correct SNI.
    host.targetname = hostname

    local resp = http.get(host, port, "/", {
      header = {Host = hostname},
      bypass_cache = true,
      no_cache = true,
    })

    if resp and resp.status then
      local entry = stdnse.output_table()
      entry.hostname = hostname
      entry.status = resp.status
      entry.title = extract_title(resp.body)
      if resp.location and #resp.location > 0 then
        entry.redirect_url = resp.location[#resp.location]
      end
      table.insert(results, entry)
    else
      stdnse.debug1("http.get failed for hostname=%s", hostname)
    end
  end

  host.targetname = saved_targetname

  if #results == 0 then return nil end
  return results
end
