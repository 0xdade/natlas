local datetime = require "datetime"
local outlib = require "outlib"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local have_openssl, _ = pcall(require, "openssl")

description = [[
Retrieves SSL/TLS certificates for each hostname supplied via the
<code>natlas.hostnames</code> script argument by re-probing the port with a
matching SNI extension for each name.  Certificates with duplicate SHA-1
fingerprints are suppressed.  The IP address is always probed first (no SNI).

Each result entry includes the SNI used, subject/issuer, validity window,
public key info, extensions, fingerprints, and PEM.
]]

author = "natlas"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
dependencies = {"https-redirect"}

portrule = function(host, port)
  return shortport.ssl(host, port)
      or sslcert.isPortSupported(port)
      or sslcert.getPrepareTLSWithoutReconnect(port)
end

local function cert_to_table(cert, sni)
  local o = stdnse.output_table()
  o.sni = sni

  if cert.subject then
    o.subject = outlib.sorted_by_key(cert.subject)
    o.subject_cn = cert.subject.commonName or ""
  end

  if cert.issuer then
    o.issuer = outlib.sorted_by_key(cert.issuer)
    o.issuer_cn = cert.issuer.commonName or ""
  end

  if cert.pubkey then
    local pk = stdnse.output_table()
    pk.type = cert.pubkey.type
    pk.bits = cert.pubkey.bits
    o.pubkey = pk
  end

  o.sig_algo = cert.sig_algorithm

  if cert.validity then
    local val = stdnse.output_table()
    for _, k in ipairs({"notBefore", "notAfter"}) do
      local v = cert.validity[k]
      val[k] = type(v) == "string" and v or datetime.format_timestamp(v)
    end
    o.validity = val
  end

  if cert.extensions and #cert.extensions > 0 then
    local exts = {}
    for i, v in ipairs(cert.extensions) do
      local ext = stdnse.output_table()
      ext.name = v.name
      ext.value = v.value
      if v.critical then ext.critical = "true" end
      exts[i] = ext
    end
    o.extensions = exts
  end

  if have_openssl then
    o.sha1 = stdnse.tohex(cert:digest("sha1"))
  end

  o.pem = cert.pem
  return o
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

  local port_key = ("%d%s"):format(port.number, port.protocol)
  local seen = {}
  local results = {}

  local saved_targetname = host.targetname

  for _, sni in ipairs(hostnames) do
    -- Clear the per-port cert cache so getCertificate re-connects with new SNI.
    if host.registry["ssl-cert"] then
      host.registry["ssl-cert"][port_key] = nil
    end
    host.targetname = sni

    local status, cert = sslcert.getCertificate(host, port)
    if not status then
      stdnse.debug1("getCertificate failed for SNI=%s: %s", sni, cert)
    else
      local fp = have_openssl and stdnse.tohex(cert:digest("sha1")) or sni
      if not seen[fp] then
        seen[fp] = true
        table.insert(results, cert_to_table(cert, sni))
      else
        stdnse.debug2("Duplicate cert (sha1=%s) for SNI=%s, skipping", fp, sni)
      end
    end
  end

  host.targetname = saved_targetname

  if #results == 0 then return nil end
  return results
end
