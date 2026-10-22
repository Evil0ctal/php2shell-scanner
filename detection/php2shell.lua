-- ============================================================================
-- php2shell - OpenResty / Nginx Lua WAF Rules
-- CVE-2026-109618 / CVE-2026-109619
--
-- Drop this into your OpenResty access_by_lua_block or reference it via
-- access_by_lua_file. Blocks the primary php2shell attack vectors at the
-- reverse-proxy layer before requests reach PHP.
--
-- Ported into php2shell-scanner from ikow/php2shell-poc detection/php2shell.lua.
-- HARDENED against dinosn/php-cve-2026-10961x-lab-poc docs/WAF-BYPASS.md:
--   1. The original read only the first 64 KB, so padding the trigger field
--      past 64 KB evaded rule 1. Default raised to 1 MB and the inspected
--      prefix size is reported in the block log.
--   2. The multipart gate now accepts the ';', ',' and space separators PHP
--      itself trims at, so the comma Content-Type variant cannot slip through.
--   3. A body-structure alert fires on a multipart body whose inspected prefix
--      contains no parsable part boundary - a sign of padding/evasion.
-- Note: the OOM-corruption chains carry none of these strings; behaviour-based
-- detection (PHP workers spawning shells) remains the reliable backstop.
-- ============================================================================

local _M = {}

-- Accept the whole separator class PHP's SAPI parser trims at: ';', ',', space.
-- "multipart/form-data" optionally followed by one of those (or end of value).
local MULTIPART_PAT = "multipart/form%-data%s*[;,%s]"

local function is_multipart()
    local ct = ngx.req.get_headers()["content-type"]
    if not ct then
        return false, nil
    end
    ct = ct:lower()
    -- Plain type with no parameters, or type followed by a PHP-accepted separator.
    if ct == "multipart/form-data" or ct:find(MULTIPART_PAT) then
        return true, ct
    end
    return false, ct
end

-- A non-semicolon separator before "boundary=" is an evasion fingerprint.
local function nonstandard_separator(ct)
    if not ct then
        return false
    end
    return ct:find("multipart/form%-data%s*,%s*boundary=") ~= nil
        or ct:find("multipart/form%-data%s+boundary=") ~= nil
end

-- Read the request body up to max_size, from memory or the spilled temp file.
local function get_body(max_size)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        local file = ngx.req.get_body_file()
        if file then
            local fh = io.open(file, "r")
            if fh then
                body = fh:read(max_size)
                fh:close()
            end
        end
    end
    return body
end

local function block(reason, log_only)
    ngx.log(ngx.WARN, "php2shell: ", reason, " from ", ngx.var.remote_addr,
            " uri=", ngx.var.request_uri)
    if not log_only then
        ngx.status = 403
        ngx.header["X-Blocked-By"] = "php2shell-detection"
        ngx.say("Forbidden")
        return ngx.exit(403)
    end
end

function _M.check(opts)
    opts = opts or {}
    local max_body_read = opts.max_body_read or 1048576  -- 1 MB default (was 64 KB)
    local log_only = opts.log_only or false

    local multipart, ct = is_multipart()
    if not multipart then
        return
    end

    if nonstandard_separator(ct) then
        ngx.log(ngx.WARN, "php2shell: non-standard multipart Content-Type separator "
                .. "(WAF bypass) from ", ngx.var.remote_addr, " uri=", ngx.var.request_uri)
    end

    local body = get_body(max_body_read)
    if not body then
        return
    end

    -- Rule 1: Block PHP_SESSION_UPLOAD_PROGRESS (primary trigger).
    if body:find("PHP_SESSION_UPLOAD_PROGRESS", 1, true) then
        return block("blocked PHP_SESSION_UPLOAD_PROGRESS (inspected "
                     .. #body .. " bytes)", log_only)
    end

    -- Rule 2: PHPSESSID as a form field (session fixation) - alert only.
    if body:find('name="PHPSESSID"', 1, true) or body:find("name=PHPSESSID", 1, true) then
        ngx.log(ngx.WARN, "php2shell: PHPSESSID in body from ", ngx.var.remote_addr,
                " uri=", ngx.var.request_uri)
    end

    -- Rule 3: PHP code in an upload filename (session injection).
    if (body:find("<?php", 1, true) or body:find("<?=", 1, true))
            and body:find('filename="', 1, true) then
        return block("PHP code in upload filename", log_only)
    end

    -- Rule 4: Structure check - a multipart body with no parsable boundary line
    -- in the inspected prefix suggests padding past the inspection window.
    if not body:find("\r\nContent%-Disposition:") and not body:find("^Content%-Disposition:") then
        ngx.log(ngx.WARN, "php2shell: multipart body with no parsable part in first "
                .. #body .. " bytes (possible padding/evasion) from ",
                ngx.var.remote_addr, " uri=", ngx.var.request_uri)
    end
end

return _M

-- ============================================================================
-- Usage in nginx.conf:
--
--   # Option A: Inline (block mode)
--   access_by_lua_block { require("php2shell").check() }
--
--   # Option B: Log-only (detect without blocking)
--   access_by_lua_block { require("php2shell").check({ log_only = true }) }
--
--   # Option C: Larger inspection window (bigger uploads, more CPU)
--   access_by_lua_block { require("php2shell").check({ max_body_read = 4194304 }) }
--
-- Set client_body_buffer_size / client_max_body_size so bodies you want to
-- inspect stay in memory rather than spilling to disk.
-- ============================================================================
