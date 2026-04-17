-- Docker routing example
--
-- Route incoming SSH connections to Docker containers without storing any
-- sshpiper configuration on the containers themselves (no labels required).
-- The mapping of downstream users to containers and the corresponding
-- authorized_keys files live entirely on the sshpiper host, which makes it
-- easy to manage access centrally and keep container definitions untouched.
--
-- Each entry in `routes` matches a downstream username and describes:
--   * container         - name or ID of the target container (passed to
--                         `docker inspect`).
--   * container_user    - username to use for the upstream SSH connection.
--   * container_port    - sshd port inside the container (default 22).
--   * network           - optional docker network name when the container is
--                         attached to multiple networks.
--   * authorized_keys   - path to an authorized_keys file on the sshpiper
--                         host. The file is loaded fresh on every public-key
--                         attempt, so edits take effect immediately.
--   * private_key       - path to an SSH private key used to authenticate
--                         against the container's sshd. Generate it once and
--                         append the matching public key to the container's
--                         ~/.ssh/authorized_keys.
--
-- NOTE: Containers without sshd inside are not reachable through this Lua
-- example alone. For that use case, start the bundled docker plugin with
-- `sshpiper.docker_exec_cmd=true` on the target container - sshpiper will
-- spawn an internal sshd bridge and `docker exec` into the container. The
-- two plugins can be combined in the same sshpiperd invocation.

local routes = {
    ["alice"] = {
        container = "web",
        container_user = "root",
        authorized_keys = "/etc/sshpiper/authorized_keys/alice",
        private_key = "/etc/sshpiper/keys/alice",
    },
    ["bob"] = {
        container = "db",
        container_user = "postgres",
        container_port = 22,
        authorized_keys = "/etc/sshpiper/authorized_keys/bob",
        private_key = "/etc/sshpiper/keys/bob",
    },
}

-- read_file returns the full contents of `path`, or nil and an error message.
local function read_file(path)
    local f, err = io.open(path, "rb")
    if not f then
        return nil, err
    end
    local data = f:read("*a")
    f:close()
    return data
end

-- shell_quote escapes a single argument for use inside a /bin/sh -c string.
-- Values passed here come from the trusted `routes` table above, not from
-- untrusted downstream input; quoting is applied defensively so typos in
-- names containing spaces or quotes do not break the command.
local function shell_quote(s)
    return "'" .. string.gsub(s, "'", "'\\''") .. "'"
end

-- docker_inspect_ip returns the IPv4 address of `container`. When `network`
-- is non-empty, that specific network is queried; otherwise the container's
-- first non-empty IP is returned. stderr from docker is left attached to
-- sshpiperd's stderr so failures are visible in the logs.
local function docker_inspect_ip(container, network)
    local format
    if network and network ~= "" then
        format = "{{(index .NetworkSettings.Networks " .. shell_quote(network) .. ").IPAddress}}"
    else
        format = "{{range .NetworkSettings.Networks}}{{.IPAddress}}\\n{{end}}"
    end

    local cmd = "docker inspect -f " .. shell_quote(format) .. " " .. shell_quote(container)
    local p = io.popen(cmd, "r")
    if not p then
        return nil, "failed to spawn docker"
    end
    local out = p:read("*a") or ""
    p:close()

    for line in string.gmatch(out, "[^\r\n]+") do
        local ip = string.match(line, "^%s*(.-)%s*$")
        if ip and ip ~= "" then
            return ip
        end
    end
    return nil, "no IP address found for container " .. container
end

-- build_upstream resolves the container IP and returns a sshpiper upstream
-- table for the given route.
local function build_upstream(route)
    local ip, err = docker_inspect_ip(route.container, route.network)
    if not ip then
        sshpiper_log("error", "docker inspect failed: " .. tostring(err))
        return nil
    end

    local private_key_data
    if route.private_key then
        local data, rerr = read_file(route.private_key)
        if not data then
            sshpiper_log("error", "cannot read private key " .. route.private_key .. ": " .. tostring(rerr))
            return nil
        end
        private_key_data = data
    end

    return {
        host = ip .. ":" .. tostring(route.container_port or 22),
        username = route.container_user,
        private_key_data = private_key_data,
        ignore_hostkey = true, -- container host keys are typically ephemeral
    }
end

function sshpiper_on_publickey(conn, key)
    local route = routes[conn.sshpiper_user]
    if not route then
        sshpiper_log("info", "no route defined for user " .. conn.sshpiper_user)
        return nil
    end

    if not route.authorized_keys then
        sshpiper_log("error", "route for " .. conn.sshpiper_user .. " is missing authorized_keys")
        return nil
    end

    local data, err = read_file(route.authorized_keys)
    if not data then
        sshpiper_log("error", "cannot read " .. route.authorized_keys .. ": " .. tostring(err))
        return nil
    end

    local ok, parse_err = sshpiper_match_authorized_keys(key, data)
    if parse_err then
        sshpiper_log("warn", "failed to parse " .. route.authorized_keys .. ": " .. parse_err)
    end
    if not ok then
        return nil
    end

    return build_upstream(route)
end
