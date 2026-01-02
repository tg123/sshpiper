# Lua Plugin for sshpiperd

The Lua plugin allows you to use Lua scripts to dynamically route SSH connections. This provides maximum flexibility for custom routing logic based on usernames, source IPs, authentication methods, and more.

## Features

- Dynamic routing based on any connection metadata
- Support for both password and public key authentication
- Flexible upstream configuration (host, port, username, authentication)
- Full Lua scripting capabilities for complex routing logic

## Installation

The Lua plugin is built as part of the sshpiper project:

```bash
go build -tags full -o out ./...
```

## Usage

```bash
sshpiperd [sshpiperd options] ./out/lua --script /path/to/script.lua
```

### Plugin Options

- `--script`: Path to the Lua script file (required) - can also be set via `SSHPIPERD_LUA_SCRIPT` environment variable

## Lua Script API

Your Lua script should define one or both of these functions:

### `on_password(conn, password)`

Called when a user attempts password authentication.

**Parameters:**
- `conn`: Table containing connection metadata
  - `conn.user`: Username of the connecting user
  - `conn.remote_addr`: IP address of the client
  - `conn.unique_id`: Unique identifier for this connection
- `password`: The password provided by the user (string)

**Returns:** A table describing the upstream server, or `nil` to reject the connection.

### `on_publickey(conn, key)`

Called when a user attempts public key authentication.

**Parameters:**
- `conn`: Table containing connection metadata
  - `conn.user`: Username of the connecting user
  - `conn.remote_addr`: IP address of the client
  - `conn.unique_id`: Unique identifier for this connection
- `key`: The public key provided by the user (bytes as string)

**Returns:** A table describing the upstream server, or `nil` to reject the connection.

### Upstream Table Format

The returned table should contain:

- `host`: **(required)** Upstream SSH server address in `host:port` format
- `username`: *(optional)* Username for the upstream server (defaults to connecting user)
- `ignore_hostkey`: *(optional)* Whether to skip host key verification (default: `true`)
- Authentication (one of):
  - `password`: Override password to use for upstream
  - `private_key`: Path to private key file for upstream authentication
  - `private_key_data`: Private key data as string for upstream authentication
  - *(none)*: Use the original password from the client

## Examples

### Simple Fixed Target

Route all connections to a single upstream server:

```lua
function on_password(conn, password)
    return {
        host = "192.168.1.100:22",
        username = "admin"
        -- password will be forwarded to upstream
    }
end

function on_publickey(conn, key)
    return {
        host = "192.168.1.100:22",
        username = "admin",
        private_key = "/path/to/upstream/key"
    }
end
```

### Username-Based Routing

Route based on username pattern:

```lua
function on_password(conn, password)
    local user = conn.user
    
    -- Route alice to server1, bob to server2
    if user == "alice" then
        return {
            host = "server1.example.com:22",
            username = "alice_prod"
        }
    elseif user == "bob" then
        return {
            host = "server2.example.com:22",
            username = "bob_dev"
        }
    end
    
    -- Reject other users
    return nil
end
```

### IP-Based Access Control

Allow or deny connections based on source IP:

```lua
function on_password(conn, password)
    local remote_addr = conn.remote_addr
    
    -- Only allow connections from internal network
    if string.match(remote_addr, "^192%.168%.") or string.match(remote_addr, "^10%.") then
        return {
            host = "internal-server:22"
        }
    end
    
    -- Reject external connections
    return nil
end
```

### Complex Routing Logic

Combine multiple conditions:

```lua
-- Load balancing pool
local servers = {
    "server1.example.com:22",
    "server2.example.com:22",
    "server3.example.com:22"
}

-- Simple round-robin counter
local counter = 0

function on_password(conn, password)
    local user = conn.user
    local remote_addr = conn.remote_addr
    
    -- Admin users go to admin server
    if user == "admin" or user == "root" then
        return {
            host = "admin-server:22",
            username = user,
            ignore_hostkey = false  -- verify host key for admin
        }
    end
    
    -- Regular users get load balanced
    counter = counter + 1
    local server_idx = (counter % #servers) + 1
    
    return {
        host = servers[server_idx],
        username = user
    }
end

function on_publickey(conn, key)
    -- Public key users always go to secure server
    return {
        host = "secure-server:22",
        username = conn.user,
        private_key = "/etc/sshpiper/upstream_key"
    }
end
```

### User Mapping

Map downstream users to different upstream users:

```lua
-- User mapping table
local user_map = {
    ["dev-alice"] = { upstream = "server1:22", user = "alice" },
    ["dev-bob"] = { upstream = "server2:22", user = "bob" },
    ["prod-alice"] = { upstream = "prod-server:22", user = "alice" }
}

function on_password(conn, password)
    local mapping = user_map[conn.user]
    
    if mapping then
        return {
            host = mapping.upstream,
            username = mapping.user
        }
    end
    
    -- Default mapping: extract username before dash
    local base_user = string.match(conn.user, "^([^-]+)")
    if base_user then
        return {
            host = "default-server:22",
            username = base_user
        }
    end
    
    return nil
end
```

## Error Handling

If your Lua script encounters an error or returns `nil`, the connection will be rejected. Make sure to:

1. Always return a valid upstream table for successful authentication
2. Return `nil` to explicitly reject a connection
3. Handle errors gracefully in your Lua code

## Security Considerations

- The Lua script runs with the same permissions as sshpiperd
- Be careful with file system access in your Lua scripts
- Validate and sanitize any user input used in routing decisions
- Consider using `ignore_hostkey = false` and proper host key verification for production
- Protect your Lua script file with appropriate file permissions

## Troubleshooting

Enable trace logging to see detailed information about Lua script execution:

```bash
sshpiperd --log-level=trace ./out/lua --script /path/to/script.lua
```

Common issues:

1. **Script not found**: Ensure the path to your Lua script is correct and readable
2. **Function not defined**: Make sure your script defines `on_password` or `on_publickey`
3. **Invalid return value**: Ensure your functions return a table with at least the `host` field
4. **Authentication failure**: Check that you're providing correct credentials for the upstream server
