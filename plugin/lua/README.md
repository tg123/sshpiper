# Lua Plugin for sshpiperd

The Lua plugin allows you to use Lua scripts to dynamically route SSH connections. This provides maximum flexibility for custom routing logic based on usernames, source IPs, authentication methods, and more.

## Features

- Dynamic routing based on any connection metadata
- Support for both password and public key authentication
- Flexible upstream configuration (host, port, username, authentication)
- Full Lua scripting capabilities for complex routing logic
- High-performance state pooling for concurrent connections

> **Note:** The Lua plugin uses a pool of independent Lua states. Each state has its own isolated global environment, so global variables defined in your Lua script are **not shared** across concurrent connections. For example, a global counter will be local to the Lua state handling a given connection and will not be updated atomically across all requests. Use connection-specific data or stateless logic for thread-safe behavior.

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

### Reloading

The plugin supports hot-reloading of the Lua script without restarting sshpiperd. Send a `SIGHUP` signal to the plugin process to reload the script:

```bash
# Find the plugin process ID
ps aux | grep lua

# Send SIGHUP to reload the script
kill -HUP <pid>
```

When reloaded:
- The script file is validated before reloading
- All existing Lua states in the pool are drained and replaced with new states using the updated script
- Active connections continue using their current state until they complete
- New connections will use the reloaded script

This allows you to update routing logic without interrupting service.

## Lua Script API

Your Lua script should define one or more of these functions:

### `sshpiper_on_noauth(conn)`

Called when a user attempts no authentication (rarely used).

**Parameters:**
- `conn`: Table containing connection metadata
  - `conn.sshpiper_user`: Username of the connecting user
  - `conn.sshpiper_remote_addr`: IP address of the client
  - `conn.sshpiper_unique_id`: Unique identifier for this connection

**Returns:** A table describing the upstream server, or `nil` to reject the connection.

### `sshpiper_on_password(conn, password)`

Called when a user attempts password authentication.

**Parameters:**
- `conn`: Table containing connection metadata
  - `conn.sshpiper_user`: Username of the connecting user
  - `conn.sshpiper_remote_addr`: IP address of the client
  - `conn.sshpiper_unique_id`: Unique identifier for this connection
- `password`: The password provided by the user (string)

**Returns:** A table describing the upstream server, or `nil` to reject the connection.

### `sshpiper_on_publickey(conn, key)`

Called when a user attempts public key authentication.

**Parameters:**
- `conn`: Table containing connection metadata
  - `conn.sshpiper_user`: Username of the connecting user
  - `conn.sshpiper_remote_addr`: IP address of the client
  - `conn.sshpiper_unique_id`: Unique identifier for this connection
- `key`: The public key provided by the user (bytes as string)

**Returns:** A table describing the upstream server, or `nil` to reject the connection.

### `sshpiper_on_keyboard_interactive(conn, challenge)`

Called when a user attempts keyboard-interactive authentication.

**Parameters:**
- `conn`: Table containing connection metadata
  - `conn.sshpiper_user`: Username of the connecting user
  - `conn.sshpiper_remote_addr`: IP address of the client
  - `conn.sshpiper_unique_id`: Unique identifier for this connection
- `challenge`: Function to challenge the user with questions
  - Call as: `answer, err = challenge(user, instruction, question, echo)`
  - Returns the user's answer or an error

**Returns:** A table describing the upstream server, or `nil` to reject the connection.

### `sshpiper_log(level, message)`

Utility function to log messages from your Lua script.

**Parameters:**
- `level`: Log level - one of `"debug"`, `"info"`, `"warn"`, or `"error"`
- `message`: The message to log (string)

**Example:**
```lua
sshpiper_log("info", "Routing user " .. conn.sshpiper_user .. " to server1")
sshpiper_log("debug", "Connection from " .. conn.sshpiper_remote_addr)
sshpiper_log("error", "Failed to route user")
```

### Upstream Table Format

The returned table should contain:

- `host`: **(required)** Upstream SSH server address in `host:port` format
- `username`: *(optional)* Username for the upstream server (defaults to connecting user)
- `ignore_hostkey`: *(optional)* Whether to skip host key verification (default: `false`; set to `true` only in non-production or controlled environments)
- Authentication (one of):
  - `password`: Override password to use for upstream
  - `private_key_data`: Private key data as a PEM-encoded SSH private key string for upstream authentication.
    Supported formats include keys with headers such as:
      - `-----BEGIN OPENSSH PRIVATE KEY-----`
      - `-----BEGIN RSA PRIVATE KEY-----`
      - `-----BEGIN EC PRIVATE KEY-----`
      - `-----BEGIN ED25519 PRIVATE KEY-----`
  - *(none)*: Use the original password from the client

## Examples

### Simple Fixed Target

Route all connections to a single upstream server:

```lua
function sshpiper_on_password(conn, password)
    return {
        host = "192.168.1.100:22",
        username = "admin",
        ignore_hostkey = true  -- skip verification for this example
        -- password will be forwarded to upstream
    }
end

function sshpiper_on_publickey(conn, key)
    return {
        host = "192.168.1.100:22",
        username = "admin",
        private_key_data = "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
        ignore_hostkey = true  -- skip verification for this example
    }
end
```

### Username-Based Routing

Route based on username pattern:

```lua
function sshpiper_on_password(conn, password)
    local user = conn.sshpiper_user
    
    -- Route alice to server1, bob to server2
    if user == "alice" then
        return {
            host = "server1.example.com:22",
            username = "alice_prod",
            ignore_hostkey = true  -- skip verification for this example
        }
    elseif user == "bob" then
        return {
            host = "server2.example.com:22",
            username = "bob_dev",
            ignore_hostkey = true  -- skip verification for this example
        }
    end
    
    -- Reject other users
    return nil
end
```

### IP-Based Access Control

Allow or deny connections based on source IP:

```lua
function sshpiper_on_password(conn, password)
    local remote_addr = conn.sshpiper_remote_addr
    
    -- Only allow connections from internal network
    if string.match(remote_addr, "^192%.168%.") or string.match(remote_addr, "^10%.") then
        return {
            host = "internal-server:22",
            ignore_hostkey = true  -- skip verification for this example
        }
    end
    
    -- Reject external connections
    return nil
end
```

### Complex Routing Logic

Combine multiple conditions:

```lua
-- Server pool for load balancing
local servers = {
    "server1.example.com:22",
    "server2.example.com:22",
    "server3.example.com:22"
}

function sshpiper_on_password(conn, password)
    local user = conn.sshpiper_user
    local remote_addr = conn.sshpiper_remote_addr
    
    -- Admin users go to admin server
    if user == "admin" or user == "root" then
        return {
            host = "admin-server:22",
            username = user,
            ignore_hostkey = false  -- verify host key for admin
        }
    end
    
    -- Regular users get randomly load balanced
    local server_idx = math.random(1, #servers)
    
    return {
        host = servers[server_idx],
        username = user,
        ignore_hostkey = true  -- skip verification for this example
    }
end

function sshpiper_on_publickey(conn, key)
    -- Public key users always go to secure server
    return {
        host = "secure-server:22",
        username = conn.sshpiper_user,
        private_key_data = "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
        ignore_hostkey = true  -- skip verification for this example
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

function sshpiper_on_password(conn, password)
    local mapping = user_map[conn.sshpiper_user]
    
    if mapping then
        return {
            host = mapping.upstream,
            username = mapping.user
        }
    end
    
    -- Default mapping: extract username before dash
    local base_user = string.match(conn.sshpiper_user, "^([^-]+)")
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
- For production, set `ignore_hostkey = false` and configure proper host key verification
- Protect your Lua script file with appropriate file permissions

## Troubleshooting

Enable trace logging to see detailed information about Lua script execution:

```bash
sshpiperd --log-level=trace ./out/lua --script /path/to/script.lua
```

Common issues:

1. **Script not found**: Ensure the path to your Lua script is correct and readable
2. **Function not defined**: Make sure your script defines `sshpiper_on_password` or `sshpiper_on_publickey`
3. **Invalid return value**: Ensure your functions return a table with at least the `host` field
4. **Authentication failure**: Check that you're providing correct credentials for the upstream server
