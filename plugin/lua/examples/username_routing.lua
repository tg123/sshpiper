-- Username-based routing example
-- Routes different users to different upstream servers

function on_password(conn, password)
    local user = conn.user
    
    -- Route alice to server1
    if user == "alice" then
        return {
            host = "server1.example.com:22",
            username = "alice"
        }
    end
    
    -- Route bob to server2
    if user == "bob" then
        return {
            host = "server2.example.com:22",
            username = "bob"
        }
    end
    
    -- Route admin users to admin server
    if user == "admin" or user == "root" then
        return {
            host = "admin.example.com:22",
            username = user,
            ignore_hostkey = false  -- verify host key for admin
        }
    end
    
    -- Default: route to default server
    return {
        host = "default.example.com:22",
        username = user
    }
end

function on_publickey(conn, key)
    -- Public key authentication always goes to secure server
    return {
        host = "secure.example.com:22",
        username = conn.user,
        private_key = "/etc/sshpiper/upstream_key"
    }
end
