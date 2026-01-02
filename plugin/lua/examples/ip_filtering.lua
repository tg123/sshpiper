-- IP-based access control example
-- Only allows connections from specific IP ranges

function on_password(conn, password)
    local remote_addr = conn.remote_addr
    
    -- Allow internal networks (192.168.x.x and 10.x.x.x)
    if string.match(remote_addr, "^192%.168%.") or string.match(remote_addr, "^10%.") then
        return {
            host = "internal-server.example.com:22",
            username = conn.user
        }
    end
    
    -- Allow specific external IP
    if string.match(remote_addr, "^203%.0%.113%.") then
        return {
            host = "external-server.example.com:22",
            username = conn.user
        }
    end
    
    -- Reject all other connections
    print("Rejecting connection from " .. remote_addr)
    return nil
end

function on_publickey(conn, key)
    -- Apply same IP filtering for public key auth
    local remote_addr = conn.remote_addr
    
    if string.match(remote_addr, "^192%.168%.") or string.match(remote_addr, "^10%.") then
        return {
            host = "internal-server.example.com:22",
            username = conn.user,
            private_key = "/etc/sshpiper/upstream_key"
        }
    end
    
    return nil
end
