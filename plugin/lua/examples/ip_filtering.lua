-- IP-based access control example
-- Only allows connections from specific IP ranges

function on_password(conn, password)
    local remote_addr = conn.sshpiper_remote_addr
    
    -- Allow internal networks (192.168.x.x and 10.x.x.x)
    if string.match(remote_addr, "^192%.168%.") or string.match(remote_addr, "^10%.") then
        return {
            host = "internal-server.example.com:22",
            username = conn.sshpiper_user
        }
    end
    
    -- Allow specific external IP
    if string.match(remote_addr, "^203%.0%.113%.") then
        return {
            host = "external-server.example.com:22",
            username = conn.sshpiper_user
        }
    end
    
    -- Reject all other connections
    print("Rejecting connection from " .. remote_addr)
    return nil
end

function on_publickey(conn, key)
    -- Apply same IP filtering for public key auth
    local remote_addr = conn.sshpiper_remote_addr
    
    if string.match(remote_addr, "^192%.168%.") or string.match(remote_addr, "^10%.") then
        return {
            host = "internal-server.example.com:22",
            username = conn.sshpiper_user,
            private_key_data = "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"
        }
    end
    
    return nil
end
