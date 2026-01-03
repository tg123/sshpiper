-- Load balancing example
-- Distributes connections across multiple servers

-- Server pool
local servers = {
    "server1.example.com:22",
    "server2.example.com:22",
    "server3.example.com:22"
}

-- Simple counter for round-robin
local counter = 0

function on_password(conn, password)
    -- Increment counter for round-robin
    counter = counter + 1
    local server_idx = (counter % #servers) + 1
    
    local selected_server = servers[server_idx]
    print("Routing " .. conn.sshpiper_user .. " to " .. selected_server)
    
    return {
        host = selected_server,
        username = conn.sshpiper_user
    }
end

function on_publickey(conn, key)
    -- Use same load balancing for public key
    counter = counter + 1
    local server_idx = (counter % #servers) + 1
    
    return {
        host = servers[server_idx],
        username = conn.sshpiper_user,
        private_key_data = "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"
    }
end
