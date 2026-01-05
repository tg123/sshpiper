-- Load balancing example
-- Distributes connections across multiple servers using random selection

-- Server pool
local servers = {
    "server1.example.com:22",
    "server2.example.com:22",
    "server3.example.com:22"
}

-- Seed random number generator with current time
math.randomseed(os.time())

function sshpiper_on_password(conn, password)
    -- Select a random server
    local server_idx = math.random(1, #servers)
    
    local selected_server = servers[server_idx]
    print("Routing " .. conn.sshpiper_user .. " to " .. selected_server)
    
    return {
        host = selected_server,
        username = conn.sshpiper_user,
        ignore_hostkey = true
    }
end

function sshpiper_on_publickey(conn, key)
    -- Use same random load balancing for public key
    local server_idx = math.random(1, #servers)
    
    return {
        host = servers[server_idx],
        username = conn.sshpiper_user,
        private_key_data = "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
        ignore_hostkey = true
    }
end
