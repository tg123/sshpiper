-- Simple fixed target example
-- This routes all connections to a single upstream server

function on_password(conn, password)
    return {
        host = "127.0.0.1:2222",
        username = "user"
    }
end

function on_publickey(conn, key)
    return {
        host = "127.0.0.1:2222",
        username = "user",
        private_key = "/path/to/upstream/key"
    }
end
