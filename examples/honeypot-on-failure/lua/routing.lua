-- Demo: redirect to a honeypot when the password is wrong.
--
-- The "real" credential is hardcoded here for demo purposes only:
--     username = demo
--     password = pass
--
-- A correct username/password pair is forwarded to the real sshd.
-- Anything else is silently routed to the cowrie SSH honeypot, which
-- happily accepts almost any password and presents a fake shell.
--
-- ⚠️ Do not hardcode credentials in production. This demo exists only
-- to illustrate how `sshpiper_on_password` can choose the upstream
-- based on the supplied password.

local valid_users = {
    demo = "pass",
}

function sshpiper_on_password(conn, password)
    local expected = valid_users[conn.sshpiper_user]
    if expected ~= nil and password == expected then
        return {
            host = "sshd:2222",
            ignore_hostkey = true,
        }
    end

    -- Wrong password (or unknown user): send the attacker to the honeypot.
    -- We rewrite the username to "root" because cowrie's default userdb
    -- accepts almost any password for "root", so the original password
    -- typed by the client is forwarded as-is and the honeypot login
    -- succeeds.
    return {
        host = "honeypot:2222",
        username = "root",
        ignore_hostkey = true,
    }
end
