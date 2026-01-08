package e2e_test

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

const luaScriptTemplate = `
-- Lua script for e2e testing

function sshpiper_on_new_connection(conn)
    if conn.sshpiper_user == "lua_blocked" then
        return "blocked"
    end
    return true
end

function sshpiper_on_noauth(conn)
    -- Allow none auth for specific user
    if conn.sshpiper_user == "lua_noauth_user" then
        return {
            host = "host-password:2222",
            username = "user",
            password = "pass",
            ignore_hostkey = true
        }
    end
    
    -- Reject other users trying none auth
    return nil
end

function sshpiper_on_password(conn, password)
    -- Route based on username
    if conn.sshpiper_user == "lua_password_simple" then
        return {
            host = "host-password:2222",
            username = "user",
            ignore_hostkey = true
        }
    end
    
    -- Route with username mapping
    if conn.sshpiper_user == "lua_mapped_user" then
        return {
            host = "host-password:2222",
            username = "user",
            ignore_hostkey = true
        }
    end
    
    -- Route to publickey host using password auth downstream
    -- but private key auth upstream
    if conn.sshpiper_user == "lua_password_to_publickey" then
        return {
            host = "host-publickey:2222",
            username = "user",
            private_key_data = [[%s]],
            ignore_hostkey = true
        }
    end
    
    -- Reject unknown users
    return nil
end

function sshpiper_on_publickey(conn, key)
    -- Accept publickey auth for specific user
    if conn.sshpiper_user == "lua_publickey_user" then
        return {
            host = "host-password:2222",
            username = "user",
            password = "pass",
            ignore_hostkey = true
        }
    end
    
    -- Reject other users
    return nil
end

function sshpiper_on_keyboard_interactive(conn, challenge)
    -- Accept keyboard-interactive for specific user
    if conn.sshpiper_user == "lua_kbdint_user" then
        -- Challenge the user
        local answer, err = challenge(conn.sshpiper_user, "Enter your response:", "Response:", true)
        
        -- Accept any response (for testing purposes)
        if answer and type(answer) == "string" then
            return {
                host = "host-password:2222",
                username = "user",
                password = "pass",
                ignore_hostkey = true
            }
        end
    end
    
    -- Reject other users
    return nil
end
`

func TestLua(t *testing.T) {
	luadir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(luadir)

	// Generate SSH keys for upstream authentication
	if err := runCmdAndWait("rm", "-f", path.Join(luadir, "id_rsa")); err != nil {
		t.Errorf("failed to remove id_rsa: %v", err)
	}

	if err := runCmdAndWait(
		"ssh-keygen",
		"-N",
		"",
		"-f",
		path.Join(luadir, "id_rsa"),
	); err != nil {
		t.Errorf("failed to generate private key: %v", err)
	}

	// Copy public key to authorized_keys for upstream server
	if err := runCmdAndWait(
		"/bin/cp",
		path.Join(luadir, "id_rsa.pub"),
		"/publickey_authorized_keys/authorized_keys",
	); err != nil {
		t.Errorf("failed to copy public key: %v", err)
	}

	// Read the private key data
	privateKeyData, err := os.ReadFile(path.Join(luadir, "id_rsa"))
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}

	// Create Lua script with private key data embedded
	luaScript := fmt.Sprintf(luaScriptTemplate, string(privateKeyData))
	luaScriptPath := path.Join(luadir, "routing.lua")

	if err := os.WriteFile(luaScriptPath, []byte(luaScript), 0o644); err != nil {
		t.Fatalf("Failed to write Lua script: %v", err)
	}

	// Dump Lua script to stdout for debugging
	_ = runCmdAndWait("cat", "-n", luaScriptPath)

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/lua",
		"--script",
		luaScriptPath,
	)
	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)
	waitForEndpointReady(piperaddr)

	t.Run("password_simple", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()

		c, stdin, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"lua_password_simple",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfile, randtext)
	})

	t.Run("password_with_user_mapping", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()

		c, stdin, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"lua_mapped_user",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfile, randtext)
	})

	t.Run("publickey_simple", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()

		c, stdin, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"lua_password_to_publickey",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		// Client uses password auth, but lua routes to publickey upstream with private key
		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfile, randtext)
	})

	t.Run("reject_unknown_user", func(t *testing.T) {
		c, stdin, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-o",
			"PreferredAuthentications=password",
			"-p",
			piperport,
			"-l",
			"unknown_user",
			"127.0.0.1",
			"echo test",
		)
		if err != nil {
			t.Errorf("failed to start ssh to piper, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "wrongpass")
		enterPassword(stdin, stdout, "wrongpass")
		enterPassword(stdin, stdout, "wrongpass")

		// The command should fail (exit with non-zero)
		err = c.Wait()
		if err == nil {
			t.Error("expected authentication to fail for unknown user, but it succeeded")
		}
	})

	t.Run("noauth_method", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()

		c, _, _, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-o",
			"PreferredAuthentications=none",
			"-p",
			piperport,
			"-l",
			"lua_noauth_user",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		// Wait for command to complete
		err = c.Wait()
		if err != nil {
			t.Errorf("ssh command failed: %v", err)
		}

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfile, randtext)
	})

	t.Run("publickey_auth", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()

		// Generate a keypair for client authentication
		clientKeyPath := path.Join(luadir, "client_key")
		if err := runCmdAndWait("rm", "-f", clientKeyPath); err != nil {
			t.Errorf("failed to remove client key: %v", err)
		}

		if err := runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			clientKeyPath,
		); err != nil {
			t.Errorf("failed to generate client key: %v", err)
		}

		c, _, _, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-o",
			"PreferredAuthentications=publickey",
			"-i",
			clientKeyPath,
			"-p",
			piperport,
			"-l",
			"lua_publickey_user",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		// Wait for command to complete
		err = c.Wait()
		if err != nil {
			t.Errorf("ssh command failed: %v", err)
		}

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfile, randtext)
	})

	t.Run("keyboard_interactive", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()

		c, stdin, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-o",
			"PreferredAuthentications=keyboard-interactive",
			"-p",
			piperport,
			"-l",
			"lua_kbdint_user",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		// Respond to the keyboard-interactive challenge
		waitForStdoutContains(stdout, "Response:", func(_ string) {
			stdin.Write([]byte("test_response\n"))
		})

		// Wait for command to complete
		err = c.Wait()
		if err != nil {
			t.Errorf("ssh command failed: %v", err)
		}

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfile, randtext)
	})

	t.Run("new_connection_block", func(t *testing.T) {
		c, stdin, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"lua_blocked",
			"127.0.0.1",
			"true",
		)
		if err != nil {
			t.Fatalf("failed to start ssh: %v", err)
		}
		defer killCmd(c)
		_ = stdin

		buf := new(strings.Builder)
		doneCopy := make(chan struct{})
		go func() {
			_, _ = io.Copy(buf, stdout)
			close(doneCopy)
		}()

		doneWait := make(chan error, 1)
		go func() {
			doneWait <- c.Wait()
		}()

		select {
		case err := <-doneWait:
			select {
			case <-doneCopy:
			case <-time.After(2 * time.Second):
			}
			if err == nil {
				t.Fatalf("blocked user should fail, but ssh exited successfully")
			} else if !strings.Contains(buf.String(), "blocked") {
				t.Fatalf("expected blocked message in ssh output, got: %s", buf.String())
			}
		case <-time.After(15 * time.Second):
			killCmd(c)
			select {
			case <-doneCopy:
			case <-time.After(2 * time.Second):
			}
			t.Fatalf("blocked user did not fail quickly; output so far: %s", buf.String())
		}
	})
}
