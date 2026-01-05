//go:build full || e2e

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Mock connection metadata for testing
type mockConnMetadata struct {
	username   string
	remoteAddr string
	uniqueID   string
}

func (m *mockConnMetadata) User() string {
	return m.username
}

func (m *mockConnMetadata) RemoteAddr() string {
	return m.remoteAddr
}

func (m *mockConnMetadata) UniqueID() string {
	return m.uniqueID
}

func (m *mockConnMetadata) GetMeta(key string) string {
	return ""
}

func TestLuaPluginSimpleScript(t *testing.T) {
	// Create a temporary Lua script
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test.lua")

	script := `
function sshpiper_on_password(conn, password)
    return {
        host = "localhost:2222",
        username = "testuser",
        ignore_hostkey = true
    }
end
`

	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	// Create plugin
	plugin := &luaPlugin{
		ScriptPath: scriptPath,
	}

	// Create config
	config, err := plugin.CreateConfig()
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	if config.PasswordCallback == nil {
		t.Fatal("PasswordCallback is nil")
	}

	// Test password callback
	conn := &mockConnMetadata{
		username:   "alice",
		remoteAddr: "192.168.1.100",
		uniqueID:   "test-123",
	}

	upstream, err := config.PasswordCallback(conn, []byte("password"))
	if err != nil {
		t.Fatalf("PasswordCallback failed: %v", err)
	}

	if upstream.Uri != "tcp://localhost:2222" {
		t.Errorf("Expected URI 'tcp://localhost:2222', got '%s'", upstream.Uri)
	}

	if upstream.UserName != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", upstream.UserName)
	}
}

func TestLuaPluginUsernameRouting(t *testing.T) {
	// Create a temporary Lua script with username-based routing
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test.lua")

	script := `
function sshpiper_on_password(conn, password)
    if conn.sshpiper_user == "alice" then
        return {
            host = "server1:22",
            username = "alice_remote",
            ignore_hostkey = true
        }
    elseif conn.sshpiper_user == "bob" then
        return {
            host = "server2:22",
            username = "bob_remote",
            ignore_hostkey = true
        }
    end
    return nil
end
`

	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	// Create plugin
	plugin := &luaPlugin{
		ScriptPath: scriptPath,
	}

	config, err := plugin.CreateConfig()
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Test alice
	connAlice := &mockConnMetadata{
		username:   "alice",
		remoteAddr: "192.168.1.100",
		uniqueID:   "test-alice",
	}

	upstream, err := config.PasswordCallback(connAlice, []byte("password"))
	if err != nil {
		t.Fatalf("PasswordCallback failed for alice: %v", err)
	}

	if upstream.Uri != "tcp://server1:22" {
		t.Errorf("Expected URI 'tcp://server1:22' for alice, got '%s'", upstream.Uri)
	}

	if upstream.UserName != "alice_remote" {
		t.Errorf("Expected username 'alice_remote', got '%s'", upstream.UserName)
	}

	// Test bob
	connBob := &mockConnMetadata{
		username:   "bob",
		remoteAddr: "192.168.1.101",
		uniqueID:   "test-bob",
	}

	upstream, err = config.PasswordCallback(connBob, []byte("password"))
	if err != nil {
		t.Fatalf("PasswordCallback failed for bob: %v", err)
	}

	if upstream.Uri != "tcp://server2:22" {
		t.Errorf("Expected URI 'tcp://server2:22' for bob, got '%s'", upstream.Uri)
	}

	if upstream.UserName != "bob_remote" {
		t.Errorf("Expected username 'bob_remote', got '%s'", upstream.UserName)
	}

	// Test unknown user (should fail)
	connUnknown := &mockConnMetadata{
		username:   "charlie",
		remoteAddr: "192.168.1.102",
		uniqueID:   "test-charlie",
	}

	_, err = config.PasswordCallback(connUnknown, []byte("password"))
	if err == nil {
		t.Error("Expected error for unknown user, got nil")
	}
}

func TestLuaPluginMissingScript(t *testing.T) {
	plugin := &luaPlugin{
		ScriptPath: "/nonexistent/script.lua",
	}

	_, err := plugin.CreateConfig()
	if err == nil {
		t.Error("Expected error for missing script, got nil")
	}
}

func TestLuaPluginInvalidReturn(t *testing.T) {
	// Create a temporary Lua script with invalid return
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test.lua")

	script := `
function sshpiper_on_password(conn, password)
    return "not a table"
end
`

	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	plugin := &luaPlugin{
		ScriptPath: scriptPath,
	}

	config, err := plugin.CreateConfig()
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	conn := &mockConnMetadata{
		username:   "alice",
		remoteAddr: "192.168.1.100",
		uniqueID:   "test-123",
	}

	_, err = config.PasswordCallback(conn, []byte("password"))
	if err == nil {
		t.Error("Expected error for invalid return type, got nil")
	}
}

func TestLuaPluginConcurrency(t *testing.T) {
	// Create a temporary Lua script
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test.lua")

	script := `
function sshpiper_on_password(conn, password)
    return {
        host = "localhost:2222",
        username = conn.sshpiper_user,
        ignore_hostkey = true
    }
end
`

	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	plugin := &luaPlugin{
		ScriptPath: scriptPath,
	}

	config, err := plugin.CreateConfig()
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Test concurrent authentication requests
	const numGoroutines = 10
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			conn := &mockConnMetadata{
				username:   fmt.Sprintf("user%d", id),
				remoteAddr: "192.168.1.100",
				uniqueID:   fmt.Sprintf("test-%d", id),
			}

			upstream, err := config.PasswordCallback(conn, []byte("password"))
			if err != nil {
				errors <- err
				return
			}

			if upstream.UserName != conn.User() {
				errors <- fmt.Errorf("expected username %s, got %s", conn.User(), upstream.UserName)
				return
			}

			errors <- nil
		}(i)
	}

	// Check all results
	for i := 0; i < numGoroutines; i++ {
		if err := <-errors; err != nil {
			t.Errorf("Goroutine failed: %v", err)
		}
	}
}

func TestLuaPluginNoCallbacks(t *testing.T) {
	// Create a temporary Lua script with no callbacks defined
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test.lua")

	script := `
-- No callbacks defined
local x = 1 + 1
`

	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	plugin := &luaPlugin{
		ScriptPath: scriptPath,
	}

	_, err := plugin.CreateConfig()
	if err == nil {
		t.Error("Expected error when no callbacks are defined, got nil")
	}

	if err != nil && err.Error() != "no authentication callbacks defined in Lua script (must define at least one of: sshpiper_on_noauth, sshpiper_on_password, sshpiper_on_publickey, sshpiper_on_keyboard_interactive)" {
		t.Errorf("Expected specific error message, got: %v", err)
	}
}
