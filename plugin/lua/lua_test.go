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
function on_password(conn, password)
    return {
        host = "localhost:2222",
        username = "testuser"
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

	if upstream.Host != "localhost" {
		t.Errorf("Expected host 'localhost', got '%s'", upstream.Host)
	}

	if upstream.Port != 2222 {
		t.Errorf("Expected port 2222, got %d", upstream.Port)
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
function on_password(conn, password)
    if conn.user == "alice" then
        return {
            host = "server1:22",
            username = "alice_remote"
        }
    elseif conn.user == "bob" then
        return {
            host = "server2:22",
            username = "bob_remote"
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

	if upstream.Host != "server1" {
		t.Errorf("Expected host 'server1' for alice, got '%s'", upstream.Host)
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

	if upstream.Host != "server2" {
		t.Errorf("Expected host 'server2' for bob, got '%s'", upstream.Host)
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
function on_password(conn, password)
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
function on_password(conn, password)
    return {
        host = "localhost:2222",
        username = conn.user
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
