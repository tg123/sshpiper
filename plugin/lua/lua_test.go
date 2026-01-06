//go:build full || e2e

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lua "github.com/yuin/gopher-lua"
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

func TestLuaPluginAdditionalCallbacks(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "callbacks.lua")

	script := `
failure_count = 0
last_pipe_start = ""
last_pipe_error = ""
last_pipe_create_error = ""

function sshpiper_on_new_connection(conn)
    if conn.sshpiper_user == "reject" then
        return "blocked"
    end
    return true
end

function sshpiper_on_next_auth_methods(conn)
    if failure_count > 0 then
        return {"password"}
    end
    return {"publickey"}
end

function sshpiper_on_password(conn, password)
    return {
        host = "localhost:2222",
        username = conn.sshpiper_user,
        ignore_hostkey = true
    }
end

function sshpiper_on_upstream_auth_failure(conn, method, err, allowed)
    failure_count = failure_count + 1
end

function sshpiper_on_banner(conn)
    return "welcome " .. conn.sshpiper_user
end

function sshpiper_on_verify_hostkey(conn, hostname, netaddr, key)
    if hostname == "ok" then
        return true
    end
    return false, "bad host"
end

function sshpiper_on_pipe_create_error(remote_addr, err)
    last_pipe_create_error = remote_addr .. ":" .. err
end

function sshpiper_on_pipe_start(conn)
    last_pipe_start = conn.sshpiper_unique_id
end

function sshpiper_on_pipe_error(conn, err)
    last_pipe_error = conn.sshpiper_unique_id .. ":" .. err
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
		uniqueID:   "test-uid",
	}

	rejectConn := &mockConnMetadata{
		username:   "reject",
		remoteAddr: "192.168.1.101",
		uniqueID:   "reject-uid",
	}

	if config.NewConnectionCallback == nil {
		t.Fatalf("NewConnectionCallback not registered")
	}

	if config.NextAuthMethodsCallback == nil {
		t.Fatalf("NextAuthMethodsCallback not registered")
	}

	if config.UpstreamAuthFailureCallback == nil {
		t.Fatalf("UpstreamAuthFailureCallback not registered")
	}

	if config.BannerCallback == nil {
		t.Fatalf("BannerCallback not registered")
	}

	if config.VerifyHostKeyCallback == nil {
		t.Fatalf("VerifyHostKeyCallback not registered")
	}

	if config.PipeCreateErrorCallback == nil {
		t.Fatalf("PipeCreateErrorCallback not registered")
	}

	if config.PipeStartCallback == nil {
		t.Fatalf("PipeStartCallback not registered")
	}

	if config.PipeErrorCallback == nil {
		t.Fatalf("PipeErrorCallback not registered")
	}

	if err := config.NewConnectionCallback(conn); err != nil {
		t.Fatalf("NewConnectionCallback failed: %v", err)
	}

	if err := config.NewConnectionCallback(rejectConn); err == nil {
		t.Fatalf("NewConnectionCallback should fail for reject user")
	}

	methods, err := config.NextAuthMethodsCallback(conn)
	if err != nil {
		t.Fatalf("NextAuthMethodsCallback failed: %v", err)
	}

	if len(methods) != 1 || methods[0] != "publickey" {
		t.Fatalf("Unexpected methods before failure: %v", methods)
	}

	config.UpstreamAuthFailureCallback(conn, "password", errors.New("bad"), []string{"password"})

	methods, err = config.NextAuthMethodsCallback(conn)
	if err != nil {
		t.Fatalf("NextAuthMethodsCallback failed after failure: %v", err)
	}

	if len(methods) != 1 || methods[0] != "password" {
		t.Fatalf("Unexpected methods after failure: %v", methods)
	}

	if banner := config.BannerCallback(conn); banner != "welcome alice" {
		t.Fatalf("Unexpected banner: %s", banner)
	}

	if err := config.VerifyHostKeyCallback(conn, "ok", "addr", []byte("key")); err != nil {
		t.Fatalf("VerifyHostKeyCallback should succeed: %v", err)
	}

	if err := config.VerifyHostKeyCallback(conn, "bad", "addr", []byte("key")); err == nil {
		t.Fatalf("VerifyHostKeyCallback should fail for bad host")
	}

	config.PipeStartCallback(conn)
	config.PipeErrorCallback(conn, errors.New("boom"))
	config.PipeCreateErrorCallback(conn.RemoteAddr(), errors.New("dial failed"))

	L, err := plugin.getLuaState()
	if err != nil {
		t.Fatalf("failed to get lua state for verification: %v", err)
	}
	defer plugin.putLuaState(L)

	failureCount := L.GetGlobal("failure_count")
	if v, ok := failureCount.(lua.LNumber); !ok || int(v) != 1 {
		t.Fatalf("failure_count not updated, got %v", failureCount)
	}

	if v := L.GetGlobal("last_pipe_start"); v != lua.LString(conn.UniqueID()) {
		t.Fatalf("unexpected last_pipe_start: %v", v)
	}

	if v := L.GetGlobal("last_pipe_error"); v != lua.LString(conn.UniqueID()+":boom") {
		t.Fatalf("unexpected last_pipe_error: %v", v)
	}

	if v := L.GetGlobal("last_pipe_create_error"); v != lua.LString(conn.RemoteAddr()+":dial failed") {
		t.Fatalf("unexpected last_pipe_create_error: %v", v)
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

	if err != nil && !strings.Contains(err.Error(), "no authentication callbacks defined") {
		t.Errorf("Expected error about no callbacks defined, got: %v", err)
	}
}

// TestExampleScriptsValid tests that all example Lua scripts are valid
func TestExampleScriptsValid(t *testing.T) {
	examplesDir := "examples"

	// Check if examples directory exists
	if _, err := os.Stat(examplesDir); os.IsNotExist(err) {
		t.Skip("Examples directory not found")
	}

	// Read all .lua files in examples directory
	files, err := filepath.Glob(filepath.Join(examplesDir, "*.lua"))
	if err != nil {
		t.Fatalf("Failed to read examples directory: %v", err)
	}

	if len(files) == 0 {
		t.Error("No example Lua scripts found in examples directory")
	}

	// Test each example script
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			plugin := newLuaPlugin()
			plugin.ScriptPath = file

			// Try to create config - this validates the script
			_, err := plugin.CreateConfig()
			if err != nil {
				t.Errorf("Example script %s failed to load: %v", filepath.Base(file), err)
			}
		})
	}
}
