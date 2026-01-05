//go:build full || e2e

package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	lua "github.com/yuin/gopher-lua"
)

type luaPlugin struct {
	ScriptPath string
	statePool  *sync.Pool
	mu         sync.RWMutex // protects script reloading
	version    atomic.Uint64 // version counter for reload synchronization
	cancelFunc context.CancelFunc // for cleanup
}

func newLuaPlugin() *luaPlugin {
	return &luaPlugin{}
}

// CreateConfig creates the SSH Piper plugin configuration
func (p *luaPlugin) CreateConfig() (*libplugin.SshPiperPluginConfig, error) {
	// Validate the script exists
	if _, err := os.Stat(p.ScriptPath); err != nil {
		return nil, fmt.Errorf("lua script not found: %w", err)
	}

	// Prime a lua state so we can detect which callbacks exist before
	// wiring them. This lets callbacks be truly optional.
	prime := lua.NewState()
	if err := prime.DoFile(p.ScriptPath); err != nil {
		prime.Close()
		return nil, fmt.Errorf("failed to load lua script: %w", err)
	}

	// Discover which callback functions are present in the script.
	checkFn := func(name string) bool {
		if fn, ok := prime.GetGlobal(name).(*lua.LFunction); ok && fn != nil {
			return true
		}
		return false
	}

	hasNoAuthCallback := checkFn("sshpiper_on_noauth")
	hasPasswordCallback := checkFn("sshpiper_on_password")
	hasPublicKeyCallback := checkFn("sshpiper_on_publickey")
	hasKeyboardInteractive := checkFn("sshpiper_on_keyboard_interactive")

	// Initialize the Lua state pool
	p.statePool = &sync.Pool{
		New: func() interface{} {
			L := lua.NewState(lua.Options{
				SkipOpenLibs: false,
			})
			
			// Redirect stdout to our logger
			L.SetGlobal("print", L.NewFunction(func(L *lua.LState) int {
				top := L.GetTop()
				str := ""
				for i := 1; i <= top; i++ {
					if i > 1 {
						str += "\t"
					}
					str += L.CheckAny(i).String()
				}
				log.Info(str)
				return 0
			}))

			// Inject log function for Lua scripts
			p.injectLogFunction(L)

			// Pre-load the script
			p.mu.RLock()
			scriptPath := p.ScriptPath
			p.mu.RUnlock()

			if err := L.DoFile(scriptPath); err != nil {
				log.Errorf("Failed to load lua script in pool: %v", err)
				L.Close()
				return nil
			}
			return L
		},
	}

	// Inject log function into primed state before reusing it
	// Also inject print() redirect for consistency
	prime.SetGlobal("print", prime.NewFunction(func(L *lua.LState) int {
		top := L.GetTop()
		str := ""
		for i := 1; i <= top; i++ {
			if i > 1 {
				str += "\t"
			}
			str += L.CheckAny(i).String()
		}
		log.Info(str)
		return 0
	}))
	p.injectLogFunction(prime)

	// Reuse the primed state in the pool to avoid reloading.
	p.statePool.Put(prime)

	// Ensure at least one callback is defined
	if !hasNoAuthCallback && !hasPasswordCallback && !hasPublicKeyCallback && !hasKeyboardInteractive {
		return nil, fmt.Errorf("no authentication callbacks defined in Lua script (must define at least one of: sshpiper_on_noauth, sshpiper_on_password, sshpiper_on_publickey, sshpiper_on_keyboard_interactive)")
	}

	config := &libplugin.SshPiperPluginConfig{}

	if hasNoAuthCallback {
		config.NoClientAuthCallback = p.handleNoAuth
	}

	if hasPasswordCallback {
		config.PasswordCallback = p.handlePassword
	}

	if hasPublicKeyCallback {
		config.PublicKeyCallback = p.handlePublicKey
	}

	if hasKeyboardInteractive {
		config.KeyboardInteractiveCallback = p.handleKeyboardInteractive
	}

	return config, nil
}

// getLuaState gets a Lua state from the pool
func (p *luaPlugin) getLuaState() (*lua.LState, uint64, error) {
	p.mu.RLock()
	version := p.version.Load()
	p.mu.RUnlock()
	
	v := p.statePool.Get()
	if v == nil {
		return nil, 0, fmt.Errorf("failed to get Lua state from pool")
	}
	L, ok := v.(*lua.LState)
	if !ok || L == nil {
		return nil, 0, fmt.Errorf("invalid Lua state in pool")
	}
	return L, version, nil
}

// putLuaState returns a Lua state to the pool
func (p *luaPlugin) putLuaState(L *lua.LState) {
	p.statePool.Put(L)
}

// reloadScript reloads the Lua script by draining and repopulating the pool
func (p *luaPlugin) reloadScript() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Validate the script still exists
	if _, err := os.Stat(p.ScriptPath); err != nil {
		return fmt.Errorf("lua script not found: %w", err)
	}

	// Test load the script to ensure it's valid before draining the pool
	testState := lua.NewState()
	if err := testState.DoFile(p.ScriptPath); err != nil {
		testState.Close()
		return fmt.Errorf("failed to reload lua script: %w", err)
	}
	testState.Close()

	// Increment version counter
	p.version.Add(1)

	// Drain the old pool by creating a new one
	// The old states will be garbage collected
	oldPool := p.statePool
	p.statePool = &sync.Pool{
		New: func() interface{} {
			L := lua.NewState(lua.Options{
				SkipOpenLibs: false,
			})
			
			// Redirect stdout to our logger
			L.SetGlobal("print", L.NewFunction(func(L *lua.LState) int {
				top := L.GetTop()
				str := ""
				for i := 1; i <= top; i++ {
					if i > 1 {
						str += "\t"
					}
					str += L.CheckAny(i).String()
				}
				log.Info(str)
				return 0
			}))

			// Inject log function for Lua scripts
			p.injectLogFunction(L)

			// Pre-load the script
			if err := L.DoFile(p.ScriptPath); err != nil {
				log.Errorf("Failed to load lua script in pool: %v", err)
				L.Close()
				return nil
			}
			return L
		},
	}

	// Close all states in the old pool - drain until Get returns nil
	go func() {
		for {
			v := oldPool.Get()
			if v == nil {
				break
			}
			if L, ok := v.(*lua.LState); ok && L != nil {
				L.Close()
			}
		}
	}()

	log.Info("Lua script reloaded successfully")
	return nil
}

// injectLogFunction injects a logging function into the Lua environment
func (p *luaPlugin) injectLogFunction(L *lua.LState) {
	logFn := L.NewFunction(func(L *lua.LState) int {
		level := L.CheckString(1)
		message := L.CheckString(2)

		switch level {
		case "debug":
			log.Debug(message)
		case "info":
			log.Info(message)
		case "warn":
			log.Warn(message)
		case "error":
			log.Error(message)
		default:
			log.Info(message)
		}

		return 0
	})
	L.SetGlobal("sshpiper_log", logFn)
}

// createConnTable creates a Lua table with connection metadata
func (p *luaPlugin) createConnTable(L *lua.LState, conn libplugin.ConnMetadata) *lua.LTable {
	connTable := L.NewTable()
	L.SetField(connTable, "sshpiper_user", lua.LString(conn.User()))
	L.SetField(connTable, "sshpiper_remote_addr", lua.LString(conn.RemoteAddr()))
	L.SetField(connTable, "sshpiper_unique_id", lua.LString(conn.UniqueID()))
	return connTable
}

// handlePassword is called when a user tries to authenticate with a password
func (p *luaPlugin) handlePassword(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
	L, version, err := p.getLuaState()
	if err != nil {
		return nil, err
	}
	defer p.putLuaState(L)

	// Verify the version hasn't changed during reload
	p.mu.RLock()
	currentVersion := p.version.Load()
	p.mu.RUnlock()
	if version != currentVersion {
		// Script was reloaded, get a fresh state
		p.putLuaState(L)
		return p.handlePassword(conn, password)
	}

	// Create a table with connection metadata
	connTable := p.createConnTable(L, conn)

	// Check if the function exists
	fn := L.GetGlobal("sshpiper_on_password")
	if fn == lua.LNil {
		L.Pop(1) // Pop the nil value to avoid stack pollution
		return nil, fmt.Errorf("sshpiper_on_password function not defined in Lua script")
	}

	// Call the sshpiper_on_password function
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, connTable, lua.LString(password)); err != nil {
		return nil, fmt.Errorf("lua error in sshpiper_on_password: %w", err)
	}

	// Get the return value
	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		return nil, fmt.Errorf("authentication failed: no upstream returned")
	}

	upstream, err := p.parseUpstreamTable(L, ret, conn, password)
	if err != nil {
		return nil, err
	}

	log.Infof("routing user %s to %s", conn.User(), upstream.Uri)
	return upstream, nil
}

// handlePublicKey is called when a user tries to authenticate with a public key
func (p *luaPlugin) handlePublicKey(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
	L, version, err := p.getLuaState()
	if err != nil {
		return nil, err
	}
	defer p.putLuaState(L)

	// Verify the version hasn't changed during reload
	p.mu.RLock()
	currentVersion := p.version.Load()
	p.mu.RUnlock()
	if version != currentVersion {
		// Script was reloaded, get a fresh state
		p.putLuaState(L)
		return p.handlePublicKey(conn, key)
	}

	// Create a table with connection metadata
	connTable := p.createConnTable(L, conn)

	// Check if the function exists
	fn := L.GetGlobal("sshpiper_on_publickey")
	if fn == lua.LNil {
		L.Pop(1) // Pop the nil value to avoid stack pollution
		return nil, fmt.Errorf("sshpiper_on_publickey function not defined in Lua script")
	}

	// Call the sshpiper_on_publickey function
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, connTable, lua.LString(key)); err != nil {
		return nil, fmt.Errorf("lua error in sshpiper_on_publickey: %w", err)
	}

	// Get the return value
	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		return nil, fmt.Errorf("authentication failed: no upstream returned")
	}

	upstream, err := p.parseUpstreamTable(L, ret, conn, nil)
	if err != nil {
		return nil, err
	}

	log.Infof("routing user %s to %s", conn.User(), upstream.Uri)
	return upstream, nil
}

// parseUpstreamTable parses a Lua table into an Upstream struct
func (p *luaPlugin) parseUpstreamTable(L *lua.LState, value lua.LValue, conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
	table, ok := value.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("expected table return value, got %s", value.Type())
	}

	// Extract host (required)
	hostVal := L.GetField(table, "host")
	if hostVal == lua.LNil {
		return nil, fmt.Errorf("host field is required in upstream table")
	}
	hostStr, ok := hostVal.(lua.LString)
	if !ok {
		return nil, fmt.Errorf("host must be a string")
	}

	// Parse host:port and create URI
	host, port, err := libplugin.SplitHostPortForSSH(string(hostStr))
	if err != nil {
		return nil, fmt.Errorf("invalid host:port format: %w", err)
	}

	// grpc plugin expects a URI with a transport scheme; default to tcp.
	upstream := &libplugin.Upstream{
		Uri:           fmt.Sprintf("tcp://%s:%d", host, port),
		IgnoreHostKey: false, // default to false for security
	}

	// Extract username (optional, defaults to connecting user)
	usernameVal := L.GetField(table, "username")
	if usernameVal != lua.LNil {
		if username, ok := usernameVal.(lua.LString); ok {
			upstream.UserName = string(username)
		}
	} else {
		// Use the connecting user's username as default
		upstream.UserName = conn.User()
	}

	// Extract ignore_hostkey (optional)
	ignoreHostKeyVal := L.GetField(table, "ignore_hostkey")
	if ignoreHostKeyVal != lua.LNil {
		if ignoreHostKey, ok := ignoreHostKeyVal.(lua.LBool); ok {
			upstream.IgnoreHostKey = bool(ignoreHostKey)
		}
	}

	// Handle authentication
	privateKeyDataVal := L.GetField(table, "private_key_data")

	if privateKeyDataVal != lua.LNil {
		// Use private key authentication
		if pkData, ok := privateKeyDataVal.(lua.LString); ok {
			privateKeyData := []byte(pkData)
			if len(privateKeyData) == 0 {
				return nil, fmt.Errorf("private key data is empty")
			}
			upstream.Auth = libplugin.CreatePrivateKeyAuth(privateKeyData, nil)
		} else {
			return nil, fmt.Errorf("private_key_data must be a string")
		}
	} else {
		// Use password authentication
		passwordVal := L.GetField(table, "password")
		if passwordVal != lua.LNil {
			if pwd, ok := passwordVal.(lua.LString); ok {
				upstream.Auth = libplugin.CreatePasswordAuth([]byte(pwd))
			}
		} else if password != nil {
			// Use the original password
			upstream.Auth = libplugin.CreatePasswordAuth(password)
		} else {
			return nil, fmt.Errorf("no authentication method specified")
		}
	}

	return upstream, nil
}

// handleNoAuth is called when a user tries no authentication
func (p *luaPlugin) handleNoAuth(conn libplugin.ConnMetadata) (*libplugin.Upstream, error) {
	L, version, err := p.getLuaState()
	if err != nil {
		return nil, err
	}
	defer p.putLuaState(L)

	// Verify the version hasn't changed during reload
	p.mu.RLock()
	currentVersion := p.version.Load()
	p.mu.RUnlock()
	if version != currentVersion {
		// Script was reloaded, get a fresh state
		p.putLuaState(L)
		return p.handleNoAuth(conn)
	}

	// Create a table with connection metadata
	connTable := p.createConnTable(L, conn)

	// Check if the function exists
	fn := L.GetGlobal("sshpiper_on_noauth")
	if fn == lua.LNil {
		L.Pop(1) // Pop the nil value to avoid stack pollution
		return nil, fmt.Errorf("sshpiper_on_noauth function not defined in Lua script")
	}

	// Call the sshpiper_on_noauth function
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, connTable); err != nil {
		return nil, fmt.Errorf("lua error in sshpiper_on_noauth: %w", err)
	}

	// Get the return value
	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		return nil, fmt.Errorf("authentication failed: no upstream returned")
	}

	upstream, err := p.parseUpstreamTable(L, ret, conn, nil)
	if err != nil {
		return nil, err
	}

	log.Infof("routing user %s to %s (noauth)", conn.User(), upstream.Uri)
	return upstream, nil
}

// handleKeyboardInteractive is called when a user tries keyboard-interactive authentication
func (p *luaPlugin) handleKeyboardInteractive(conn libplugin.ConnMetadata, client libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {
	L, version, err := p.getLuaState()
	if err != nil {
		return nil, err
	}
	defer p.putLuaState(L)

	// Verify the version hasn't changed during reload
	p.mu.RLock()
	currentVersion := p.version.Load()
	p.mu.RUnlock()
	if version != currentVersion {
		// Script was reloaded, get a fresh state
		p.putLuaState(L)
		return p.handleKeyboardInteractive(conn, client)
	}

	// Create a table with connection metadata
	connTable := p.createConnTable(L, conn)

	// Create a challenge function that can be called from Lua
	challengeFn := L.NewFunction(func(L *lua.LState) int {
		user := L.CheckString(1)
		instruction := L.CheckString(2)
		question := L.CheckString(3)
		echo := L.CheckBool(4)

		answer, err := client(user, instruction, question, echo)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}

		L.Push(lua.LString(answer))
		L.Push(lua.LNil)
		return 2
	})

	// Check if the function exists
	fn := L.GetGlobal("sshpiper_on_keyboard_interactive")
	if fn == lua.LNil {
		L.Pop(1) // Pop the nil value to avoid stack pollution
		return nil, fmt.Errorf("sshpiper_on_keyboard_interactive function not defined in Lua script")
	}

	// Call the sshpiper_on_keyboard_interactive function
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, connTable, challengeFn); err != nil {
		return nil, fmt.Errorf("lua error in sshpiper_on_keyboard_interactive: %w", err)
	}

	// Get the return value
	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		return nil, fmt.Errorf("authentication failed: no upstream returned")
	}

	upstream, err := p.parseUpstreamTable(L, ret, conn, nil)
	if err != nil {
		return nil, err
	}

	log.Infof("routing user %s to %s (keyboard-interactive)", conn.User(), upstream.Uri)
	return upstream, nil
}
