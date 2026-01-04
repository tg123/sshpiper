//go:build full || e2e

package main

import (
	"fmt"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	lua "github.com/yuin/gopher-lua"
	ssh "golang.org/x/crypto/ssh"
)

type luaPlugin struct {
	ScriptPath string
	statePool  *sync.Pool
	authFailed sync.Map

	hasNoAuthCallback      bool
	hasPasswordCallback    bool
	hasPublicKeyCallback   bool
	hasKeyboardInteractive bool
}

func newLuaPlugin() *luaPlugin {
	return &luaPlugin{}
}

func (p *luaPlugin) markAuthFailed(conn libplugin.ConnMetadata) {
	if conn == nil {
		return
	}

	if id := conn.UniqueID(); id != "" {
		p.authFailed.Store(id, struct{}{})
	}
}

func (p *luaPlugin) hasAuthFailed(conn libplugin.ConnMetadata) bool {
	if conn == nil {
		return false
	}

	id := conn.UniqueID()
	if id == "" {
		return false
	}

	_, ok := p.authFailed.Load(id)
	return ok
}

func callbackNotDefined(name string) error {
	return fmt.Errorf("lua callback %s not defined in script", name)
}

func authFailed(msg string) error {
	return ssh.NoMoreMethodsErr{Allowed: []string{}}
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

	p.hasNoAuthCallback = checkFn("sshpiper_on_noauth")
	p.hasPasswordCallback = checkFn("sshpiper_on_password")
	p.hasPublicKeyCallback = checkFn("sshpiper_on_publickey")
	p.hasKeyboardInteractive = checkFn("sshpiper_on_keyboard_interactive")

	// Initialize the Lua state pool
	p.statePool = &sync.Pool{
		New: func() interface{} {
			L := lua.NewState()
			// Pre-load the script
			if err := L.DoFile(p.ScriptPath); err != nil {
				log.Errorf("Failed to load lua script in pool: %v", err)
				L.Close()
				return nil
			}
			return L
		},
	}

	// Reuse the primed state in the pool to avoid reloading.
	p.statePool.Put(prime)

	config := &libplugin.SshPiperPluginConfig{
		// Fail fast on auth failures to avoid multi-prompt loops.
		NextAuthMethodsCallback: p.nextAuthMethods,
	}

	if p.hasNoAuthCallback {
		config.NoClientAuthCallback = p.handleNoAuth
	}

	if p.hasPasswordCallback {
		config.PasswordCallback = p.handlePassword
	}

	if p.hasPublicKeyCallback {
		config.PublicKeyCallback = p.handlePublicKey
	}

	if p.hasKeyboardInteractive {
		config.KeyboardInteractiveCallback = p.handleKeyboardInteractive
	}

	return config, nil
}

// nextAuthMethods disables follow-up auth attempts once a Lua callback fails.
func (p *luaPlugin) nextAuthMethods(conn libplugin.ConnMetadata) ([]string, error) {
	if p.hasAuthFailed(conn) {
		return []string{}, nil
	}

	methods := make([]string, 0, 4)

	if p.hasNoAuthCallback {
		methods = append(methods, "none")
	}

	if p.hasPasswordCallback {
		methods = append(methods, "password")
	}

	if p.hasPublicKeyCallback {
		methods = append(methods, "publickey")
	}

	if p.hasKeyboardInteractive {
		methods = append(methods, "keyboard-interactive")
	}

	return methods, nil
}

// getLuaState gets a Lua state from the pool
func (p *luaPlugin) getLuaState() (*lua.LState, error) {
	v := p.statePool.Get()
	if v == nil {
		return nil, fmt.Errorf("failed to get Lua state from pool")
	}
	L, ok := v.(*lua.LState)
	if !ok || L == nil {
		return nil, fmt.Errorf("invalid Lua state in pool")
	}
	return L, nil
}

// putLuaState returns a Lua state to the pool
func (p *luaPlugin) putLuaState(L *lua.LState) {
	p.statePool.Put(L)
}

// handlePassword is called when a user tries to authenticate with a password
func (p *luaPlugin) handlePassword(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
	L, err := p.getLuaState()
	if err != nil {
		p.markAuthFailed(conn)
		return nil, err
	}
	if L != nil {
		defer p.putLuaState(L)
	}

	// Create a table with connection metadata
	connTable := L.NewTable()
	L.SetField(connTable, "sshpiper_user", lua.LString(conn.User()))
	L.SetField(connTable, "sshpiper_remote_addr", lua.LString(conn.RemoteAddr()))
	L.SetField(connTable, "sshpiper_unique_id", lua.LString(conn.UniqueID()))

	// Check if the function exists
	fn := L.GetGlobal("sshpiper_on_password")
	if fn == lua.LNil {
		p.markAuthFailed(conn)
		return nil, callbackNotDefined("sshpiper_on_password")
	}

	// Call the sshpiper_on_password function
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, connTable, lua.LString(password)); err != nil {
		p.markAuthFailed(conn)
		return nil, fmt.Errorf("lua error in sshpiper_on_password: %w", err)
	}

	// Get the return value
	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		p.markAuthFailed(conn)
		return nil, authFailed("authentication failed: no upstream returned")
	}

	upstream, err := p.parseUpstreamTable(L, ret, conn, password)
	if err != nil {
		p.markAuthFailed(conn)
		return nil, err
	}

	log.Infof("routing user %s to %s", conn.User(), upstream.Uri)
	return upstream, nil
}

// handlePublicKey is called when a user tries to authenticate with a public key
func (p *luaPlugin) handlePublicKey(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
	L, err := p.getLuaState()
	if err != nil {
		p.markAuthFailed(conn)
		return nil, err
	}
	if L != nil {
		defer p.putLuaState(L)
	}

	// Create a table with connection metadata
	connTable := L.NewTable()
	L.SetField(connTable, "sshpiper_user", lua.LString(conn.User()))
	L.SetField(connTable, "sshpiper_remote_addr", lua.LString(conn.RemoteAddr()))
	L.SetField(connTable, "sshpiper_unique_id", lua.LString(conn.UniqueID()))

	// Check if the function exists
	fn := L.GetGlobal("sshpiper_on_publickey")
	if fn == lua.LNil {
		p.markAuthFailed(conn)
		return nil, callbackNotDefined("sshpiper_on_publickey")
	}

	// Call the sshpiper_on_publickey function
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, connTable, lua.LString(key)); err != nil {
		p.markAuthFailed(conn)
		return nil, fmt.Errorf("lua error in sshpiper_on_publickey: %w", err)
	}

	// Get the return value
	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		p.markAuthFailed(conn)
		return nil, authFailed("authentication failed: no upstream returned")
	}

	upstream, err := p.parseUpstreamTable(L, ret, conn, nil)
	if err != nil {
		p.markAuthFailed(conn)
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
	L, err := p.getLuaState()
	if err != nil {
		p.markAuthFailed(conn)
		return nil, err
	}
	if L != nil {
		defer p.putLuaState(L)
	}

	// Create a table with connection metadata
	connTable := L.NewTable()
	L.SetField(connTable, "sshpiper_user", lua.LString(conn.User()))
	L.SetField(connTable, "sshpiper_remote_addr", lua.LString(conn.RemoteAddr()))
	L.SetField(connTable, "sshpiper_unique_id", lua.LString(conn.UniqueID()))

	// Check if the function exists
	fn := L.GetGlobal("sshpiper_on_noauth")
	if fn == lua.LNil {
		p.markAuthFailed(conn)
		return nil, callbackNotDefined("sshpiper_on_noauth")
	}

	// Call the sshpiper_on_noauth function
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, connTable); err != nil {
		p.markAuthFailed(conn)
		return nil, fmt.Errorf("lua error in sshpiper_on_noauth: %w", err)
	}

	// Get the return value
	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		p.markAuthFailed(conn)
		return nil, authFailed("authentication failed: no upstream returned")
	}

	upstream, err := p.parseUpstreamTable(L, ret, conn, nil)
	if err != nil {
		p.markAuthFailed(conn)
		return nil, err
	}

	log.Infof("routing user %s to %s (noauth)", conn.User(), upstream.Uri)
	return upstream, nil
}

// handleKeyboardInteractive is called when a user tries keyboard-interactive authentication
func (p *luaPlugin) handleKeyboardInteractive(conn libplugin.ConnMetadata, client libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {
	L, err := p.getLuaState()
	if err != nil {
		p.markAuthFailed(conn)
		return nil, err
	}
	if L != nil {
		defer p.putLuaState(L)
	}

	// Create a table with connection metadata
	connTable := L.NewTable()
	L.SetField(connTable, "sshpiper_user", lua.LString(conn.User()))
	L.SetField(connTable, "sshpiper_remote_addr", lua.LString(conn.RemoteAddr()))
	L.SetField(connTable, "sshpiper_unique_id", lua.LString(conn.UniqueID()))

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
		p.markAuthFailed(conn)
		return nil, callbackNotDefined("sshpiper_on_keyboard_interactive")
	}

	// Call the sshpiper_on_keyboard_interactive function
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, connTable, challengeFn); err != nil {
		p.markAuthFailed(conn)
		return nil, fmt.Errorf("lua error in sshpiper_on_keyboard_interactive: %w", err)
	}

	// Get the return value
	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		p.markAuthFailed(conn)
		return nil, authFailed("authentication failed: no upstream returned")
	}

	upstream, err := p.parseUpstreamTable(L, ret, conn, nil)
	if err != nil {
		p.markAuthFailed(conn)
		return nil, err
	}

	log.Infof("routing user %s to %s (keyboard-interactive)", conn.User(), upstream.Uri)
	return upstream, nil
}
