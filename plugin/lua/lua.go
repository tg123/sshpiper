//go:build full || e2e

package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	lua "github.com/yuin/gopher-lua"
)

type luaPlugin struct {
	ScriptPath string
	statePool  *sync.Pool
	mu         sync.RWMutex       // protects script reloading
	reloadMu   sync.Mutex         // prevents concurrent reloads
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

	hasNewConnection := checkFn("sshpiper_on_new_connection")
	hasNextAuthMethods := checkFn("sshpiper_on_next_auth_methods")
	hasNoAuthCallback := checkFn("sshpiper_on_noauth")
	hasPasswordCallback := checkFn("sshpiper_on_password")
	hasPublicKeyCallback := checkFn("sshpiper_on_publickey")
	hasKeyboardInteractive := checkFn("sshpiper_on_keyboard_interactive")
	hasUpstreamAuthFailure := checkFn("sshpiper_on_upstream_auth_failure")
	hasBanner := checkFn("sshpiper_on_banner")
	hasVerifyHostKey := checkFn("sshpiper_on_verify_hostkey")
	hasPipeCreateError := checkFn("sshpiper_on_pipe_create_error")
	hasPipeStart := checkFn("sshpiper_on_pipe_start")
	hasPipeError := checkFn("sshpiper_on_pipe_error")

	// Initialize the pool by creating it (calls reloadScript internally)
	p.initPool()

	// Prime state was only used for validation; close it so the pool
	// creates fresh states via its New function.
	prime.Close()

	// Ensure at least one callback is defined
	if !hasNoAuthCallback && !hasPasswordCallback && !hasPublicKeyCallback && !hasKeyboardInteractive {
		return nil, fmt.Errorf("no authentication callbacks defined in Lua script (must define at least one of: sshpiper_on_noauth, sshpiper_on_password, sshpiper_on_publickey, sshpiper_on_keyboard_interactive)")
	}

	config := &libplugin.SshPiperPluginConfig{}

	if hasNewConnection {
		config.NewConnectionCallback = p.handleNewConnection
	}

	if hasNextAuthMethods {
		config.NextAuthMethodsCallback = p.handleNextAuthMethods
	}

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

	if hasUpstreamAuthFailure {
		config.UpstreamAuthFailureCallback = p.handleUpstreamAuthFailure
	}

	if hasBanner {
		config.BannerCallback = p.handleBanner
	}

	if hasVerifyHostKey {
		config.VerifyHostKeyCallback = p.handleVerifyHostKey
	}

	if hasPipeCreateError {
		config.PipeCreateErrorCallback = p.handlePipeCreateError
	}

	if hasPipeStart {
		config.PipeStartCallback = p.handlePipeStart
	}

	if hasPipeError {
		config.PipeErrorCallback = p.handlePipeError
	}

	return config, nil
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

// redirectPrint redirects Lua print() to Go log.Info
func (p *luaPlugin) redirectPrint(L *lua.LState) {
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
}

// initPool initializes the Lua state pool with the New function
func (p *luaPlugin) initPool() {
	p.statePool = &sync.Pool{
		New: func() interface{} {
			L := lua.NewState(lua.Options{
				SkipOpenLibs: false,
			})

			// Redirect stdout to our logger
			p.redirectPrint(L)

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
}

// reloadScript reloads the Lua script by draining and repopulating the pool
func (p *luaPlugin) reloadScript() error {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Validate the script still exists
	if _, err := os.Stat(p.ScriptPath); err != nil {
		return fmt.Errorf("lua script not found: %w", err)
	}

	// Test load the script to ensure it's valid before draining the pool
	testState := lua.NewState()
	defer testState.Close()
	if err := testState.DoFile(p.ScriptPath); err != nil {
		return fmt.Errorf("failed to reload lua script: %w", err)
	}

	// Drain the old pool by creating a new one
	oldPool := p.statePool
	p.initPool()

	// Close all states in the old pool synchronously before returning
	// This ensures old states aren't returned after reload
	for {
		v := oldPool.Get()
		if v == nil {
			break
		}
		if L, ok := v.(*lua.LState); ok && L != nil {
			L.Close()
		}
	}

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

func (p *luaPlugin) handleNewConnection(conn libplugin.ConnMetadata) error {
	L, err := p.getLuaState()
	if err != nil {
		return err
	}
	defer p.putLuaState(L)

	connTable := p.createConnTable(L, conn)

	fn := L.GetGlobal("sshpiper_on_new_connection")
	if fn == lua.LNil {
		L.Pop(1)
		return fmt.Errorf("sshpiper_on_new_connection function not defined in Lua script")
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, connTable); err != nil {
		return fmt.Errorf("lua error in sshpiper_on_new_connection: %w", err)
	}

	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		return nil
	}

	switch v := ret.(type) {
	case lua.LBool:
		if bool(v) {
			return nil
		}
		return fmt.Errorf("connection rejected")
	case lua.LString:
		msg := string(v)
		if msg == "" {
			msg = "connection rejected"
		}
		return fmt.Errorf("%s", msg)
	}

	return fmt.Errorf("unexpected return type from sshpiper_on_new_connection: %s", ret.Type())
}

func (p *luaPlugin) handleNextAuthMethods(conn libplugin.ConnMetadata) ([]string, error) {
	L, err := p.getLuaState()
	if err != nil {
		return nil, err
	}
	defer p.putLuaState(L)

	connTable := p.createConnTable(L, conn)

	fn := L.GetGlobal("sshpiper_on_next_auth_methods")
	if fn == lua.LNil {
		L.Pop(1)
		return nil, fmt.Errorf("sshpiper_on_next_auth_methods function not defined in Lua script")
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, connTable); err != nil {
		return nil, fmt.Errorf("lua error in sshpiper_on_next_auth_methods: %w", err)
	}

	ret := L.Get(-1)
	L.Pop(1)

	tbl, ok := ret.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("expected table return value, got %s", ret.Type())
	}

	var methods []string
	for i := 1; ; i++ {
		value := tbl.RawGetInt(i)
		if value == lua.LNil {
			break
		}

		v, ok := value.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("expected auth method name as string, got %s", value.Type())
		}

		methods = append(methods, string(v))
	}

	return methods, nil
}

// handlePassword is called when a user tries to authenticate with a password
func (p *luaPlugin) handlePassword(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
	L, err := p.getLuaState()
	if err != nil {
		return nil, err
	}
	defer p.putLuaState(L)

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
	L, err := p.getLuaState()
	if err != nil {
		return nil, err
	}
	defer p.putLuaState(L)

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

	// Extract ignore_hostkey (optional, defaults to false for security)
	upstream.IgnoreHostKey = false // default - secure
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
		return nil, err
	}
	if L != nil {
		defer p.putLuaState(L)
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
	L, err := p.getLuaState()
	if err != nil {
		return nil, err
	}
	defer p.putLuaState(L)

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

func (p *luaPlugin) handleUpstreamAuthFailure(conn libplugin.ConnMetadata, method string, callbackErr error, allowmethods []string) {
	L, err := p.getLuaState()
	if err != nil {
		log.Errorf("failed to get lua state: %v", err)
		return
	}
	defer p.putLuaState(L)

	connTable := p.createConnTable(L, conn)
	allowedTable := L.NewTable()
	for _, m := range allowmethods {
		allowedTable.Append(lua.LString(m))
	}

	fn := L.GetGlobal("sshpiper_on_upstream_auth_failure")
	if fn == lua.LNil {
		L.Pop(1)
		log.Error("sshpiper_on_upstream_auth_failure function not defined in Lua script")
		return
	}

	errMsg := ""
	if callbackErr != nil {
		errMsg = callbackErr.Error()
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    0,
		Protect: true,
	}, connTable, lua.LString(method), lua.LString(errMsg), allowedTable); err != nil {
		log.Errorf("lua error in sshpiper_on_upstream_auth_failure: %v", err)
	}
}

func (p *luaPlugin) handleBanner(conn libplugin.ConnMetadata) string {
	L, err := p.getLuaState()
	if err != nil {
		log.Errorf("failed to get lua state: %v", err)
		return ""
	}
	defer p.putLuaState(L)

	connTable := p.createConnTable(L, conn)

	fn := L.GetGlobal("sshpiper_on_banner")
	if fn == lua.LNil {
		L.Pop(1)
		log.Error("sshpiper_on_banner function not defined in Lua script")
		return ""
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, connTable); err != nil {
		log.Errorf("lua error in sshpiper_on_banner: %v", err)
		return ""
	}

	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		return ""
	}

	if v, ok := ret.(lua.LString); ok {
		return string(v)
	}

	log.Errorf("unexpected return type from sshpiper_on_banner: %s", ret.Type())
	return ""
}

func (p *luaPlugin) handleVerifyHostKey(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
	L, err := p.getLuaState()
	if err != nil {
		return err
	}
	defer p.putLuaState(L)

	connTable := p.createConnTable(L, conn)

	fn := L.GetGlobal("sshpiper_on_verify_hostkey")
	if fn == lua.LNil {
		L.Pop(1)
		return fmt.Errorf("sshpiper_on_verify_hostkey function not defined in Lua script")
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    2,
		Protect: true,
	}, connTable, lua.LString(hostname), lua.LString(netaddr), lua.LString(string(key))); err != nil {
		return fmt.Errorf("lua error in sshpiper_on_verify_hostkey: %w", err)
	}

	result := L.Get(-2)
	luaErr := L.Get(-1)
	L.Pop(2)

	if luaErr != lua.LNil {
		if msg, ok := luaErr.(lua.LString); ok {
			if msg == "" {
				return fmt.Errorf("host key verification failed")
			}
			return fmt.Errorf("%s", string(msg))
		}
		return fmt.Errorf("host key verification failed")
	}

	if v, ok := result.(lua.LBool); ok && bool(v) {
		return nil
	}

	return fmt.Errorf("host key verification failed")
}

func (p *luaPlugin) handlePipeCreateError(remoteAddr string, callbackErr error) {
	L, err := p.getLuaState()
	if err != nil {
		log.Errorf("failed to get lua state: %v", err)
		return
	}
	defer p.putLuaState(L)

	fn := L.GetGlobal("sshpiper_on_pipe_create_error")
	if fn == lua.LNil {
		L.Pop(1)
		log.Error("sshpiper_on_pipe_create_error function not defined in Lua script")
		return
	}

	errMsg := ""
	if callbackErr != nil {
		errMsg = callbackErr.Error()
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    0,
		Protect: true,
	}, lua.LString(remoteAddr), lua.LString(errMsg)); err != nil {
		log.Errorf("lua error in sshpiper_on_pipe_create_error: %v", err)
	}
}

func (p *luaPlugin) handlePipeStart(conn libplugin.ConnMetadata) {
	L, err := p.getLuaState()
	if err != nil {
		log.Errorf("failed to get lua state: %v", err)
		return
	}
	defer p.putLuaState(L)

	connTable := p.createConnTable(L, conn)

	fn := L.GetGlobal("sshpiper_on_pipe_start")
	if fn == lua.LNil {
		L.Pop(1)
		log.Error("sshpiper_on_pipe_start function not defined in Lua script")
		return
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    0,
		Protect: true,
	}, connTable); err != nil {
		log.Errorf("lua error in sshpiper_on_pipe_start: %v", err)
	}
}

func (p *luaPlugin) handlePipeError(conn libplugin.ConnMetadata, callbackErr error) {
	L, err := p.getLuaState()
	if err != nil {
		log.Errorf("failed to get lua state: %v", err)
		return
	}
	defer p.putLuaState(L)

	connTable := p.createConnTable(L, conn)

	fn := L.GetGlobal("sshpiper_on_pipe_error")
	if fn == lua.LNil {
		L.Pop(1)
		log.Error("sshpiper_on_pipe_error function not defined in Lua script")
		return
	}

	errMsg := ""
	if callbackErr != nil {
		errMsg = callbackErr.Error()
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    0,
		Protect: true,
	}, connTable, lua.LString(errMsg)); err != nil {
		log.Errorf("lua error in sshpiper_on_pipe_error: %v", err)
	}
}
