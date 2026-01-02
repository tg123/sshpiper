//go:build full || e2e

package main

import (
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

	return &libplugin.SshPiperPluginConfig{
		PasswordCallback:  p.handlePassword,
		PublicKeyCallback: p.handlePublicKey,
	}, nil
}

// getLuaState gets a Lua state from the pool
func (p *luaPlugin) getLuaState() (*lua.LState, error) {
	L := p.statePool.Get().(*lua.LState)
	if L == nil {
		return nil, fmt.Errorf("failed to get Lua state from pool")
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
		return nil, err
	}
	defer p.putLuaState(L)

	// Create a table with connection metadata
	connTable := L.NewTable()
	L.SetField(connTable, "user", lua.LString(conn.User()))
	L.SetField(connTable, "remote_addr", lua.LString(conn.RemoteAddr()))
	L.SetField(connTable, "unique_id", lua.LString(conn.UniqueID()))

	// Call the on_password function
	if err := L.CallByParam(lua.P{
		Fn:      L.GetGlobal("on_password"),
		NRet:    1,
		Protect: true,
	}, connTable, lua.LString(password)); err != nil {
		return nil, fmt.Errorf("lua error in on_password: %w", err)
	}

	// Get the return value
	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		return nil, fmt.Errorf("authentication failed: no upstream returned")
	}

	upstream, err := p.parseUpstreamTable(L, ret, password)
	if err != nil {
		return nil, err
	}

	log.Infof("routing user %s to %s:%d", conn.User(), upstream.Host, upstream.Port)
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
	connTable := L.NewTable()
	L.SetField(connTable, "user", lua.LString(conn.User()))
	L.SetField(connTable, "remote_addr", lua.LString(conn.RemoteAddr()))
	L.SetField(connTable, "unique_id", lua.LString(conn.UniqueID()))

	// Call the on_publickey function
	if err := L.CallByParam(lua.P{
		Fn:      L.GetGlobal("on_publickey"),
		NRet:    1,
		Protect: true,
	}, connTable, lua.LString(key)); err != nil {
		return nil, fmt.Errorf("lua error in on_publickey: %w", err)
	}

	// Get the return value
	ret := L.Get(-1)
	L.Pop(1)

	if ret == lua.LNil {
		return nil, fmt.Errorf("authentication failed: no upstream returned")
	}

	upstream, err := p.parseUpstreamTable(L, ret, nil)
	if err != nil {
		return nil, err
	}

	log.Infof("routing user %s to %s:%d", conn.User(), upstream.Host, upstream.Port)
	return upstream, nil
}

// parseUpstreamTable parses a Lua table into an Upstream struct
func (p *luaPlugin) parseUpstreamTable(L *lua.LState, value lua.LValue, password []byte) (*libplugin.Upstream, error) {
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

	// Parse host:port
	host, port, err := libplugin.SplitHostPortForSSH(string(hostStr))
	if err != nil {
		return nil, fmt.Errorf("invalid host:port format: %w", err)
	}

	upstream := &libplugin.Upstream{
		Host:          host,
		Port:          int32(port),
		IgnoreHostKey: true, // default to true for simplicity
	}

	// Extract username (optional, defaults to connecting user)
	usernameVal := L.GetField(table, "username")
	if usernameVal != lua.LNil {
		if username, ok := usernameVal.(lua.LString); ok {
			upstream.UserName = string(username)
		}
	}

	// Extract ignore_hostkey (optional)
	ignoreHostKeyVal := L.GetField(table, "ignore_hostkey")
	if ignoreHostKeyVal != lua.LNil {
		if ignoreHostKey, ok := ignoreHostKeyVal.(lua.LBool); ok {
			upstream.IgnoreHostKey = bool(ignoreHostKey)
		}
	}

	// Handle authentication
	privateKeyVal := L.GetField(table, "private_key")
	privateKeyDataVal := L.GetField(table, "private_key_data")

	if privateKeyVal != lua.LNil || privateKeyDataVal != lua.LNil {
		// Use private key authentication
		var privateKeyData []byte
		var err error

		if privateKeyVal != lua.LNil {
			if pkPath, ok := privateKeyVal.(lua.LString); ok {
				privateKeyData, err = os.ReadFile(string(pkPath))
				if err != nil {
					return nil, fmt.Errorf("failed to read private key file: %w", err)
				}
			}
		} else if privateKeyDataVal != lua.LNil {
			if pkData, ok := privateKeyDataVal.(lua.LString); ok {
				privateKeyData = []byte(pkData)
			}
		}

		if len(privateKeyData) == 0 {
			return nil, fmt.Errorf("private key data is empty")
		}

		upstream.Auth = libplugin.CreatePrivateKeyAuth(privateKeyData, nil)
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
