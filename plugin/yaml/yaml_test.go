//go:build full || e2e

package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

const yamlConfigTemplate = `
version: "1.0"
pipes:
- from:
    - username: "password_simple"
  to:
    host: host-password:2222
    username: "user"
    ignore_hostkey: true
- from:
    - username: "password_.*_regex"
      username_regex_match: true
  to:
    host: host-password:2222
    username: "user"
    known_hosts_data: 
    - fDF8RjRwTmVveUZHVEVHcEIyZ3A4RGE0WlE4TGNVPXxycVZYNU0rWTJoS0dteFphcVFBb0syRHp1TEE9IHNzaC1lZDI1NTE5IEFBQUFDM056YUMxbFpESTFOVEU1QUFBQUlPTXFxbmtWenJtMFNkRzZVT29xS0xzYWJnSDVDOW9rV2kwZGgybDlHS0psCg==
    - fDF8VzRpUUd0VFVyREJwSjM3RnFuOWRwcEdVRE5jPXxEZWFna2RwVHpZZDExdDhYWXlORnlhZmROZ2c9IHNzaC1lZDI1NTE5IEFBQUFDM056YUMxbFpESTFOVEU1QUFBQUlBZnVDSEtWVGpxdXh2dDZDTTZ0ZEc0U0xwMUJ0bi9uT2VISEU1VU96UmRmCg==
- from:
    - username: "publickey_simple"
      authorized_keys: /tmp/auth_keys
  to:
    host: host-publickey:2222
    username: "user"
    private_key: /tmp/private_key
    known_hosts_data: fDF8RjRwTmVveUZHVEVHcEIyZ3A4RGE0WlE4TGNVPXxycVZYNU0rWTJoS0dteFphcVFBb0syRHp1TEE9IHNzaC1lZDI1NTE5IEFBQUFDM056YUMxbFpESTFOVEU1QUFBQUlPTXFxbmtWenJtMFNkRzZVT29xS0xzYWJnSDVDOW9rV2kwZGgybDlHS0psCg==
- from:
    - username: ".*"
      username_regex_match: true
      authorized_keys: 
      - /tmp/private_key1
      - /tmp/private_key2
  to:
    host: host-publickey:2222
    username: "user"
    ignore_hostkey: true
    private_key: /tmp/private_key
`

func TestYamlDecode(t *testing.T) {
	var config piperConfig

	err := yaml.Unmarshal([]byte(yamlConfigTemplate), &config)
	if err != nil {
		t.Fatalf("Failed to unmarshal yaml: %v", err)
	}
}

func TestListOrStringUnmarshal(t *testing.T) {
	type listHolder struct {
		Field listOrString `yaml:"field"`
	}

	var listValue listHolder
	err := yaml.Unmarshal([]byte("field:\n- alpha\n- beta\n"), &listValue)
	if err != nil {
		t.Fatalf("Failed to unmarshal list value: %v", err)
	}
	if !slices.Equal(listValue.Field.List, []string{"alpha", "beta"}) {
		t.Fatalf("Expected list values, got %v", listValue.Field.List)
	}
	if listValue.Field.Str != "" {
		t.Fatalf("Expected empty string value, got %q", listValue.Field.Str)
	}

	var stringValue listHolder
	err = yaml.Unmarshal([]byte("field: gamma\n"), &stringValue)
	if err != nil {
		t.Fatalf("Failed to unmarshal string value: %v", err)
	}
	if stringValue.Field.Str != "gamma" {
		t.Fatalf("Expected string value 'gamma', got %q", stringValue.Field.Str)
	}
	if len(stringValue.Field.List) != 0 {
		t.Fatalf("Expected no list values, got %v", stringValue.Field.List)
	}
}

func TestListOrStringCombineAny(t *testing.T) {
	combined := listOrString{List: []string{"alpha", "beta"}, Str: "gamma"}
	if !combined.Any() {
		t.Fatalf("Expected Any to be true")
	}
	if !slices.Equal(combined.Combine(), []string{"alpha", "beta", "gamma"}) {
		t.Fatalf("Unexpected combined list: %v", combined.Combine())
	}

	empty := listOrString{}
	if empty.Any() {
		t.Fatalf("Expected Any to be false for empty listOrString")
	}
}

func TestLoadFileOrDecode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	p := piperConfig{filename: configPath}

	fileName := "keys_$DOWNSTREAM_USER.txt"
	filePath := filepath.Join(dir, "keys_alice.txt")
	if err := os.WriteFile(filePath, []byte("file-data"), 0o600); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	data, err := p.loadFileOrDecode(fileName, "", map[string]string{
		"DOWNSTREAM_USER": "alice",
	})
	if err != nil {
		t.Fatalf("Failed to load file: %v", err)
	}
	if string(data) != "file-data" {
		t.Fatalf("Expected file contents, got %q", string(data))
	}

	encoded := base64.StdEncoding.EncodeToString([]byte("inline-data"))
	data, err = p.loadFileOrDecode("", encoded, nil)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}
	if string(data) != "inline-data" {
		t.Fatalf("Expected decoded contents, got %q", string(data))
	}
}

func TestLoadFileOrDecodeMany(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	p := piperConfig{filename: configPath}

	if err := os.WriteFile(filepath.Join(dir, "file-one.txt"), []byte("one"), 0o600); err != nil {
		t.Fatalf("Failed to write file-one: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file-two.txt"), []byte("two"), 0o600); err != nil {
		t.Fatalf("Failed to write file-two: %v", err)
	}

	files := listOrString{List: []string{"file-one.txt"}, Str: "file-two.txt"}
	inline := listOrString{Str: base64.StdEncoding.EncodeToString([]byte("three"))}

	data, err := p.loadFileOrDecodeMany(files, inline, nil)
	if err != nil {
		t.Fatalf("Failed to load multiple entries: %v", err)
	}
	if string(data) != "one\ntwo\nthree" {
		t.Fatalf("Unexpected combined data: %q", string(data))
	}
}

func TestCheckPerm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Failed to chmod config: %v", err)
	}

	p := &plugin{}
	if err := p.checkPerm(path); err == nil {
		t.Fatalf("Expected permission error")
	}

	p.NoCheckPerm = true
	if err := p.checkPerm(path); err != nil {
		t.Fatalf("Expected permission check to be skipped, got %v", err)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`version: "1.0"
pipes:
  - from:
      - username: "user"
    to:
      host: host:22
`), 0o600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	p := &plugin{
		FileGlobs: *cli.NewStringSlice(path),
	}
	configs, err := p.loadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("Expected one config, got %d", len(configs))
	}
	if configs[0].filename != path {
		t.Fatalf("Expected filename to be %q, got %q", path, configs[0].filename)
	}
}

func TestMatchConnRegex(t *testing.T) {
	config := &piperConfig{filename: filepath.Join(t.TempDir(), "config.yaml")}
	from := &yamlPipeFrom{
		Username:           "^user_(.*)$",
		UsernameRegexMatch: true,
	}
	privateKeyData := base64.StdEncoding.EncodeToString([]byte("test-private-key"))
	to := &yamlPipeTo{
		Host:           "example.com:22",
		Username:       "$1",
		PrivateKeyData: privateKeyData,
	}

	wrapper := &skelpipeFromWrapper{
		config: config,
		from:   from,
		to:     to,
	}

	conn := fakeConn{user: "user_alice"}
	pipeTo, err := wrapper.MatchConn(conn)
	if err != nil {
		t.Fatalf("Failed to match connection: %v", err)
	}
	privateKeyWrapper, ok := pipeTo.(*skelpipeToPrivateKeyWrapper)
	if !ok {
		t.Fatalf("Expected private key wrapper, got %T", pipeTo)
	}
	if privateKeyWrapper.User(conn) != "alice" {
		t.Fatalf("Expected upstream user 'alice', got %q", privateKeyWrapper.User(conn))
	}
	if privateKeyWrapper.Host(conn) != "example.com:22" {
		t.Fatalf("Unexpected host %q", privateKeyWrapper.Host(conn))
	}
}

func TestSkelPipeWrapperFrom(t *testing.T) {
	pipe := &yamlPipe{
		From: []yamlPipeFrom{
			{Username: "user"},
			{Username: "key", AuthorizedKeys: listOrString{Str: "/tmp/keys"}},
		},
		To: yamlPipeTo{Host: "host:22"},
	}
	wrapper := &skelpipeWrapper{
		pipe:   pipe,
		config: &piperConfig{},
	}

	froms := wrapper.From()
	if len(froms) != 2 {
		t.Fatalf("Expected 2 from entries, got %d", len(froms))
	}
	if _, ok := froms[0].(*skelpipePasswordWrapper); !ok {
		t.Fatalf("Expected password wrapper, got %T", froms[0])
	}
	if _, ok := froms[1].(*skelpipePublicKeyWrapper); !ok {
		t.Fatalf("Expected public key wrapper, got %T", froms[1])
	}
}

// fakeConn is a minimal ConnMetadata implementation for matching tests.
type fakeConn struct {
	user string
	id   string
}

func (f fakeConn) User() string {
	return f.user
}

// RemoteAddr returns an empty address for tests.
func (f fakeConn) RemoteAddr() string {
	return ""
}

// UniqueID returns a stable ID for tests.
func (f fakeConn) UniqueID() string {
	if f.id == "" {
		return "test-connection-id"
	}
	return f.id
}

// GetMeta returns no metadata for tests.
func (f fakeConn) GetMeta(key string) string {
	return ""
}
