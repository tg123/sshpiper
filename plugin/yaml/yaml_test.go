//go:build full || e2e

package main

import (
	"testing"

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
