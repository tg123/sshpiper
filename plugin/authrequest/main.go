//go:build full || e2e

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

type authRequester struct {
	client  *http.Client
	authURL string
}

func (r *authRequester) passwordAuth(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
	req, err := http.NewRequest(http.MethodGet, r.authURL, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(conn.User(), string(password))

	if addr := conn.RemoteAddr(); addr != "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			req.Header.Set("X-Forwarded-For", host)
		} else {
			req.Header.Set("X-Forwarded-For", addr)
		}
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("authrequest: unexpected status %d", resp.StatusCode)
	}

	return &libplugin.Upstream{
		Auth: libplugin.CreateNextPluginAuth(map[string]string{}),
	}, nil
}

func buildAuthURL(base, path string) (string, error) {
	if base == "" {
		return "", fmt.Errorf("authrequest: base url is required")
	}

	if path == "" {
		path = "/auth"
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return strings.TrimSuffix(base, "/") + path, nil
}

func createAuthRequestConfig(base, path string, timeout time.Duration) (*libplugin.SshPiperPluginConfig, error) {
	authURL, err := buildAuthURL(base, path)
	if err != nil {
		return nil, err
	}

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	r := &authRequester{
		client: &http.Client{
			Timeout: timeout,
		},
		authURL: authURL,
	}

	return &libplugin.SshPiperPluginConfig{
		NextAuthMethodsCallback: func(conn libplugin.ConnMetadata) ([]string, error) {
			return []string{"password"}, nil
		},
		PasswordCallback: r.passwordAuth,
	}, nil
}

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "authrequest",
		Usage: "sshpiperd auth_request plugin compatible with nginx auth_request",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "url",
				Usage:    "base url of auth server",
				EnvVars:  []string{"SSHPIPERD_AUTHREQUEST_URL"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "path",
				Usage:   "auth path relative to the base url",
				Value:   "/auth",
				EnvVars: []string{"SSHPIPERD_AUTHREQUEST_PATH"},
			},
			&cli.DurationFlag{
				Name:    "timeout",
				Usage:   "http request timeout",
				Value:   5 * time.Second,
				EnvVars: []string{"SSHPIPERD_AUTHREQUEST_TIMEOUT"},
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			return createAuthRequestConfig(
				c.String("url"),
				c.String("path"),
				c.Duration("timeout"),
			)
		},
	})
}
