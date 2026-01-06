package libplugin

import (
	"context"
	"reflect"
	"testing"
)

func TestListCallbacks_UsesNoticeNames(t *testing.T) {
	s := &server{
		config: SshPiperPluginConfig{
			NewConnectionCallback: func(conn ConnMetadata) error { return nil },
			NextAuthMethodsCallback: func(conn ConnMetadata) ([]string, error) {
				return nil, nil
			},
			NoClientAuthCallback: func(conn ConnMetadata) (*Upstream, error) { return nil, nil },
			PasswordCallback: func(conn ConnMetadata, password []byte) (*Upstream, error) {
				return nil, nil
			},
			PublicKeyCallback: func(conn ConnMetadata, key []byte) (*Upstream, error) { return nil, nil },
			KeyboardInteractiveCallback: func(conn ConnMetadata, challenge KeyboardInteractiveChallenge) (*Upstream, error) {
				return nil, nil
			},
			UpstreamAuthFailureCallback: func(conn ConnMetadata, method string, err error, allowmethods []string) {},
			BannerCallback:              func(conn ConnMetadata) string { return "" },
			VerifyHostKeyCallback: func(conn ConnMetadata, hostname, netaddr string, key []byte) error {
				return nil
			},
			PipeCreateErrorCallback: func(remoteAddr string, err error) {},
			PipeStartCallback:       func(conn ConnMetadata) {},
			PipeErrorCallback:       func(conn ConnMetadata, err error) {},
		},
	}

	resp, err := s.ListCallbacks(context.Background(), &ListCallbackRequest{})
	if err != nil {
		t.Fatalf("ListCallbacks returned error: %v", err)
	}

	expected := []string{
		"NewConnection",
		"NextAuthMethods",
		"NoneAuth",
		"PasswordAuth",
		"PublicKeyAuth",
		"KeyboardInteractiveAuth",
		"UpstreamAuthFailureNotice",
		"Banner",
		"VerifyHostKey",
		"PipeStartNotice",
		"PipeErrorNotice",
		"PipeCreateErrorNotice",
	}

	if !reflect.DeepEqual(resp.Callbacks, expected) {
		t.Fatalf("expected callbacks %v, got %v", expected, resp.Callbacks)
	}
}
