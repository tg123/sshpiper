package libplugin

import "testing"

func TestGetOrGenerateUri_GeneratesUriWithIPv6(t *testing.T) {
	up := &Upstream{
		Host: "2001:db8::1",
		Port: 2222,
	}

	got := up.GetOrGenerateUri()
	if got != "tcp://[2001:db8::1]:2222" {
		t.Errorf("expected generated uri, got %q", got)
	}
}
