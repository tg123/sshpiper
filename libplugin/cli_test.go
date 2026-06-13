package libplugin

import (
	"testing"
	"time"
)

func TestParseFlagsCommandLine(t *testing.T) {
	var dest string
	flags := []Flag{
		&StringFlag{Name: "target", Destination: &dest},
		&BoolFlag{Name: "flag"},
		&IntFlag{Name: "num", Value: 1},
		&DurationFlag{Name: "dur"},
		&StringSliceFlag{Name: "list"},
	}

	c, err := parseFlags("test", "", flags, []string{
		"--target", "example:22",
		"--flag",
		"--num", "42",
		"--dur", "30s",
		"--list", "a", "--list", "b",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := c.String("target"); got != "example:22" {
		t.Errorf("String(target) = %q, want example:22", got)
	}
	if dest != "example:22" {
		t.Errorf("destination = %q, want example:22", dest)
	}
	if !c.Bool("flag") {
		t.Errorf("Bool(flag) = false, want true")
	}
	if got := c.Int("num"); got != 42 {
		t.Errorf("Int(num) = %d, want 42", got)
	}
	if got := c.Duration("dur"); got != 30*time.Second {
		t.Errorf("Duration(dur) = %v, want 30s", got)
	}
	if got := c.StringSlice("list"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("StringSlice(list) = %v, want [a b]", got)
	}
	if !c.IsSet("target") {
		t.Errorf("IsSet(target) = false, want true")
	}
	if c.IsSet("missing") {
		t.Errorf("IsSet(missing) = true, want false")
	}
}

func TestParseFlagsDefaults(t *testing.T) {
	flags := []Flag{
		&StringFlag{Name: "target", Value: "default:22"},
		&IntFlag{Name: "num", Value: 7},
	}

	c, err := parseFlags("test", "", flags, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := c.String("target"); got != "default:22" {
		t.Errorf("String(target) = %q, want default:22", got)
	}
	if got := c.Int("num"); got != 7 {
		t.Errorf("Int(num) = %d, want 7", got)
	}
	if c.IsSet("target") {
		t.Errorf("IsSet(target) = true, want false for default value")
	}
}

func TestParseFlagsEnvVars(t *testing.T) {
	t.Setenv("TEST_TARGET", "envhost:2222")
	t.Setenv("TEST_FLAG", "true")
	t.Setenv("TEST_NUM", "11")
	t.Setenv("TEST_DUR", "1m")
	t.Setenv("TEST_LIST", "x,y,z")

	flags := []Flag{
		&StringFlag{Name: "target", EnvVars: []string{"TEST_TARGET"}},
		&BoolFlag{Name: "flag", EnvVars: []string{"TEST_FLAG"}},
		&IntFlag{Name: "num", EnvVars: []string{"TEST_NUM"}},
		&DurationFlag{Name: "dur", EnvVars: []string{"TEST_DUR"}},
		&StringSliceFlag{Name: "list", EnvVars: []string{"TEST_LIST"}},
	}

	c, err := parseFlags("test", "", flags, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := c.String("target"); got != "envhost:2222" {
		t.Errorf("String(target) = %q, want envhost:2222", got)
	}
	if !c.Bool("flag") {
		t.Errorf("Bool(flag) = false, want true")
	}
	if got := c.Int("num"); got != 11 {
		t.Errorf("Int(num) = %d, want 11", got)
	}
	if got := c.Duration("dur"); got != time.Minute {
		t.Errorf("Duration(dur) = %v, want 1m", got)
	}
	if got := c.StringSlice("list"); len(got) != 3 || got[0] != "x" || got[2] != "z" {
		t.Errorf("StringSlice(list) = %v, want [x y z]", got)
	}
	if !c.IsSet("target") {
		t.Errorf("IsSet(target) = false, want true (set via env)")
	}
}

func TestParseFlagsCommandLineOverridesEnv(t *testing.T) {
	t.Setenv("TEST_TARGET", "envhost:2222")

	flags := []Flag{
		&StringFlag{Name: "target", EnvVars: []string{"TEST_TARGET"}},
	}

	c, err := parseFlags("test", "", flags, []string{"--target", "cli:22"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := c.String("target"); got != "cli:22" {
		t.Errorf("String(target) = %q, want cli:22 (command line wins)", got)
	}
}

func TestParseFlagsRequired(t *testing.T) {
	flags := []Flag{
		&StringFlag{Name: "target", Required: true},
	}

	if _, err := parseFlags("test", "", flags, nil); err == nil {
		t.Fatalf("expected error for missing required flag, got nil")
	}

	if _, err := parseFlags("test", "", flags, []string{"--target", "x"}); err != nil {
		t.Fatalf("unexpected error when required flag provided: %v", err)
	}
}

func TestStringSliceDestinationAndValue(t *testing.T) {
	dst := NewStringSlice()
	flags := []Flag{
		&StringSliceFlag{Name: "config", Destination: dst},
	}

	c, err := parseFlags("test", "", flags, []string{"--config", "a", "--config", "b"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := dst.Value(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("destination Value() = %v, want [a b]", got)
	}
	if got := c.StringSlice("config"); len(got) != 2 {
		t.Errorf("StringSlice(config) = %v, want 2 entries", got)
	}
}
