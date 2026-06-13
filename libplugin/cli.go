package libplugin

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// CliContext provides access to the parsed command-line flag values for a
// plugin. It is passed to PluginTemplate.CreateConfig. It intentionally does
// not depend on any third party command-line library so that plugins built on
// top of libplugin do not inherit such a dependency.
type CliContext interface {
	// String returns the value of the named string flag.
	String(name string) string
	// Bool returns the value of the named boolean flag.
	Bool(name string) bool
	// Int returns the value of the named integer flag.
	Int(name string) int
	// Duration returns the value of the named duration flag.
	Duration(name string) time.Duration
	// StringSlice returns the values of the named string slice flag.
	StringSlice(name string) []string
	// IsSet reports whether the named flag was set on the command line or via
	// one of its environment variables.
	IsSet(name string) bool
	// Context returns the context associated with the plugin invocation.
	Context() context.Context
}

// Flag is implemented by all plugin command-line flag types.
type Flag interface {
	register(fs *flag.FlagSet, c *cliContext)
	finalize(c *cliContext) error
}

// parseFlags registers the given flags on a flag.FlagSet, parses args, applies
// environment variable fallbacks and required-flag validation, and returns the
// resulting CliContext.
func parseFlags(name, usage string, flags []Flag, args []string) (*cliContext, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		if usage != "" {
			fmt.Fprintf(os.Stderr, "%s - %s\n\n", name, usage)
		}
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", name)
		fs.PrintDefaults()
	}

	c := newCliContext(context.Background())
	for _, f := range flags {
		f.register(fs, c)
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	fs.Visit(func(fl *flag.Flag) {
		c.set[fl.Name] = true
	})

	for _, f := range flags {
		if err := f.finalize(c); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// StringSlice holds the values of a repeatable string flag.
type StringSlice struct {
	values []string
}

// NewStringSlice creates a StringSlice populated with the given values.
func NewStringSlice(values ...string) *StringSlice {
	return &StringSlice{values: append([]string(nil), values...)}
}

// Value returns the values held by the slice.
func (s *StringSlice) Value() []string {
	if s == nil {
		return nil
	}
	return s.values
}

// String implements flag.Value.
func (s *StringSlice) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(s.values, ",")
}

// stringSliceValue adapts a *StringSlice to flag.Value. The first time a value
// is set on the command line, any default values are discarded, matching the
// behaviour of common command-line libraries.
type stringSliceValue struct {
	slice      *StringSlice
	hasBeenSet bool
}

func (v *stringSliceValue) String() string {
	if v == nil || v.slice == nil {
		return ""
	}
	return v.slice.String()
}

func (v *stringSliceValue) Set(s string) error {
	if !v.hasBeenSet {
		v.slice.values = nil
		v.hasBeenSet = true
	}
	v.slice.values = append(v.slice.values, s)
	return nil
}

type cliContext struct {
	ctx     context.Context
	strings map[string]*string
	bools   map[string]*bool
	ints    map[string]*int
	durs    map[string]*time.Duration
	slices  map[string]*StringSlice
	set     map[string]bool
}

func newCliContext(ctx context.Context) *cliContext {
	return &cliContext{
		ctx:     ctx,
		strings: map[string]*string{},
		bools:   map[string]*bool{},
		ints:    map[string]*int{},
		durs:    map[string]*time.Duration{},
		slices:  map[string]*StringSlice{},
		set:     map[string]bool{},
	}
}

func (c *cliContext) String(name string) string {
	if p, ok := c.strings[name]; ok {
		return *p
	}
	return ""
}

func (c *cliContext) Bool(name string) bool {
	if p, ok := c.bools[name]; ok {
		return *p
	}
	return false
}

func (c *cliContext) Int(name string) int {
	if p, ok := c.ints[name]; ok {
		return *p
	}
	return 0
}

func (c *cliContext) Duration(name string) time.Duration {
	if p, ok := c.durs[name]; ok {
		return *p
	}
	return 0
}

func (c *cliContext) StringSlice(name string) []string {
	if p, ok := c.slices[name]; ok {
		return p.Value()
	}
	return nil
}

func (c *cliContext) IsSet(name string) bool {
	return c.set[name]
}

func (c *cliContext) Context() context.Context {
	return c.ctx
}

func lookupEnv(envVars []string) (string, bool) {
	for _, key := range envVars {
		if v, ok := os.LookupEnv(key); ok {
			return v, true
		}
	}
	return "", false
}

func requireFlag(name string, required, set bool) error {
	if required && !set {
		return fmt.Errorf("required flag %q not set", name)
	}
	return nil
}

// StringFlag defines a string command-line flag.
type StringFlag struct {
	Name        string
	Usage       string
	EnvVars     []string
	Required    bool
	Value       string
	Destination *string
}

func (f *StringFlag) register(fs *flag.FlagSet, c *cliContext) {
	c.strings[f.Name] = fs.String(f.Name, f.Value, f.Usage)
}

func (f *StringFlag) finalize(c *cliContext) error {
	p := c.strings[f.Name]
	if !c.set[f.Name] {
		if v, ok := lookupEnv(f.EnvVars); ok {
			*p = v
			c.set[f.Name] = true
		}
	}
	if err := requireFlag(f.Name, f.Required, c.set[f.Name]); err != nil {
		return err
	}
	if f.Destination != nil {
		*f.Destination = *p
	}
	return nil
}

// BoolFlag defines a boolean command-line flag.
type BoolFlag struct {
	Name        string
	Usage       string
	EnvVars     []string
	Required    bool
	Value       bool
	Destination *bool
}

func (f *BoolFlag) register(fs *flag.FlagSet, c *cliContext) {
	c.bools[f.Name] = fs.Bool(f.Name, f.Value, f.Usage)
}

func (f *BoolFlag) finalize(c *cliContext) error {
	p := c.bools[f.Name]
	if !c.set[f.Name] {
		if v, ok := lookupEnv(f.EnvVars); ok {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("invalid boolean value %q for flag %q: %w", v, f.Name, err)
			}
			*p = b
			c.set[f.Name] = true
		}
	}
	if err := requireFlag(f.Name, f.Required, c.set[f.Name]); err != nil {
		return err
	}
	if f.Destination != nil {
		*f.Destination = *p
	}
	return nil
}

// IntFlag defines an integer command-line flag.
type IntFlag struct {
	Name        string
	Usage       string
	EnvVars     []string
	Required    bool
	Value       int
	Destination *int
}

func (f *IntFlag) register(fs *flag.FlagSet, c *cliContext) {
	c.ints[f.Name] = fs.Int(f.Name, f.Value, f.Usage)
}

func (f *IntFlag) finalize(c *cliContext) error {
	p := c.ints[f.Name]
	if !c.set[f.Name] {
		if v, ok := lookupEnv(f.EnvVars); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("invalid integer value %q for flag %q: %w", v, f.Name, err)
			}
			*p = n
			c.set[f.Name] = true
		}
	}
	if err := requireFlag(f.Name, f.Required, c.set[f.Name]); err != nil {
		return err
	}
	if f.Destination != nil {
		*f.Destination = *p
	}
	return nil
}

// DurationFlag defines a time.Duration command-line flag.
type DurationFlag struct {
	Name        string
	Usage       string
	EnvVars     []string
	Required    bool
	Value       time.Duration
	Destination *time.Duration
}

func (f *DurationFlag) register(fs *flag.FlagSet, c *cliContext) {
	c.durs[f.Name] = fs.Duration(f.Name, f.Value, f.Usage)
}

func (f *DurationFlag) finalize(c *cliContext) error {
	p := c.durs[f.Name]
	if !c.set[f.Name] {
		if v, ok := lookupEnv(f.EnvVars); ok {
			d, err := time.ParseDuration(v)
			if err != nil {
				return fmt.Errorf("invalid duration value %q for flag %q: %w", v, f.Name, err)
			}
			*p = d
			c.set[f.Name] = true
		}
	}
	if err := requireFlag(f.Name, f.Required, c.set[f.Name]); err != nil {
		return err
	}
	if f.Destination != nil {
		*f.Destination = *p
	}
	return nil
}

// StringSliceFlag defines a repeatable string command-line flag.
type StringSliceFlag struct {
	Name        string
	Usage       string
	EnvVars     []string
	Required    bool
	Value       *StringSlice
	Destination *StringSlice
}

func (f *StringSliceFlag) register(fs *flag.FlagSet, c *cliContext) {
	dst := f.Destination
	if dst == nil {
		dst = &StringSlice{}
	}
	if f.Value != nil {
		dst.values = append([]string(nil), f.Value.values...)
	}
	fs.Var(&stringSliceValue{slice: dst}, f.Name, f.Usage)
	c.slices[f.Name] = dst
}

func (f *StringSliceFlag) finalize(c *cliContext) error {
	dst := c.slices[f.Name]
	if !c.set[f.Name] {
		if v, ok := lookupEnv(f.EnvVars); ok {
			dst.values = strings.Split(v, ",")
			c.set[f.Name] = true
		}
	}
	return requireFlag(f.Name, f.Required, c.set[f.Name])
}
