package remotecall

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"
)

type StringMapFlag struct {
	cli.Generic
	Value map[string]string
}

func (f *StringMapFlag) Set(value string) error {
	if f.Value == nil {
		f.Value = make(map[string]string)
	}
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid format, expecting key=value")
	}
	f.Value[parts[0]] = parts[1]
	return nil
}

func (f *StringMapFlag) String() string {
	var result []string
	for k, v := range f.Value {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(result, ", ")
}
