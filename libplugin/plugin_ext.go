package libplugin

import "fmt"

// GetOrGenerateUri returns the existing Uri if set, otherwise constructs it from Host and Port.
func (x *Upstream) GetOrGenerateUri() string {
	uri := x.GetUri()
	if uri != "" {
		return uri
	}

	port := x.Port
	if port <= 0 {
		port = 22
	}

	return fmt.Sprintf("tcp://%v:%v", x.Host, port)
}
