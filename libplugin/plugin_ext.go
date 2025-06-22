package libplugin

import (
	"fmt"
	"net"
	"strconv"
)

// GetOrGenerateUri returns the existing Uri if set, otherwise constructs it from Host and Port.
func (x *Upstream) GetOrGenerateUri() string {
	uri := x.GetUri()
	if uri != "" {
		return uri
	}

	port := x.GetPort()
	if port <= 0 {
		port = 22
	}
	addr := net.JoinHostPort(x.GetHost(), strconv.Itoa(int(port)))

	return fmt.Sprintf("tcp://%v", addr)
}
