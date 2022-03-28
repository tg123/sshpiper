package utils

import (
	"fmt"
	"net"
	"strings"
)

func FormatIPAddress(host string) string {
	ip4 := net.ParseIP(host).To4()

	if ip4 != nil || !strings.Contains(host, ":") {
		return host
	}

	return fmt.Sprintf("[%s]", host)
}
