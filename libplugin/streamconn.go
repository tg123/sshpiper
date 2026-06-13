package libplugin

import (
	"net"

	"github.com/tg123/sshpiper/libplugin/connovergrpc"
)

// NewConnFromStream wraps a CreateConn bidirectional stream as a net.Conn.
// The data exchanged on the connection is tunneled through connovergrpc
// ConnMessage data frames. onClose, when not nil, is invoked once when the
// connection is closed.
func NewConnFromStream(stream connovergrpc.MessageStream, addr string, onClose func() error) net.Conn {
	return connovergrpc.NewConnFromMessageStream(stream, addr, onClose)
}
