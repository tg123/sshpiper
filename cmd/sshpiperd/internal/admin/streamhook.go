package admin

import (
	"bytes"
	"encoding/binary"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Mirrors the constants in cmd/sshpiperd/asciicast.go. Duplicated here to
// keep this package free of an upward import.
const (
	msgChannelData        = 94
	msgChannelRequest     = 98
	msgChannelOpenConfirm = 91
)

// StreamHook is an inspector that converts raw SSH packets observed by
// ssh.InspectPacketHook into Frame events published on a Broadcaster.
//
// One StreamHook is created per session by the daemon. The same instance is
// installed on both the upstream-bound (uphook) and downstream-bound
// (downhook) packet paths so that:
//
//   - upstream → downstream channel-data becomes "o" (output) frames;
//   - downstream → upstream pty-req / window-change become "header" / "r"
//     frames with the correct terminal geometry.
type StreamHook struct {
	bc *Broadcaster

	mu sync.Mutex
	// channelIDMap[server-side id] = client-side id, populated from
	// channel-open-confirm packets so window-change requests addressed to
	// the server-side id can be remapped to the per-channel header.
	channelIDMap map[uint32]uint32
	// per-channel state — start time and accumulated env for the next
	// pty-req-induced header.
	channels map[uint32]*channelState
	// pending env / pty info collected before "shell"/"exec" arrives.
	pendingEnv  map[string]string
	pendingW    uint32
	pendingH    uint32
	pendingTerm string
}

type channelState struct {
	startTime time.Time
}

// NewStreamHook returns a StreamHook that publishes to bc.
func NewStreamHook(bc *Broadcaster) *StreamHook {
	return &StreamHook{
		bc:           bc,
		channelIDMap: make(map[uint32]uint32),
		channels:     make(map[uint32]*channelState),
		pendingEnv:   make(map[string]string),
	}
}

// Up handles packets travelling from the upstream server toward the
// downstream client. It publishes "o" output frames for channel-data and
// records server→client channel id mappings.
func (h *StreamHook) Up(msg []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(msg) == 0 {
		return ssh.PipePacketHookTransform, msg, nil
	}
	switch msg[0] {
	case msgChannelData:
		if len(msg) < 9 {
			break
		}
		clientChannelID := binary.BigEndian.Uint32(msg[1:5])
		h.mu.Lock()
		_, ok := h.channels[clientChannelID]
		h.mu.Unlock()
		if !ok {
			break
		}
		// the data payload starts at offset 9 (1 byte msg + 4 channel + 4 length)
		data := append([]byte(nil), msg[9:]...)
		h.bc.Publish(Frame{
			Kind:      "o",
			ChannelID: clientChannelID,
			Time:      time.Now(),
			Data:      data,
		})
	case msgChannelOpenConfirm:
		if len(msg) < 9 {
			break
		}
		clientChannelID := binary.BigEndian.Uint32(msg[1:5])
		serverChannelID := binary.BigEndian.Uint32(msg[5:9])
		h.mu.Lock()
		h.channelIDMap[serverChannelID] = clientChannelID
		h.mu.Unlock()
	}
	return ssh.PipePacketHookTransform, msg, nil
}

// Down handles packets travelling from the downstream client toward the
// upstream server. It tracks pty-req / env / window-change / shell+exec
// requests and emits header and "r" resize frames as needed.
func (h *StreamHook) Down(msg []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(msg) == 0 || msg[0] != msgChannelRequest {
		return ssh.PipePacketHookTransform, msg, nil
	}
	if len(msg) < 5 {
		return ssh.PipePacketHookTransform, msg, nil
	}
	serverChannelID := binary.BigEndian.Uint32(msg[1:5])
	buf := bytes.NewReader(msg[5:])
	reqType := readSSHString(buf)

	switch reqType {
	case "pty-req":
		_, _ = buf.ReadByte() // want_reply
		term := readSSHString(buf)
		var w, hgt uint32
		_ = binary.Read(buf, binary.BigEndian, &w)
		_ = binary.Read(buf, binary.BigEndian, &hgt)
		h.mu.Lock()
		h.pendingTerm = term
		h.pendingW = w
		h.pendingH = hgt
		h.mu.Unlock()
	case "env":
		_, _ = buf.ReadByte()
		k := readSSHString(buf)
		v := readSSHString(buf)
		h.mu.Lock()
		h.pendingEnv[k] = v
		h.mu.Unlock()
	case "window-change":
		_, _ = buf.ReadByte()
		var w, hgt uint32
		_ = binary.Read(buf, binary.BigEndian, &w)
		_ = binary.Read(buf, binary.BigEndian, &hgt)
		h.mu.Lock()
		clientChannelID, ok := h.channelIDMap[serverChannelID]
		h.mu.Unlock()
		if !ok {
			break
		}
		h.bc.Publish(Frame{
			Kind:      "r",
			ChannelID: clientChannelID,
			Time:      time.Now(),
			Width:     w,
			Height:    hgt,
		})
	case "shell", "exec":
		h.mu.Lock()
		clientChannelID, ok := h.channelIDMap[serverChannelID]
		if !ok {
			h.mu.Unlock()
			break
		}
		env := make(map[string]string, len(h.pendingEnv)+1)
		for k, v := range h.pendingEnv {
			env[k] = v
		}
		if h.pendingTerm != "" {
			env["TERM"] = h.pendingTerm
		}
		w, hgt := h.pendingW, h.pendingH
		// reset pendings for any subsequent shell/exec on a different channel
		h.pendingEnv = make(map[string]string)
		h.pendingTerm = ""
		h.pendingW, h.pendingH = 0, 0
		h.channels[clientChannelID] = &channelState{startTime: time.Now()}
		h.mu.Unlock()

		h.bc.Publish(Frame{
			Kind:      "header",
			ChannelID: clientChannelID,
			Time:      time.Now(),
			Width:     w,
			Height:    hgt,
			Env:       env,
		})
	}
	return ssh.PipePacketHookTransform, msg, nil
}

// readSSHString reads an SSH-style length-prefixed string from buf.
func readSSHString(buf *bytes.Reader) string {
	var l uint32
	if err := binary.Read(buf, binary.BigEndian, &l); err != nil {
		return ""
	}
	if int(l) > buf.Len() {
		return ""
	}
	s := make([]byte, l)
	if _, err := buf.Read(s); err != nil {
		return ""
	}
	return string(s)
}
