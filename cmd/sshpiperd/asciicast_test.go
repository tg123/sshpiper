package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestAsciicastLogger_InputEvent(t *testing.T) {
	recordDir := t.TempDir()
	logger := newAsciicastLogger(recordDir, "")

	serverChannelID := uint32(22)
	clientChannelID := uint32(11)

	openConfirm := make([]byte, 9)
	openConfirm[0] = msgChannelOpenConfirm
	binary.BigEndian.PutUint32(openConfirm[1:5], clientChannelID)
	binary.BigEndian.PutUint32(openConfirm[5:9], serverChannelID)
	if err := logger.uphook(openConfirm); err != nil {
		t.Fatalf("uphook open confirm: %v", err)
	}

	req := buildChannelRequest(serverChannelID, "shell", nil)
	if err := logger.downhook(req); err != nil {
		t.Fatalf("downhook shell: %v", err)
	}

	inputPayload := []byte("ls -la\n")
	inputMsg := buildChannelData(serverChannelID, inputPayload)
	if err := logger.downhook(inputMsg); err != nil {
		t.Fatalf("downhook input: %v", err)
	}

	_ = logger.Close()

	castPath := filepath.Join(recordDir, "shell-channel-11.cast")
	content, err := os.ReadFile(castPath)
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}

	if !bytes.Contains(content, []byte("\"i\"")) {
		t.Fatalf("expected input event in cast, got: %s", string(content))
	}
}

func TestAsciicastLogger_MarkerEvent(t *testing.T) {
	recordDir := t.TempDir()
	logger := newAsciicastLogger(recordDir, "")

	serverChannelID := uint32(42)
	clientChannelID := uint32(7)

	openConfirm := make([]byte, 9)
	openConfirm[0] = msgChannelOpenConfirm
	binary.BigEndian.PutUint32(openConfirm[1:5], clientChannelID)
	binary.BigEndian.PutUint32(openConfirm[5:9], serverChannelID)
	if err := logger.uphook(openConfirm); err != nil {
		t.Fatalf("uphook open confirm: %v", err)
	}

	execPayload := buildStringPayload("date")
	req := buildChannelRequest(serverChannelID, "exec", execPayload)
	if err := logger.downhook(req); err != nil {
		t.Fatalf("downhook exec: %v", err)
	}

	_ = logger.Close()

	castPath := filepath.Join(recordDir, "exec-channel-7.cast")
	content, err := os.ReadFile(castPath)
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}

	if !bytes.Contains(content, []byte("\"m\"")) {
		t.Fatalf("expected marker event in cast, got: %s", string(content))
	}
}

func buildChannelData(channelID uint32, payload []byte) []byte {
	msg := make([]byte, 9+len(payload))
	msg[0] = msgChannelData
	binary.BigEndian.PutUint32(msg[1:5], channelID)
	binary.BigEndian.PutUint32(msg[5:9], uint32(len(payload)))
	copy(msg[9:], payload)
	return msg
}

func buildChannelRequest(channelID uint32, reqType string, payload []byte) []byte {
	typeBytes := buildStringPayload(reqType)
	msg := make([]byte, 5+len(typeBytes)+1+len(payload))
	msg[0] = msgChannelRequest
	binary.BigEndian.PutUint32(msg[1:5], channelID)
	copy(msg[5:], typeBytes)
	msg[5+len(typeBytes)] = 0
	copy(msg[6+len(typeBytes):], payload)
	return msg
}

func buildStringPayload(value string) []byte {
	buf := &bytes.Buffer{}
	_ = binary.Write(buf, binary.BigEndian, uint32(len(value)))
	_, _ = buf.WriteString(value)
	return buf.Bytes()
}
