package main

import (
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestHookChain_Hook(t *testing.T) {
	hc := &hookChain{}

	// Mock hooks
	hook1 := func(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
		return ssh.PipePacketHookTransform, append(packet, '1'), nil
	}

	hook2 := func(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
		return ssh.PipePacketHookTransform, append(packet, '2'), nil
	}

	hook3 := func(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
		return ssh.PipePacketHookTransform, append(packet, '3'), nil
	}

	hook4 := func(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
		return ssh.PipePacketHookReply, append(packet, '4'), nil
	}

	hook5 := func(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
		return ssh.PipePacketHookTransform, append(packet, '5'), nil
	}

	hc.append(hook1)
	hc.append(hook2)
	hc.append(hook3)
	hc.append(hook4)
	hc.append(hook5)

	finalHook := hc.hook()
	if finalHook == nil {
		t.Fatal("expected a non-nil hook")
	}

	packet := []byte("test")
	method, packetOut, err := finalHook(packet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if method != ssh.PipePacketHookReply {
		t.Errorf("expected method to be PipePacketHookReply, got %v", method)
	}

	expectedPacket := "test1234"
	if string(packetOut) != expectedPacket {
		t.Errorf("expected packetOut to be %q, got %q", expectedPacket, string(packetOut))
	}
}

func TestHookChain_HookWithError(t *testing.T) {
	hc := &hookChain{}

	// Mock hooks
	hook1 := func(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
		return ssh.PipePacketHookTransform, append(packet, '1'), nil
	}

	hookWithError := func(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
		return ssh.PipePacketHookTransform, nil, errors.New("mock error")
	}

	hc.append(hook1)
	hc.append(hookWithError)

	finalHook := hc.hook()
	if finalHook == nil {
		t.Fatal("expected a non-nil hook")
	}

	packet := []byte("test")
	_, _, err := finalHook(packet)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}

	expectedError := "mock error"
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err.Error())
	}
}
