package main

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestNewIdleTimeoutHook_DisabledForNonPositiveTimeout(t *testing.T) {
	timer := time.AfterFunc(time.Hour, func() {})
	defer timer.Stop()
	if got := newIdleTimeoutHook(timer, 0); got != nil {
		t.Errorf("timeout=0: got %v, want nil", got)
	}
	if got := newIdleTimeoutHook(timer, -1); got != nil {
		t.Errorf("timeout<0: got %v, want nil", got)
	}
	if got := newIdleTimeoutHook(nil, time.Second); got != nil {
		t.Errorf("nil timer: got %v, want nil", got)
	}
}

func TestIdleTimeoutHook_OnlyChannelDataResetsTimer(t *testing.T) {
	fired := make(chan struct{}, 1)
	timer := time.AfterFunc(80*time.Millisecond, func() { fired <- struct{}{} })
	defer timer.Stop()

	hook := newIdleTimeoutHook(timer, 80*time.Millisecond)
	if hook == nil {
		t.Fatal("expected non-nil hook")
	}

	// Non channel-data packets must not reset the timer; after 100ms it
	// must fire even though we're calling the hook the whole time.
	end := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(end) {
		for _, msg := range []byte{1, 80, 90, 93, 96, 97} {
			method, out, err := hook([]byte{msg, 0xAA})
			if err != nil {
				t.Fatalf("hook returned error for msg %d: %v", msg, err)
			}
			if method != ssh.PipePacketHookTransform {
				t.Errorf("msg %d: method = %v, want Transform", msg, method)
			}
			if len(out) != 2 || out[0] != msg {
				t.Errorf("msg %d: hook must not modify packet, got %v", msg, out)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("timer never fired despite no channel-data activity")
	}
}

func TestIdleTimeoutHook_ChannelDataKeepsTimerAlive(t *testing.T) {
	fired := make(chan struct{}, 1)
	timer := time.AfterFunc(100*time.Millisecond, func() { fired <- struct{}{} })
	defer timer.Stop()

	hook := newIdleTimeoutHook(timer, 100*time.Millisecond)

	// Send channel data every 30ms for 300ms (well past one timeout window).
	end := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(end) {
		if _, _, err := hook([]byte{94, 'x'}); err != nil {
			t.Fatalf("hook err: %v", err)
		}
		time.Sleep(30 * time.Millisecond)
	}

	select {
	case <-fired:
		t.Error("timer fired while channel-data activity was ongoing")
	default:
	}

	// And after we stop sending data, it should fire shortly.
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Error("timer never fired after activity stopped")
	}
}
