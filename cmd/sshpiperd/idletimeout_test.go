package main

import (
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestNewIdleTracker_DisabledForNonPositiveTimeout(t *testing.T) {
	if got := newIdleTracker(0); got != nil {
		t.Errorf("newIdleTracker(0) = %v, want nil", got)
	}
	if got := newIdleTracker(-1 * time.Second); got != nil {
		t.Errorf("newIdleTracker(-1s) = %v, want nil", got)
	}
}

func TestIdleTrackerHook_RecordsChannelData(t *testing.T) {
	tr := newIdleTracker(time.Hour)
	if tr == nil {
		t.Fatal("expected non-nil tracker")
	}
	defer tr.stop()

	// Force lastNano well into the past.
	tr.lastNano.Store(time.Now().Add(-time.Hour).UnixNano())
	old := tr.lastNano.Load()

	hook := tr.hook()

	// Non channel-data packets should NOT bump lastNano.
	for _, msg := range []byte{
		1,  // disconnect
		80, // global request
		90, // channel open
		93, // window adjust
		96, // channel EOF
		97, // channel close
	} {
		method, out, err := hook([]byte{msg, 0xAA, 0xBB})
		if err != nil {
			t.Fatalf("hook returned error for msg %d: %v", msg, err)
		}
		if method != ssh.PipePacketHookTransform {
			t.Errorf("msg %d: method = %v, want Transform", msg, method)
		}
		if len(out) != 3 || out[0] != msg {
			t.Errorf("msg %d: hook must not modify packet, got %v", msg, out)
		}
	}
	if tr.lastNano.Load() != old {
		t.Errorf("non-data packets must not bump lastNano")
	}

	// Channel data and extended data must bump lastNano.
	for _, msg := range []byte{idleMsgChannelData, idleMsgChannelExtendedData} {
		old := tr.lastNano.Load()
		// Sleep to guarantee a different UnixNano.
		time.Sleep(2 * time.Millisecond)
		if _, _, err := hook([]byte{msg, 1, 2, 3}); err != nil {
			t.Fatalf("hook returned error for msg %d: %v", msg, err)
		}
		if tr.lastNano.Load() <= old {
			t.Errorf("msg %d: lastNano was not advanced (was %d, now %d)", msg, old, tr.lastNano.Load())
		}
	}

	// An empty packet is tolerated.
	if _, out, err := hook(nil); err != nil || out != nil {
		t.Errorf("hook(nil) = (%v, %v), want (nil, nil)", out, err)
	}
}

func TestIdleTracker_FiresAfterTimeout(t *testing.T) {
	tr := newIdleTracker(50 * time.Millisecond)
	if tr == nil {
		t.Fatal("expected non-nil tracker")
	}

	var fired atomic.Int32
	tr.run(func() { fired.Add(1) })

	// Wait long enough for several check intervals.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && fired.Load() == 0 {
		time.Sleep(20 * time.Millisecond)
	}

	if fired.Load() != 1 {
		t.Fatalf("onTimeout fired %d times, want 1", fired.Load())
	}

	// stop must be safe even after the goroutine has already returned, and
	// safe to call multiple times.
	tr.stop()
	tr.stop()
}

func TestIdleTracker_DoesNotFireWhileActive(t *testing.T) {
	tr := newIdleTracker(80 * time.Millisecond)
	if tr == nil {
		t.Fatal("expected non-nil tracker")
	}
	defer tr.stop()

	var fired atomic.Int32
	tr.run(func() { fired.Add(1) })

	hook := tr.hook()
	// Send channel-data every 20ms for ~300ms (well past the 80ms timeout).
	end := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(end) {
		if _, _, err := hook([]byte{idleMsgChannelData, 'x'}); err != nil {
			t.Fatalf("hook returned error: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := fired.Load(); got != 0 {
		t.Errorf("onTimeout fired %d times while active, want 0", got)
	}
}
