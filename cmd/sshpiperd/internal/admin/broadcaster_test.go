package admin

import (
	"sync"
	"testing"
	"time"
)

func TestBroadcaster_PublishesToSubscribers(t *testing.T) {
	b := NewBroadcaster()
	defer b.Close()

	chA, cancelA := b.Subscribe(true)
	defer cancelA()
	chB, cancelB := b.Subscribe(true)
	defer cancelB()

	go b.Publish(Frame{Kind: "o", ChannelID: 1, Data: []byte("hi")})

	for i, ch := range []<-chan Frame{chA, chB} {
		select {
		case f := <-ch:
			if f.Kind != "o" || string(f.Data) != "hi" {
				t.Fatalf("subscriber %d got %+v", i, f)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d timed out", i)
		}
	}
}

func TestBroadcaster_ReplaysHeaderToLateSubscribers(t *testing.T) {
	b := NewBroadcaster()
	defer b.Close()

	b.Publish(Frame{Kind: "header", ChannelID: 7, Width: 80, Height: 24})
	if !b.HasHeader() {
		t.Fatalf("HasHeader should be true after a header frame")
	}

	ch, cancel := b.Subscribe(true)
	defer cancel()

	select {
	case f := <-ch:
		if f.Kind != "header" || f.ChannelID != 7 || f.Width != 80 {
			t.Fatalf("late subscriber didn't get header: %+v", f)
		}
	case <-time.After(time.Second):
		t.Fatal("late subscriber timed out waiting for replayed header")
	}
}

func TestBroadcaster_HeaderHistoryDeduplicatedPerChannel(t *testing.T) {
	b := NewBroadcaster()
	defer b.Close()

	b.Publish(Frame{Kind: "header", ChannelID: 1, Width: 80, Height: 24})
	b.Publish(Frame{Kind: "header", ChannelID: 1, Width: 100, Height: 30})
	b.Publish(Frame{Kind: "header", ChannelID: 2, Width: 120, Height: 40})

	ch, cancel := b.Subscribe(true)
	defer cancel()

	got := map[uint32]uint32{}
	for i := 0; i < 2; i++ {
		select {
		case f := <-ch:
			got[f.ChannelID] = f.Width
		case <-time.After(time.Second):
			t.Fatalf("expected 2 replayed headers, got %d", i)
		}
	}
	if got[1] != 100 || got[2] != 120 {
		t.Fatalf("unexpected replayed headers: %+v", got)
	}
}

func TestBroadcaster_DropsOnSlowSubscriber(t *testing.T) {
	b := NewBroadcaster()
	defer b.Close()

	// Subscribe but never read; the buffer is 256, so 1000 publishes must
	// neither block nor leak unbounded memory.
	_, cancel := b.Subscribe(true)
	defer cancel()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			b.Publish(Frame{Kind: "o", Data: []byte{byte(i)}})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow subscriber")
	}
}

func TestBroadcaster_CloseUnblocksSubscribers(t *testing.T) {
	b := NewBroadcaster()
	ch, cancel := b.Subscribe(true)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range ch {
			// drain
		}
	}()
	b.Close()
	doneCh := make(chan struct{})
	go func() { wg.Wait(); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("subscriber goroutine did not exit after Close")
	}
}

func TestBroadcaster_HasSubscribersAndReplayHeadersFalse(t *testing.T) {
	b := NewBroadcaster()
	defer b.Close()

	if b.HasSubscribers() {
		t.Fatal("HasSubscribers() should be false on a fresh broadcaster")
	}
	b.Publish(Frame{Kind: "header", ChannelID: 1, Width: 80, Height: 24})

	// replayHeaders=false: subscriber must NOT receive the cached header,
	// only frames published after subscribing.
	ch, cancel := b.Subscribe(false)
	defer cancel()

	if !b.HasSubscribers() {
		t.Fatal("HasSubscribers() should be true after Subscribe")
	}

	select {
	case f := <-ch:
		t.Fatalf("did not expect cached header, got %+v", f)
	case <-time.After(50 * time.Millisecond):
	}

	b.Publish(Frame{Kind: "o", ChannelID: 1, Data: []byte("x")})
	select {
	case f := <-ch:
		if f.Kind != "o" {
			t.Fatalf("got %+v, want output frame", f)
		}
	case <-time.After(time.Second):
		t.Fatal("expected output frame")
	}
}
