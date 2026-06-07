package admin

import (
	"sync"
	"time"
)

// Frame is one event published to subscribers of a session.
//
// It mirrors the structure of an asciicast v2 record: a session begins with
// at least one Header frame (one per pty/exec channel that opens), and is
// followed by Output, Input, and Resize frames as the user interacts.
type Frame struct {
	// Kind is one of: "header", "o" (output), "i" (input), "r" (resize).
	Kind string
	// ChannelID identifies which SSH channel the frame belongs to. A single
	// SSH session can host multiple shell/exec channels concurrently.
	ChannelID uint32
	// Time is the wall-clock time the event was observed.
	Time time.Time

	// For "header" frames:
	Width, Height uint32
	Env           map[string]string

	// For "o" / "i" / "r" frames:
	Data []byte
}

// Broadcaster fans out per-session Frames to any number of live subscribers.
//
// Subscribers receive frames via a buffered channel; if a subscriber falls
// behind, frames addressed to it are dropped (the channel is full) so that
// slow viewers cannot back-pressure the recording hot path.
type Broadcaster struct {
	mu          sync.Mutex
	subscribers map[chan Frame]struct{}
	history     []Frame // header(s) only — kept so late subscribers can render
	closed      bool
}

// NewBroadcaster returns a Broadcaster with no subscribers.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{subscribers: make(map[chan Frame]struct{})}
}

// Subscribe registers a new subscriber and returns its receive channel plus
// a cancel function. The cancel function must be called when the subscriber
// is done. If replayHeaders is true, any header frames previously seen on
// this broadcaster are delivered to the new subscriber up-front so it can
// render the correct terminal size before the first output frame arrives.
func (b *Broadcaster) Subscribe(replayHeaders bool) (<-chan Frame, func()) {
	ch := make(chan Frame, 256)
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		close(ch)
		return ch, func() {}
	}
	b.subscribers[ch] = struct{}{}
	if replayHeaders {
		// replay any cached header frames so late joiners see the correct geometry
		for _, f := range b.history {
			select {
			case ch <- f:
			default:
			}
		}
	}
	b.mu.Unlock()
	return ch, func() { b.unsubscribe(ch) }
}

// HasSubscribers reports whether the broadcaster currently has at least one
// active subscriber. Producers can use this as a cheap fast-path to skip
// expensive packet parsing / Frame construction when nobody is watching.
func (b *Broadcaster) HasSubscribers() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.closed && len(b.subscribers) > 0
}

func (b *Broadcaster) unsubscribe(ch chan Frame) {
	b.mu.Lock()
	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
	b.mu.Unlock()
}

// Publish sends a frame to all current subscribers. Subscribers whose
// channels are full have the frame dropped — they are never blocked on.
// Header frames are also remembered so future subscribers can replay them.
func (b *Broadcaster) Publish(f Frame) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	if f.Kind == "header" {
		// keep at most one header per channel to bound memory
		filtered := b.history[:0]
		for _, h := range b.history {
			if h.ChannelID != f.ChannelID {
				filtered = append(filtered, h)
			}
		}
		b.history = append(filtered, f)
	}
	for ch := range b.subscribers {
		select {
		case ch <- f:
		default:
			// drop on slow subscribers; viewers are best-effort
		}
	}
	b.mu.Unlock()
}

// HasHeader reports whether the broadcaster has seen at least one header
// frame, i.e. whether a stream subscriber would receive any meaningful data.
func (b *Broadcaster) HasHeader() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.history) > 0
}

// Close terminates all subscribers and prevents further publishing.
func (b *Broadcaster) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for ch := range b.subscribers {
		close(ch)
	}
	b.subscribers = nil
}
