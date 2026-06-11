// Package aggregator wraps libadmin.Aggregator with a periodic background
// refresh loop and convenience helpers used by the sshpiperd-webadmin HTTP
// layer. Keeping the loop here (rather than inside libadmin) lets the CLI
// tool decide for itself whether it wants on-demand or periodic refresh.
package aggregator

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libadmin"
)

// Aggregator is a thin wrapper around libadmin.Aggregator adding a
// background refresh loop.
type Aggregator struct {
	*libadmin.Aggregator
	interval time.Duration

	cancelMu sync.Mutex
	cancel   context.CancelFunc
}

// New constructs a webadmin Aggregator. The background refresh loop is not
// started automatically; call StartBackgroundRefresh once configuration is
// complete.
func New(d libadmin.Discovery, opts libadmin.DialOptions, interval time.Duration) *Aggregator {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Aggregator{
		Aggregator: libadmin.NewAggregator(d, opts),
		interval:   interval,
	}
}

// StartBackgroundRefresh kicks off a goroutine that periodically calls
// Refresh. It is safe to call multiple times: extra calls are no-ops.
func (a *Aggregator) StartBackgroundRefresh() {
	a.cancelMu.Lock()
	defer a.cancelMu.Unlock()
	if a.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	go a.loop(ctx)
}

func (a *Aggregator) loop(ctx context.Context) {
	t := time.NewTicker(a.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rctx, cancel := context.WithTimeout(ctx, a.interval)
			if _, errs := a.Refresh(rctx); len(errs) > 0 {
				for _, err := range errs {
					log.Debugf("aggregator refresh: %v", err)
				}
			}
			cancel()
		}
	}
}

// Close stops the background refresh loop and releases all underlying
// connections.
func (a *Aggregator) Close() error {
	a.cancelMu.Lock()
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	a.cancelMu.Unlock()
	return a.Aggregator.Close()
}
