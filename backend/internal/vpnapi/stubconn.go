package vpnapi

import (
	"context"
	"sync/atomic"

	"github.com/framefilter/bubbleui/backend/internal/wgpool"
)

// StubConnector is a Connector that does nothing but record state. The
// dev daemon (`bubble-vpnd -mock`) uses it; tests use it directly.
//
// On the router we'll swap in a real Connector that shells out to
// `wg-quick up <iface>` / `wg-quick down <iface>` and writes the active
// config to /etc/bubble/wg/active.conf.
type StubConnector struct {
	active atomic.Int64
}

func (s *StubConnector) Connect(_ context.Context, c wgpool.Config) error {
	s.active.Store(c.ID)
	return nil
}

func (s *StubConnector) Disconnect(_ context.Context) error {
	s.active.Store(0)
	return nil
}

func (s *StubConnector) Active() int64 { return s.active.Load() }
