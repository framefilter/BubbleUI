// Package signin manages the captive-portal sign-in window from
// DESIGN.md §6.5: a tightly-scoped, time-boxed, user-consented bypass
// of the kill switch that lets the user reach the hotel portal page
// without dropping the kill switch globally.
//
// The state machine has three states:
//
//	Closed    — kill switch fully engaged. Default.
//	Open      — firewall hole active to a fixed PortalIPs set on
//	            TCP 80/443; scoped DNS forwarder running. Auto-expires
//	            at Deadline.
//	Expiring  — graceful window: probe success was just observed and
//	            we're tearing down the rule + reverting DNS before
//	            handing off to the WG bring-up. Brief.
//
// The actual nftables rules and dnsmasq invocations live behind the
// Applier interface. The dev binary uses NoopApplier; the router-side
// implementation lands when we have hardware. The state machine is
// fully testable without either.
package signin

import (
	"context"
	"errors"
	"sync"
	"time"
)

// State enumerates the window lifecycle.
type State int

const (
	StateClosed State = iota
	StateOpen
	StateExpiring
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateExpiring:
		return "expiring"
	default:
		return "unknown"
	}
}

// Errors surfaced by the state machine. Callers should map all to a
// single 4xx for users.
var (
	ErrAlreadyOpen = errors.New("signin: window already open")
	ErrNotOpen     = errors.New("signin: window not open")
	ErrStrictMode  = errors.New("signin: strict mode is enabled — auto-bypass disabled")
	ErrNoPortalIPs = errors.New("signin: cannot open with empty portal-IP allowlist")
)

// Applier is what actually opens / closes the firewall hole and the
// scoped DNS forwarder. Production wires this to nftables + dnsmasq.
type Applier interface {
	Open(ctx context.Context, portalIPs []string, ports []int) error
	Close(ctx context.Context) error
}

// NoopApplier is the dev/test default: it records what it was asked to
// do and reports it back via Last(). On a router with no nftables
// available, swap in a real Applier when hardware support lands.
type NoopApplier struct {
	mu        sync.Mutex
	lastOpen  *appliedOpen
	lastClose time.Time
}

type appliedOpen struct {
	at    time.Time
	ips   []string
	ports []int
}

func (a *NoopApplier) Open(_ context.Context, ips []string, ports []int) error {
	a.mu.Lock()
	a.lastOpen = &appliedOpen{at: time.Now(), ips: append([]string(nil), ips...), ports: append([]int(nil), ports...)}
	a.mu.Unlock()
	return nil
}

func (a *NoopApplier) Close(_ context.Context) error {
	a.mu.Lock()
	a.lastClose = time.Now()
	a.mu.Unlock()
	return nil
}

// Last returns the last (open, close) timestamps. Useful for tests.
func (a *NoopApplier) Last() (lastOpenIPs []string, lastClose time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastOpen != nil {
		lastOpenIPs = append([]string(nil), a.lastOpen.ips...)
	}
	return lastOpenIPs, a.lastClose
}

// Manager is the state-machine owner. One per running daemon.
type Manager struct {
	applier  Applier
	now      func() time.Time
	defaultD time.Duration
	ports    []int

	mu        sync.Mutex
	state     State
	openedAt  time.Time
	deadline  time.Time
	portalIPs []string
	strict    bool
}

// Config carries deps + defaults.
type Config struct {
	Applier         Applier
	DefaultDuration time.Duration // window lifetime; default 10 min
	AllowedPorts    []int         // ports allowed during the window; default {80, 443}
}

// New constructs a Manager.
func New(cfg Config) *Manager {
	if cfg.DefaultDuration == 0 {
		cfg.DefaultDuration = 10 * time.Minute
	}
	ports := cfg.AllowedPorts
	if len(ports) == 0 {
		ports = []int{80, 443}
	}
	return &Manager{
		applier:  cfg.Applier,
		now:      time.Now,
		defaultD: cfg.DefaultDuration,
		ports:    ports,
		state:    StateClosed,
	}
}

// SetClock overrides the time source. For tests.
func (m *Manager) SetClock(f func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = f
}

// SetStrict toggles strict mode. In strict mode, Open() is rejected;
// users must clear captive portals via a separate dedicated SSID
// (DESIGN.md §6.5 strict-mode). Default off.
func (m *Manager) SetStrict(s bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.strict = s
}

// Strict reports the current strict-mode setting.
func (m *Manager) Strict() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.strict
}

// Open transitions Closed → Open with the given portal IPs and a
// time-boxed deadline. duration=0 uses the configured default.
func (m *Manager) Open(ctx context.Context, portalIPs []string, duration time.Duration) error {
	if len(portalIPs) == 0 {
		return ErrNoPortalIPs
	}
	if duration == 0 {
		duration = m.defaultD
	}

	m.mu.Lock()
	if m.strict {
		m.mu.Unlock()
		return ErrStrictMode
	}
	if m.state != StateClosed {
		m.mu.Unlock()
		return ErrAlreadyOpen
	}
	now := m.now()
	m.state = StateOpen
	m.openedAt = now
	m.deadline = now.Add(duration)
	m.portalIPs = append([]string(nil), portalIPs...)
	ports := append([]int(nil), m.ports...)
	m.mu.Unlock()

	if err := m.applier.Open(ctx, portalIPs, ports); err != nil {
		// Roll back state if the applier rejects.
		m.mu.Lock()
		m.state = StateClosed
		m.deadline = time.Time{}
		m.openedAt = time.Time{}
		m.portalIPs = nil
		m.mu.Unlock()
		return err
	}
	return nil
}

// Close tears down the window unconditionally. No-op if already closed.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	if m.state == StateClosed {
		m.mu.Unlock()
		return nil
	}
	m.state = StateClosed
	m.deadline = time.Time{}
	m.openedAt = time.Time{}
	m.portalIPs = nil
	m.mu.Unlock()

	return m.applier.Close(ctx)
}

// Tick is what a periodic timer (or a probe success callback) calls to
// progress the state machine. If the window has hit its deadline,
// Tick closes it. Returns true if a state transition happened.
func (m *Manager) Tick(ctx context.Context) bool {
	m.mu.Lock()
	if m.state != StateOpen {
		m.mu.Unlock()
		return false
	}
	if m.now().Before(m.deadline) {
		m.mu.Unlock()
		return false
	}
	m.mu.Unlock()
	_ = m.Close(ctx)
	return true
}

// Status snapshots current state for the UI.
type Status struct {
	State        State
	OpenedAt     time.Time
	Deadline     time.Time
	RemainingSec int64
	PortalIPs    []string
	AllowedPorts []int
	StrictMode   bool
}

// Status returns a stable snapshot.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Status{
		State:        m.state,
		OpenedAt:     m.openedAt,
		Deadline:     m.deadline,
		PortalIPs:    append([]string(nil), m.portalIPs...),
		AllowedPorts: append([]int(nil), m.ports...),
		StrictMode:   m.strict,
	}
	if m.state == StateOpen {
		rem := m.deadline.Sub(m.now())
		if rem < 0 {
			rem = 0
		}
		s.RemainingSec = int64(rem.Seconds())
	}
	return s
}
