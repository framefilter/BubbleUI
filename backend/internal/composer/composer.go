// Package composer is bubble-hwd's cross-daemon orchestrator. It
// periodically polls /vpn/status and /net/signin/status and composes
// them into the right led.State per DESIGN.md §13.5.
//
// The composer is the source of truth for the LED in steady state.
// Manual writes via POST /hw/led are not blocked, but the next
// composer tick (~5 s) will overwrite them — manual writes are for
// short-lived flows like a future "test the LED" Settings button.
//
// State precedence, highest-wins:
//
//  1. SigninOpen   — captive-portal sign-in window is open (§6.5)
//  2. NoKey        — credential registered but YubiKey not on USB
//  3. Secured      — bubble-vpnd reports a tunnel is active
//  4. Killswitch   — no tunnel + no sign-in window: LAN→WAN blocked
//  5. Booting      — couldn't reach either daemon (best-effort fallback)
//
// NoKey is consulted via Source.AuthHealthURL. If that's unset (older
// bubble-authd, or the operator opted out) the rule is skipped silently.
// "Fault" is reserved for hardware faults we can't yet detect.
package composer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/framefilter/bubbleui/backend/internal/led"
)

// Source is the set of upstream-daemon URLs the composer polls.
type Source struct {
	VPNStatusURL   string // e.g. "http://127.0.0.1:8766/vpn/status"
	NetSigninURL   string // e.g. "http://127.0.0.1:8767/net/signin/status"
	AuthHealthURL  string // e.g. "http://127.0.0.1:8765/auth/health" (optional)
	HTTP           *http.Client
	PerCallTimeout time.Duration // default 1s
}

// Setter is what the composer pushes the resolved state to. The
// hwapi.Server.Set method satisfies it.
type Setter interface {
	Set(s led.State) error
}

// Composer is the orchestrator.
type Composer struct {
	src      Source
	setter   Setter
	interval time.Duration
	logger   *slog.Logger

	mu   sync.Mutex
	last led.State
}

// Config carries deps + cadence.
type Config struct {
	Source   Source
	Setter   Setter
	Interval time.Duration // default 5s
	Logger   *slog.Logger
}

// New configures a Composer.
func New(cfg Config) *Composer {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.Source.HTTP == nil {
		t := cfg.Source.PerCallTimeout
		if t == 0 {
			t = time.Second
		}
		cfg.Source.HTTP = &http.Client{Timeout: t}
	}
	return &Composer{
		src:      cfg.Source,
		setter:   cfg.Setter,
		interval: cfg.Interval,
		logger:   cfg.Logger,
	}
}

// Run loops until ctx is cancelled, ticking every interval. The
// initial state is computed and pushed before the first tick so the
// LED gets out of "off" quickly.
func (c *Composer) Run(ctx context.Context) {
	c.tick(ctx)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.tick(ctx)
		}
	}
}

// Tick runs one cycle synchronously. Useful for tests; Run calls it
// internally on a ticker.
func (c *Composer) Tick(ctx context.Context) led.State {
	return c.tick(ctx)
}

// Last returns the most-recently-resolved state. Useful for diagnostics.
func (c *Composer) Last() led.State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

func (c *Composer) tick(ctx context.Context) led.State {
	state := c.compose(ctx)
	c.mu.Lock()
	c.last = state
	c.mu.Unlock()
	if err := c.setter.Set(state); err != nil {
		c.logger.Warn("composer: setter failed", "state", state.String(), "err", err)
	}
	return state
}

// compose runs the precedence ladder. Each upstream call is bounded
// by Source.HTTP.Timeout; failures fall through to the next rule.
func (c *Composer) compose(ctx context.Context) led.State {
	if open, ok := c.signinOpen(ctx); ok && open {
		return led.StateSigninOpen
	}
	if missing, ok := c.keyMissing(ctx); ok && missing {
		return led.StateNoKey
	}
	if up, ok := c.tunnelUp(ctx); ok {
		if up {
			return led.StateSecured
		}
		// Sign-in not open + tunnel down + we successfully reached
		// bubble-vpnd: the kill switch is doing its job.
		return led.StateKillswitch
	}
	// Everything failed; report best-effort booting.
	return led.StateBooting
}

func (c *Composer) signinOpen(ctx context.Context) (open bool, reachable bool) {
	type signinResp struct {
		State string `json:"state"`
	}
	var s signinResp
	if err := getJSON(ctx, c.src.HTTP, c.src.NetSigninURL, &s); err != nil {
		c.logger.Debug("composer: net signin probe failed", "err", err)
		return false, false
	}
	return s.State == "open", true
}

// keyMissing reports whether bubble-authd has a credential registered
// AND can no longer see the YubiKey on USB. ok=false when AuthHealthURL
// isn't configured or the request fails — in either case the rule is
// skipped (we don't want a transient netd hiccup to falsely flash NoKey).
func (c *Composer) keyMissing(ctx context.Context) (missing bool, ok bool) {
	if c.src.AuthHealthURL == "" {
		return false, false
	}
	type healthResp struct {
		HasCredentials bool `json:"has_credentials"`
		YubiKeyPresent bool `json:"yubikey_present"`
	}
	var h healthResp
	if err := getJSON(ctx, c.src.HTTP, c.src.AuthHealthURL, &h); err != nil {
		c.logger.Debug("composer: auth health probe failed", "err", err)
		return false, false
	}
	return h.HasCredentials && !h.YubiKeyPresent, true
}

func (c *Composer) tunnelUp(ctx context.Context) (up bool, reachable bool) {
	type vpnResp struct {
		ActiveID int64 `json:"active_id"`
	}
	var v vpnResp
	if err := getJSON(ctx, c.src.HTTP, c.src.VPNStatusURL, &v); err != nil {
		c.logger.Debug("composer: vpn status probe failed", "err", err)
		return false, false
	}
	return v.ActiveID != 0, true
}

func getJSON(ctx context.Context, client *http.Client, url string, out any) error {
	if url == "" {
		return fmt.Errorf("composer: empty url")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("composer: %s returned %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
