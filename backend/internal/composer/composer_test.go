package composer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/framefilter/bubbleui/backend/internal/led"
)

type recorderSetter struct {
	mu      sync.Mutex
	history []led.State
}

func (r *recorderSetter) Set(s led.State) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.history = append(r.history, s)
	return nil
}

func (r *recorderSetter) last() led.State {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.history) == 0 {
		return led.StateOff
	}
	return r.history[len(r.history)-1]
}

func newComposer(t *testing.T, vpnBody, signinBody string) (*Composer, *recorderSetter) {
	t.Helper()
	vpn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(vpnBody))
	}))
	signin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(signinBody))
	}))
	t.Cleanup(func() {
		vpn.Close()
		signin.Close()
	})

	r := &recorderSetter{}
	c := New(Config{
		Source: Source{
			VPNStatusURL: vpn.URL + "/vpn/status",
			NetSigninURL: signin.URL + "/net/signin/status",
		},
		Setter:   r,
		Interval: 50 * time.Millisecond,
	})
	return c, r
}

func TestComposeSigninOpenWins(t *testing.T) {
	c, r := newComposer(t,
		`{"active_id":7}`,
		`{"state":"open"}`,
	)
	got := c.Tick(context.Background())
	if got != led.StateSigninOpen {
		t.Errorf("got %s, want signin_open", got)
	}
	if r.last() != led.StateSigninOpen {
		t.Errorf("setter last = %s", r.last())
	}
}

func TestComposeSecuredWhenTunnelUpAndSigninClosed(t *testing.T) {
	c, _ := newComposer(t,
		`{"active_id":3,"label":"ch","endpoint":"x.example:51820"}`,
		`{"state":"closed"}`,
	)
	if got := c.Tick(context.Background()); got != led.StateSecured {
		t.Errorf("got %s, want secured", got)
	}
}

func TestComposeKillswitchWhenTunnelDown(t *testing.T) {
	c, _ := newComposer(t,
		`{"active_id":0}`,
		`{"state":"closed"}`,
	)
	if got := c.Tick(context.Background()); got != led.StateKillswitch {
		t.Errorf("got %s, want killswitch_up", got)
	}
}

func TestComposeBootingWhenBothDaemonsUnreachable(t *testing.T) {
	r := &recorderSetter{}
	c := New(Config{
		Source: Source{
			VPNStatusURL:   "http://127.0.0.1:1/vpn/status",
			NetSigninURL:   "http://127.0.0.1:1/net/signin/status",
			PerCallTimeout: 100 * time.Millisecond,
		},
		Setter: r,
	})
	if got := c.Tick(context.Background()); got != led.StateBooting {
		t.Errorf("got %s, want booting", got)
	}
}

func TestComposeKillswitchWhenSigninUnreachableButVPNDown(t *testing.T) {
	// vpnd reports down + bad signin URL: precedence falls through to
	// killswitch (we successfully read tunnel state).
	c, _ := newComposer(t,
		`{"active_id":0}`,
		``, // empty body → JSON parse fails
	)
	got := c.Tick(context.Background())
	if got != led.StateKillswitch {
		t.Errorf("got %s, want killswitch_up", got)
	}
}

func TestRunPushesInitialStateThenTicks(t *testing.T) {
	c, r := newComposer(t,
		`{"active_id":1}`,
		`{"state":"closed"}`,
	)
	ctx, cancel := context.WithCancel(context.Background())
	go c.Run(ctx)

	// Wait for at least one tick.
	deadline := time.After(2 * time.Second)
	for {
		if r.last() == led.StateSecured {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("never reached secured; history=%v", r.history)
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	// Give the loop a moment to exit.
	time.Sleep(100 * time.Millisecond)
}

func TestLastReturnsLatest(t *testing.T) {
	c, _ := newComposer(t,
		`{"active_id":2}`,
		`{"state":"closed"}`,
	)
	c.Tick(context.Background())
	if c.Last() != led.StateSecured {
		t.Errorf("Last = %s, want secured", c.Last())
	}
}
