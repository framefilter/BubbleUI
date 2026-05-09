package signin

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newManager(t *testing.T) (*Manager, *NoopApplier) {
	t.Helper()
	a := &NoopApplier{}
	m := New(Config{Applier: a, DefaultDuration: 10 * time.Minute})
	return m, a
}

func TestOpenClose(t *testing.T) {
	m, a := newManager(t)
	ctx := context.Background()

	if err := m.Open(ctx, []string{"203.0.113.42"}, 0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := m.Status().State; got != StateOpen {
		t.Errorf("state = %s, want open", got)
	}

	openIPs, _ := a.Last()
	if len(openIPs) != 1 || openIPs[0] != "203.0.113.42" {
		t.Errorf("applier saw IPs = %v", openIPs)
	}

	if err := m.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := m.Status().State; got != StateClosed {
		t.Errorf("state = %s, want closed", got)
	}
	_, lastClose := a.Last()
	if lastClose.IsZero() {
		t.Error("applier was not asked to close")
	}
}

func TestOpenRejectsEmptyIPs(t *testing.T) {
	m, _ := newManager(t)
	if err := m.Open(context.Background(), nil, 0); !errors.Is(err, ErrNoPortalIPs) {
		t.Fatalf("expected ErrNoPortalIPs, got %v", err)
	}
}

func TestOpenRejectsWhenAlreadyOpen(t *testing.T) {
	m, _ := newManager(t)
	if err := m.Open(context.Background(), []string{"1.2.3.4"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := m.Open(context.Background(), []string{"5.6.7.8"}, 0); !errors.Is(err, ErrAlreadyOpen) {
		t.Fatalf("expected ErrAlreadyOpen, got %v", err)
	}
}

func TestStrictModeBlocksOpen(t *testing.T) {
	m, _ := newManager(t)
	m.SetStrict(true)
	if err := m.Open(context.Background(), []string{"1.2.3.4"}, 0); !errors.Is(err, ErrStrictMode) {
		t.Fatalf("expected ErrStrictMode, got %v", err)
	}
	// Disable strict and try again.
	m.SetStrict(false)
	if err := m.Open(context.Background(), []string{"1.2.3.4"}, 0); err != nil {
		t.Fatalf("Open after un-strict: %v", err)
	}
}

func TestTickClosesAfterDeadline(t *testing.T) {
	m, a := newManager(t)
	t0 := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	now := t0
	m.SetClock(func() time.Time { return now })

	if err := m.Open(context.Background(), []string{"1.2.3.4"}, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	// Before deadline: no transition.
	now = t0.Add(2 * time.Minute)
	if m.Tick(context.Background()) {
		t.Fatal("Tick should not have transitioned before deadline")
	}
	if m.Status().State != StateOpen {
		t.Fatal("state should still be open")
	}
	// At deadline: closed.
	now = t0.Add(6 * time.Minute)
	if !m.Tick(context.Background()) {
		t.Fatal("Tick should have transitioned past deadline")
	}
	if m.Status().State != StateClosed {
		t.Fatal("state should be closed")
	}
	if _, lc := a.Last(); lc.IsZero() {
		t.Fatal("applier not asked to close")
	}
}

func TestStatusReportsRemaining(t *testing.T) {
	m, _ := newManager(t)
	t0 := time.Now()
	now := t0
	m.SetClock(func() time.Time { return now })

	if err := m.Open(context.Background(), []string{"1.2.3.4"}, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	now = t0.Add(3 * time.Minute)
	s := m.Status()
	// Opened with 10 min, used 3, expect ~7 min = 420 s remaining.
	if s.RemainingSec < 7*60-2 || s.RemainingSec > 7*60+2 {
		t.Errorf("RemainingSec = %d, want ~420", s.RemainingSec)
	}
	if len(s.PortalIPs) != 1 || s.PortalIPs[0] != "1.2.3.4" {
		t.Errorf("PortalIPs = %v", s.PortalIPs)
	}
	if len(s.AllowedPorts) != 2 || s.AllowedPorts[0] != 80 || s.AllowedPorts[1] != 443 {
		t.Errorf("AllowedPorts = %v", s.AllowedPorts)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	m, _ := newManager(t)
	if err := m.Close(context.Background()); err != nil {
		t.Fatalf("Close on closed: %v", err)
	}
	if err := m.Close(context.Background()); err != nil {
		t.Fatalf("Close again: %v", err)
	}
}

func TestApplierFailureRollsBackState(t *testing.T) {
	failing := &failingApplier{err: errors.New("nft: rule rejected")}
	m := New(Config{Applier: failing})
	if err := m.Open(context.Background(), []string{"1.2.3.4"}, 0); err == nil {
		t.Fatal("expected applier error to bubble up")
	}
	if got := m.Status().State; got != StateClosed {
		t.Errorf("state = %s, want closed (rolled back)", got)
	}
}

type failingApplier struct {
	err error
}

func (f *failingApplier) Open(_ context.Context, _ []string, _ []int) error { return f.err }
func (f *failingApplier) Close(_ context.Context) error                     { return nil }
