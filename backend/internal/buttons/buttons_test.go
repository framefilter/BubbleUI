package buttons

import (
	"context"
	"testing"
	"time"
)

func TestMockPressEmitsDownThenUp(t *testing.T) {
	r := NewMock()
	defer r.Stop()

	go r.Press(context.Background(), Reset, 10*time.Millisecond)

	first := <-r.Events()
	if first.Button != Reset || first.Kind != Down {
		t.Errorf("first = %+v, want reset/down", first)
	}
	second := <-r.Events()
	if second.Button != Reset || second.Kind != Up {
		t.Errorf("second = %+v, want reset/up", second)
	}
	gap := second.At.Sub(first.At)
	if gap < 10*time.Millisecond {
		t.Errorf("gap = %v, want ≥ 10ms", gap)
	}
}

func TestMockStopClosesChannel(t *testing.T) {
	r := NewMock()
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	// Channel should be closed.
	_, ok := <-r.Events()
	if ok {
		t.Fatal("expected closed channel after Stop")
	}
	// Calling again is safe.
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop x2: %v", err)
	}
	// Subsequent Down/Up are no-ops, not panics.
	r.Down(Reset)
	r.Up(Reset)
}

func TestEventKindString(t *testing.T) {
	if Down.String() != "down" {
		t.Error()
	}
	if Up.String() != "up" {
		t.Error()
	}
}

func TestNewLinuxStubReturnsErr(t *testing.T) {
	if _, err := NewLinux(); err == nil {
		t.Fatal("expected stub to return ErrNotImplemented")
	}
}
