package buttons

import (
	"context"
	"testing"
	"time"
)

func TestLongPressEmitsStagesInOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := NewMock()
	defer r.Stop()

	lp := NewLongPress(ctx, r, Reset, []time.Duration{
		50 * time.Millisecond,
		120 * time.Millisecond,
		250 * time.Millisecond,
	})

	r.Down(Reset)

	var got []Stage
	deadline := time.After(800 * time.Millisecond)
loop:
	for len(got) < 3 {
		select {
		case s := <-lp.Stages():
			got = append(got, s)
		case <-deadline:
			break loop
		}
	}
	r.Up(Reset)

	if len(got) != 3 {
		t.Fatalf("got %d stages, want 3: %+v", len(got), got)
	}
	for i, s := range got {
		if s.Released {
			t.Errorf("stage %d should not be released", i)
		}
		if s.Index != i {
			t.Errorf("stage %d Index = %d, want %d", i, s.Index, i)
		}
		if s.Button != Reset {
			t.Errorf("stage %d Button = %s", i, s.Button)
		}
	}
}

func TestLongPressUpBeforeFirstThresholdEmitsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewMock()
	defer r.Stop()

	lp := NewLongPress(ctx, r, Reset, []time.Duration{500 * time.Millisecond})
	r.Down(Reset)
	time.Sleep(20 * time.Millisecond)
	r.Up(Reset)

	select {
	case s := <-lp.Stages():
		t.Fatalf("expected no stages, got %+v", s)
	case <-time.After(200 * time.Millisecond):
		// Good.
	}
}

func TestLongPressReleaseAfterStageEmitsReleased(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewMock()
	defer r.Stop()

	lp := NewLongPress(ctx, r, Reset, []time.Duration{
		50 * time.Millisecond,
		500 * time.Millisecond,
	})
	r.Down(Reset)

	// Wait for the first stage to fire.
	first := <-lp.Stages()
	if first.Released {
		t.Fatal("first stage should not be Released")
	}

	r.Up(Reset)

	released := <-lp.Stages()
	if !released.Released {
		t.Fatalf("expected Released=true, got %+v", released)
	}
	if released.Index != 0 {
		t.Errorf("Released Index = %d, want 0 (highest reached)", released.Index)
	}
}

func TestLongPressIgnoresOtherButtons(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewMock()
	defer r.Stop()

	lp := NewLongPress(ctx, r, Reset, []time.Duration{30 * time.Millisecond})
	r.Down(Mode1)
	r.Up(Mode1)

	select {
	case s := <-lp.Stages():
		t.Fatalf("unexpected stage from non-Reset button: %+v", s)
	case <-time.After(80 * time.Millisecond):
	}
}

func TestLongPressCancelClosesChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := NewMock()
	defer r.Stop()

	lp := NewLongPress(ctx, r, Reset, []time.Duration{50 * time.Millisecond})
	cancel()

	// Channel should close within a beat.
	select {
	case _, ok := <-lp.Stages():
		if ok {
			t.Error("expected closed channel after cancel")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Stages channel did not close after cancel")
	}
}

func TestLongPressEmptyThresholdsIsHarmless(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewMock()
	defer r.Stop()

	lp := NewLongPress(ctx, r, Reset, nil)
	r.Down(Reset)
	r.Up(Reset)

	select {
	case s := <-lp.Stages():
		t.Fatalf("expected no stages, got %+v", s)
	case <-time.After(60 * time.Millisecond):
	}
}
