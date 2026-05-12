package led

import (
	"errors"
	"testing"
)

func TestStateRoundtrip(t *testing.T) {
	for _, s := range []State{StateOff, StateBooting, StateSetup, StateSecured, StateKillswitch, StateSigninOpen, StateFault} {
		got, err := ParseState(s.String())
		if err != nil {
			t.Errorf("ParseState(%q): %v", s, err)
		}
		if got != s {
			t.Errorf("ParseState(%q) = %s", s, got)
		}
	}
}

func TestParseStateUnknown(t *testing.T) {
	if _, err := ParseState("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestMockDriverRecordsHistory(t *testing.T) {
	d := NewMock()
	if d.Current() != StateOff {
		t.Errorf("initial = %s, want off", d.Current())
	}
	for _, s := range []State{StateBooting, StateSetup, StateSecured} {
		if err := d.Render(s); err != nil {
			t.Fatalf("Render: %v", err)
		}
	}
	if d.Current() != StateSecured {
		t.Errorf("current = %s, want secured", d.Current())
	}
	hist := d.History()
	if len(hist) != 3 {
		t.Fatalf("history len = %d, want 3", len(hist))
	}
	if hist[2] != StateSecured {
		t.Errorf("last in history = %s", hist[2])
	}
}

func TestPatternForSecuredIsSolidGreen(t *testing.T) {
	p := patternFor(StateSecured)
	if p.trigger != "none" {
		t.Errorf("trigger = %s, want none", p.trigger)
	}
	if p.rgb["green"] == 0 {
		t.Errorf("expected green channel set, got %d", p.rgb["green"])
	}
}

func TestPatternForKillswitchIsBlinkingRed(t *testing.T) {
	p := patternFor(StateKillswitch)
	if p.trigger != "timer" {
		t.Errorf("trigger = %s, want timer", p.trigger)
	}
	if p.rgb["red"] == 0 {
		t.Errorf("expected red channel set")
	}
	if p.delayOnMs == 0 || p.delayOffMs == 0 {
		t.Errorf("expected non-zero delays, got on=%d off=%d", p.delayOnMs, p.delayOffMs)
	}
}

func TestNewSysfsReturnsErrOnEmptyDir(t *testing.T) {
	// The dev container has no /sys/class/leds; assert we get the
	// documented error (not a panic).
	_, err := NewSysfs("")
	if err == nil {
		// On systems where /sys/class/leds happens to exist with entries,
		// this test is effectively skipped. That's acceptable — the test
		// is here to prove the error path doesn't crash, not to gate on
		// a particular environment.
		t.Skip("running on a host with /sys/class/leds entries; error path not exercisable")
	}
	if !errors.Is(err, ErrNoSysfs) {
		t.Errorf("expected ErrNoSysfs, got %v", err)
	}
}
