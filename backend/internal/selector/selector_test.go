package selector

import (
	"errors"
	"testing"
	"time"

	"github.com/framefilter/bubbleui/backend/internal/prober"
	"github.com/framefilter/bubbleui/backend/internal/wgpool"
)

func TestRankPicksLowestRTT(t *testing.T) {
	cfgs := []wgpool.Config{
		{ID: 1, Enabled: true},
		{ID: 2, Enabled: true},
		{ID: 3, Enabled: true},
	}
	now := time.Now()
	results := []prober.Result{
		{ID: 1, RTT: 50 * time.Millisecond, StartAt: now},
		{ID: 2, RTT: 12 * time.Millisecond, StartAt: now},
		{ID: 3, RTT: 30 * time.Millisecond, StartAt: now},
	}
	ranked := Rank(cfgs, results)
	if ranked[0].Config.ID != 2 {
		t.Errorf("top = %d, want 2", ranked[0].Config.ID)
	}
	if ranked[1].Config.ID != 3 {
		t.Errorf("second = %d, want 3", ranked[1].Config.ID)
	}
	if ranked[2].Config.ID != 1 {
		t.Errorf("third = %d, want 1", ranked[2].Config.ID)
	}
}

func TestRankFailedProbesAfterSuccessful(t *testing.T) {
	cfgs := []wgpool.Config{
		{ID: 1, Enabled: true},
		{ID: 2, Enabled: true},
	}
	now := time.Now()
	results := []prober.Result{
		{ID: 1, Err: errors.New("timeout"), StartAt: now},
		{ID: 2, RTT: 99 * time.Millisecond, StartAt: now},
	}
	ranked := Rank(cfgs, results)
	if ranked[0].Config.ID != 2 {
		t.Errorf("expected successful first, got %d", ranked[0].Config.ID)
	}
	if ranked[1].Config.ID != 1 {
		t.Errorf("expected failed second, got %d", ranked[1].Config.ID)
	}
}

func TestRankDisabledLast(t *testing.T) {
	cfgs := []wgpool.Config{
		{ID: 1, Enabled: false}, // disabled but fastest probe
		{ID: 2, Enabled: true},
	}
	now := time.Now()
	results := []prober.Result{
		{ID: 1, RTT: 5 * time.Millisecond, StartAt: now},
		{ID: 2, RTT: 100 * time.Millisecond, StartAt: now},
	}
	ranked := Rank(cfgs, results)
	if ranked[0].Config.ID != 2 {
		t.Errorf("expected enabled first, got %d", ranked[0].Config.ID)
	}
}

func TestBestReturnsTopOrErr(t *testing.T) {
	now := time.Now()
	cfgs := []wgpool.Config{{ID: 1, Enabled: true}}
	ok, err := Best(cfgs, []prober.Result{{ID: 1, RTT: 30 * time.Millisecond, StartAt: now}})
	if err != nil {
		t.Fatalf("Best: %v", err)
	}
	if ok.Config.ID != 1 {
		t.Errorf("got id %d, want 1", ok.Config.ID)
	}

	// All probes failed → ErrNoCandidate.
	_, err = Best(cfgs, []prober.Result{{ID: 1, Err: errors.New("nope"), StartAt: now}})
	if !errors.Is(err, ErrNoCandidate) {
		t.Errorf("expected ErrNoCandidate, got %v", err)
	}

	// Empty configs → ErrNoCandidate.
	_, err = Best(nil, nil)
	if !errors.Is(err, ErrNoCandidate) {
		t.Errorf("empty: expected ErrNoCandidate, got %v", err)
	}

	// Only disabled configs → ErrNoCandidate.
	disabled := []wgpool.Config{{ID: 1, Enabled: false}}
	_, err = Best(disabled, []prober.Result{{ID: 1, RTT: 10 * time.Millisecond, StartAt: now}})
	if !errors.Is(err, ErrNoCandidate) {
		t.Errorf("disabled-only: expected ErrNoCandidate, got %v", err)
	}

	// Sub-microsecond RTT (e.g. localhost) is still a successful probe.
	_, err = Best(cfgs, []prober.Result{{ID: 1, RTT: 0, StartAt: now}})
	if err != nil {
		t.Errorf("zero-RTT successful probe should rank: %v", err)
	}

	// Untested config (no probe StartAt) → not considered.
	_, err = Best(cfgs, []prober.Result{{ID: 1}})
	if !errors.Is(err, ErrNoCandidate) {
		t.Errorf("untested: expected ErrNoCandidate, got %v", err)
	}
}
