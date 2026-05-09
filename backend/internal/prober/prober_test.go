package prober

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDialer records every call and lets tests script the response per
// (host, port) pair.
type fakeDialer struct {
	delays   map[string]time.Duration
	errs     map[string]error
	calls    atomic.Int64
	maxInFly atomic.Int32
	curInFly atomic.Int32
}

func (f *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.calls.Add(1)
	cur := f.curInFly.Add(1)
	if cur > f.maxInFly.Load() {
		f.maxInFly.Store(cur)
	}
	defer f.curInFly.Add(-1)

	d := f.delays[address]
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(d):
	}
	if err, ok := f.errs[address]; ok {
		return nil, err
	}
	// Return a net.Pipe end (already-connected conn) — caller closes it.
	a, _ := net.Pipe()
	return a, nil
}

func TestProbeHappyPath(t *testing.T) {
	dialer := &fakeDialer{
		delays: map[string]time.Duration{
			"10.0.0.1:443": 10 * time.Millisecond,
			"10.0.0.2:443": 50 * time.Millisecond,
			"10.0.0.3:443": 30 * time.Millisecond,
		},
	}
	candidates := []Candidate{
		{ID: 1, Host: "10.0.0.1", Port: 443},
		{ID: 2, Host: "10.0.0.2", Port: 443},
		{ID: 3, Host: "10.0.0.3", Port: 443},
	}
	results := Probe(context.Background(), candidates, Config{
		PerProbeTimeout: time.Second,
		Dialer:          dialer,
	})
	if len(results) != 3 {
		t.Fatalf("len = %d, want 3", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d] err = %v", i, r.Err)
		}
		if r.ID != candidates[i].ID {
			t.Errorf("result[%d] ID = %d, want %d (preserve input order)", i, r.ID, candidates[i].ID)
		}
	}
	if dialer.calls.Load() != 3 {
		t.Errorf("dialer.calls = %d, want 3", dialer.calls.Load())
	}
}

func TestProbeReportsErrorsPerCandidate(t *testing.T) {
	dialer := &fakeDialer{
		delays: map[string]time.Duration{},
		errs: map[string]error{
			"10.0.0.1:443": errors.New("connection refused"),
			"10.0.0.2:443": errors.New("no route to host"),
		},
	}
	results := Probe(context.Background(), []Candidate{
		{ID: 1, Host: "10.0.0.1", Port: 443},
		{ID: 2, Host: "10.0.0.2", Port: 443},
	}, Config{Dialer: dialer})
	for _, r := range results {
		if r.Err == nil {
			t.Errorf("expected err for %s:%d", r.Host, r.Port)
		}
	}
}

func TestProbeRespectsPerProbeTimeout(t *testing.T) {
	dialer := &fakeDialer{
		delays: map[string]time.Duration{"10.0.0.1:443": 5 * time.Second},
	}
	start := time.Now()
	results := Probe(context.Background(), []Candidate{
		{ID: 1, Host: "10.0.0.1", Port: 443},
	}, Config{PerProbeTimeout: 50 * time.Millisecond, Dialer: dialer})
	dur := time.Since(start)
	if dur > 500*time.Millisecond {
		t.Errorf("probe didn't respect timeout: took %v", dur)
	}
	if results[0].Err == nil {
		t.Errorf("expected err on timeout")
	}
}

func TestProbeHonorsConcurrency(t *testing.T) {
	dialer := &fakeDialer{delays: map[string]time.Duration{}}
	for i := 0; i < 20; i++ {
		dialer.delays["10.0.0."+itoa(i)+":443"] = 30 * time.Millisecond
	}
	candidates := make([]Candidate, 20)
	for i := range candidates {
		candidates[i] = Candidate{ID: int64(i + 1), Host: "10.0.0." + itoa(i), Port: 443}
	}
	Probe(context.Background(), candidates, Config{
		Concurrency: 4,
		Dialer:      dialer,
	})
	if max := dialer.maxInFly.Load(); max > 4 {
		t.Errorf("maxInFly = %d, want ≤ 4", max)
	}
}

func TestProbeRejectsInvalidCandidate(t *testing.T) {
	results := Probe(context.Background(), []Candidate{
		{ID: 1, Host: "", Port: 443},
		{ID: 2, Host: "ok.example", Port: 0},
		{ID: 3, Host: "ok.example", Port: 99999},
	}, Config{Dialer: &fakeDialer{}})
	for i, r := range results {
		if r.Err == nil {
			t.Errorf("result[%d]: expected err for invalid candidate", i)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	out := ""
	for n > 0 {
		out = string(rune('0'+(n%10))) + out
		n /= 10
	}
	return out
}
