// Package prober runs parallel TCP-connect probes against a list of
// candidate hostports. Used by bubble-vpnd to rank a pool of WireGuard
// configs by RTT before connecting (DESIGN.md §11.5 / M4).
//
// We deliberately use TCP-connect rather than ICMP (no privileges
// required, runs unchanged on the router) and TCP rather than a partial
// WireGuard handshake (~3× the code, marginal accuracy gain). RTT is
// measured as connect-time; that's dominated by RTT for any practical
// path and a fine proxy for "which server is closest right now."
package prober

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

// Candidate is one host:port to probe, plus an opaque ID the caller
// uses to correlate results back to their pool entry.
type Candidate struct {
	ID   int64
	Host string
	Port int
}

// Result mirrors a Candidate's outcome. Err is non-nil iff the probe
// did not complete within the configured timeout. RTT is the wall-clock
// time the connect took, measured by the prober (includes DNS).
type Result struct {
	ID      int64
	Host    string
	Port    int
	RTT     time.Duration
	Err     error
	StartAt time.Time
}

// Config controls probe behavior.
type Config struct {
	// PerProbeTimeout is the deadline for each individual connect.
	// Defaults to 1.5 s if zero.
	PerProbeTimeout time.Duration
	// Concurrency caps the number of in-flight probes. Zero = unlimited.
	// In practice 16 is plenty for a typical pool of <50 endpoints.
	Concurrency int
	// Dialer is the net.Dialer used. Tests substitute a hooked Dialer to
	// avoid real network access. Nil = a default dialer using
	// PerProbeTimeout.
	Dialer Dialer
}

// Dialer abstracts net.Dialer for testability.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Probe runs all candidates concurrently (up to cfg.Concurrency) and
// returns a slice of Results in the same order as the input.
func Probe(ctx context.Context, candidates []Candidate, cfg Config) []Result {
	if cfg.PerProbeTimeout == 0 {
		cfg.PerProbeTimeout = 1500 * time.Millisecond
	}
	if cfg.Dialer == nil {
		cfg.Dialer = &net.Dialer{Timeout: cfg.PerProbeTimeout}
	}

	results := make([]Result, len(candidates))

	var wg sync.WaitGroup
	sem := make(chan struct{}, max1(cfg.Concurrency))
	if cfg.Concurrency == 0 {
		// Effectively unbounded: no semaphore acquisitions.
		sem = nil
	}

	for i, c := range candidates {
		wg.Add(1)
		go func(idx int, cand Candidate) {
			defer wg.Done()
			if sem != nil {
				sem <- struct{}{}
				defer func() { <-sem }()
			}
			results[idx] = probeOne(ctx, cand, cfg)
		}(i, c)
	}

	wg.Wait()
	return results
}

func probeOne(ctx context.Context, c Candidate, cfg Config) Result {
	r := Result{ID: c.ID, Host: c.Host, Port: c.Port, StartAt: time.Now()}
	if c.Host == "" || c.Port <= 0 || c.Port > 65535 {
		r.Err = errors.New("prober: invalid candidate")
		return r
	}

	probeCtx, cancel := context.WithTimeout(ctx, cfg.PerProbeTimeout)
	defer cancel()

	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	start := time.Now()
	conn, err := cfg.Dialer.DialContext(probeCtx, "tcp", addr)
	r.RTT = time.Since(start)
	if err != nil {
		r.Err = err
		return r
	}
	_ = conn.Close()
	return r
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
