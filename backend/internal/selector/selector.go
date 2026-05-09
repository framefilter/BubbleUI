// Package selector picks the best candidate from a set of probe results.
// "Best" for v1.0 is "lowest RTT among enabled, successful probes."
// Country/feature filters land with the M6+ provider plugins
// (DESIGN.md §11.5); for now the selector is intentionally simple.
package selector

import (
	"errors"
	"sort"

	"github.com/framefilter/bubbleui/backend/internal/prober"
	"github.com/framefilter/bubbleui/backend/internal/wgpool"
)

// ErrNoCandidate is returned when no enabled config produced a
// successful probe.
var ErrNoCandidate = errors.New("selector: no usable candidate")

// Ranked pairs a pool config with its probe outcome, sorted by
// preference (best first). Failed probes appear last with Err set.
type Ranked struct {
	Config wgpool.Config
	Result prober.Result
}

// Rank merges the pool list with the matching probe results and returns
// them ordered by preference: enabled+successful first by ascending RTT,
// then enabled+failed, then disabled. Stable secondary ordering is by
// config ID for determinism.
func Rank(configs []wgpool.Config, results []prober.Result) []Ranked {
	resByID := make(map[int64]prober.Result, len(results))
	for _, r := range results {
		resByID[r.ID] = r
	}
	out := make([]Ranked, 0, len(configs))
	for _, c := range configs {
		out = append(out, Ranked{Config: c, Result: resByID[c.ID]})
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := out[i], out[j]
		// Disabled rows last.
		if ai.Config.Enabled != aj.Config.Enabled {
			return ai.Config.Enabled
		}
		// Among enabled: successful probes first. Success is purely
		// "Err == nil" — RTT can legitimately be sub-microsecond on a
		// localhost path and we must not count that as failure.
		aiOK := ai.Result.Err == nil
		ajOK := aj.Result.Err == nil
		if aiOK != ajOK {
			return aiOK
		}
		// Both successful: lowest RTT wins.
		if aiOK && ajOK {
			return ai.Result.RTT < aj.Result.RTT
		}
		// Otherwise tie-break by ID for determinism.
		return ai.Config.ID < aj.Config.ID
	})
	return out
}

// Best returns the top-ranked candidate or ErrNoCandidate if none of the
// configs produced a successful probe.
func Best(configs []wgpool.Config, results []prober.Result) (Ranked, error) {
	ranked := Rank(configs, results)
	if len(ranked) == 0 {
		return Ranked{}, ErrNoCandidate
	}
	// Find the first enabled, successful entry. The Rank ordering puts
	// these first, but we double-check rather than assuming.
	for _, r := range ranked {
		if r.Config.Enabled && r.Result.Err == nil {
			// We also need a probe result associated with this row — an
			// untested config (zero StartAt) shouldn't count as "best."
			if !r.Result.StartAt.IsZero() {
				return r, nil
			}
		}
	}
	return Ranked{}, ErrNoCandidate
}
