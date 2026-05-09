// Package captive implements the captive-portal detection probe from
// DESIGN.md §6.5 step 1. We hit a hardcoded list of connectivity-check
// URLs; an unmodified response means we're online, anything else means
// a portal is intercepting traffic.
//
// The list of probe targets is intentionally diverse so that a single
// vendor changing endpoints (Mozilla, Google, etc.) doesn't break us.
package captive

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Probe describes a single connectivity-check URL plus the body content
// we expect to see back when there's no captive portal.
type Probe struct {
	URL          string
	ExpectStatus int    // typically 200 or 204
	ExpectBody   string // optional; substring match
}

// DefaultProbes is the hardcoded list shipped on the router. Picked to
// span vendors so a single endpoint change doesn't blind us; we treat
// any one matching response as "no portal."
var DefaultProbes = []Probe{
	{URL: "http://detectportal.firefox.com/success.txt", ExpectStatus: 200, ExpectBody: "success"},
	{URL: "http://connectivitycheck.gstatic.com/generate_204", ExpectStatus: 204},
	{URL: "http://www.gstatic.com/generate_204", ExpectStatus: 204},
}

// Verdict is the result of a single Detect run.
type Verdict struct {
	// Captive is true if at least one probe came back with anything other
	// than its expected response (or the probe got redirected to an
	// HTML page).
	Captive bool
	// PortalIPs are the IP addresses observed during redirected probes.
	// These feed into §6.5's "open a firewall hole to these IPs only"
	// rule. Deduplicated.
	PortalIPs []string
	// EvidenceURL is the first probe URL that fired the portal verdict,
	// for surfacing in the UI.
	EvidenceURL string
	// Probed records every probe we attempted with its outcome. Useful
	// for the "Report Issue" log bundle (§11.4).
	Probed []ProbeOutcome
}

// ProbeOutcome is the result of a single probe within a Detect run.
type ProbeOutcome struct {
	URL        string
	StatusCode int
	BodyMatch  bool
	Redirected bool
	FinalURL   string
	Err        string
	IPs        []string // IPs the probe hit during redirects
}

// Detector runs Detect cycles. Configurable timeout per probe;
// concurrency is fixed at "all probes in parallel" since the list is small.
type Detector struct {
	// Probes overrides DefaultProbes. Empty = use defaults.
	Probes []Probe
	// PerProbeTimeout caps each probe; defaults to 3 s.
	PerProbeTimeout time.Duration
	// HTTPClient overrides the underlying client (mainly for tests).
	HTTPClient *http.Client
}

// Detect runs every configured probe in parallel and synthesizes a Verdict.
//
// Detection rule:
//   - if any probe matches its expected status+body: NOT captive (return
//     immediately with the first such match).
//   - else: captive, with the union of redirect IPs as PortalIPs.
//
// If every probe network-fails (no DNS, etc.), Captive=false and
// EvidenceURL is empty — the caller should treat that as "no internet"
// rather than "captive portal."
func (d *Detector) Detect(ctx context.Context) Verdict {
	probes := d.Probes
	if len(probes) == 0 {
		probes = DefaultProbes
	}
	timeout := d.PerProbeTimeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	type probeResult struct {
		idx     int
		outcome ProbeOutcome
		clean   bool // true iff this probe's response says "no portal"
	}

	resultsCh := make(chan probeResult, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func(i int, p Probe) {
			defer wg.Done()
			out := probe(ctx, p, timeout, d.HTTPClient)
			resultsCh <- probeResult{idx: i, outcome: out, clean: probeClean(p, &out)}
		}(i, p)
	}
	wg.Wait()
	close(resultsCh)

	v := Verdict{Probed: make([]ProbeOutcome, len(probes))}
	ipSet := make(map[string]struct{})
	cleanFound := false
	for r := range resultsCh {
		v.Probed[r.idx] = r.outcome
		if r.clean {
			cleanFound = true
			continue
		}
		// Anything non-clean (and not a network error) is captive evidence.
		if r.outcome.Err == "" {
			if v.EvidenceURL == "" {
				v.EvidenceURL = probes[r.idx].URL
			}
			for _, ip := range r.outcome.IPs {
				ipSet[ip] = struct{}{}
			}
		}
	}
	if cleanFound {
		return v
	}
	if v.EvidenceURL != "" {
		v.Captive = true
		v.PortalIPs = make([]string, 0, len(ipSet))
		for ip := range ipSet {
			v.PortalIPs = append(v.PortalIPs, ip)
		}
	}
	return v
}

// probe runs a single GET. It records the connection IPs by hooking
// the dialer; redirects up to 3 hops are followed.
func probe(ctx context.Context, p Probe, timeout time.Duration, baseClient *http.Client) ProbeOutcome {
	out := ProbeOutcome{URL: p.URL}

	var ips []string
	var ipMu sync.Mutex
	dial := (&net.Dialer{Timeout: timeout}).DialContext
	hookedDialer := func(c context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(c, network, addr)
		if err == nil {
			if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
				ipMu.Lock()
				ips = append(ips, host)
				ipMu.Unlock()
			}
		}
		return conn, err
	}

	client := baseClient
	if client == nil {
		client = &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{DialContext: hookedDialer, DisableKeepAlives: true},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", p.URL, nil)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	resp, err := client.Do(req)
	if err != nil {
		out.Err = err.Error()
		out.IPs = ips
		return out
	}
	defer resp.Body.Close()
	out.StatusCode = resp.StatusCode
	out.FinalURL = resp.Request.URL.String()
	out.Redirected = out.FinalURL != p.URL
	out.IPs = ips

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if p.ExpectBody != "" {
		out.BodyMatch = strings.Contains(string(body), p.ExpectBody)
	} else {
		out.BodyMatch = true // body content not relevant for this probe
	}
	return out
}

// probeClean reports whether out matches p's expectations (i.e. NOT
// captive).
func probeClean(p Probe, out *ProbeOutcome) bool {
	if out.Err != "" {
		return false
	}
	if p.ExpectStatus != 0 && out.StatusCode != p.ExpectStatus {
		return false
	}
	if p.ExpectBody != "" && !out.BodyMatch {
		return false
	}
	if out.Redirected {
		return false
	}
	return true
}

// String returns a one-line summary suitable for logs.
func (v Verdict) String() string {
	if v.Captive {
		return fmt.Sprintf("captive=true ips=%v evidence=%s", v.PortalIPs, v.EvidenceURL)
	}
	if v.EvidenceURL == "" && allErr(v.Probed) {
		return "no internet (every probe network-failed)"
	}
	return "captive=false"
}

func allErr(out []ProbeOutcome) bool {
	for _, o := range out {
		if o.Err == "" {
			return false
		}
	}
	return len(out) > 0
}
