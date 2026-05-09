package captive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDetectCleanWhenAllProbesMatch(t *testing.T) {
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer probe.Close()

	d := &Detector{
		Probes: []Probe{{URL: probe.URL, ExpectStatus: 204}},
	}
	v := d.Detect(context.Background())
	if v.Captive {
		t.Errorf("expected Captive=false, got %+v", v)
	}
}

func TestDetectFlagsRedirect(t *testing.T) {
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>Sign in to hotel WiFi</body></html>`))
	}))
	defer portal.Close()

	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{URL: nil}, portal.URL, http.StatusFound)
	}))
	defer probe.Close()

	d := &Detector{
		Probes: []Probe{{URL: probe.URL + "/probe", ExpectStatus: 204}},
	}
	v := d.Detect(context.Background())
	if !v.Captive {
		t.Errorf("expected Captive=true, got %+v", v)
	}
	if !strings.HasPrefix(v.EvidenceURL, probe.URL) {
		t.Errorf("EvidenceURL = %q", v.EvidenceURL)
	}
	if len(v.PortalIPs) == 0 {
		t.Errorf("expected at least one PortalIP, got %v", v.PortalIPs)
	}
}

func TestDetectAllNetworkFailedNotCaptive(t *testing.T) {
	d := &Detector{
		Probes: []Probe{
			{URL: "http://127.0.0.1:1/probe", ExpectStatus: 200},
		},
		PerProbeTimeout: 200 * time.Millisecond,
	}
	v := d.Detect(context.Background())
	if v.Captive {
		t.Errorf("expected Captive=false on network failure, got %+v", v)
	}
	if v.EvidenceURL != "" {
		t.Errorf("expected no EvidenceURL on full network failure, got %q", v.EvidenceURL)
	}
}

func TestDetectMixedCleanFirstWins(t *testing.T) {
	clean := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer clean.Close()

	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>portal</html>`))
	}))
	defer portal.Close()

	d := &Detector{
		Probes: []Probe{
			{URL: portal.URL + "/x", ExpectStatus: 204},
			{URL: clean.URL + "/y", ExpectStatus: 204},
		},
	}
	v := d.Detect(context.Background())
	if v.Captive {
		t.Errorf("expected NOT captive when at least one probe is clean, got %+v", v)
	}
}

func TestDetectBodyMismatchIsCaptive(t *testing.T) {
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hotel sign-in required"))
	}))
	defer probe.Close()

	d := &Detector{
		Probes: []Probe{{URL: probe.URL, ExpectStatus: 200, ExpectBody: "success"}},
	}
	v := d.Detect(context.Background())
	if !v.Captive {
		t.Errorf("expected Captive=true on body mismatch, got %+v", v)
	}
}
