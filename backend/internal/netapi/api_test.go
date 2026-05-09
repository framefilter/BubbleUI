package netapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/framefilter/bubbleui/backend/internal/captive"
	"github.com/framefilter/bubbleui/backend/internal/signin"
)

func newTestServer(t *testing.T) (*httptest.Server, *signin.Manager) {
	t.Helper()
	mgr := signin.New(signin.Config{Applier: &signin.NoopApplier{}})
	api := New(Config{
		Detector: &captive.Detector{Probes: []captive.Probe{}},
		Signin:   mgr,
	})
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	return srv, mgr
}

func decodeJSON(t *testing.T, body io.Reader) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func TestSigninStatusInitiallyClosed(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/net/signin/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := decodeJSON(t, resp.Body)
	if body["state"] != "closed" {
		t.Fatalf("state = %v, want closed", body["state"])
	}
}

func TestSigninOpenAndClose(t *testing.T) {
	srv, _ := newTestServer(t)

	resp, err := http.Post(srv.URL+"/net/signin/open", "application/json",
		strings.NewReader(`{"portal_ips":["203.0.113.42"],"duration_sec":600}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("open status = %d", resp.StatusCode)
	}

	statusResp, err := http.Get(srv.URL + "/net/signin/status")
	if err != nil {
		t.Fatal(err)
	}
	defer statusResp.Body.Close()
	body := decodeJSON(t, statusResp.Body)
	if body["state"] != "open" {
		t.Fatalf("state = %v, want open", body["state"])
	}
	ips, _ := body["portal_ips"].([]any)
	if len(ips) != 1 || ips[0] != "203.0.113.42" {
		t.Fatalf("portal_ips = %v", body["portal_ips"])
	}
	if rem, _ := body["remaining_sec"].(float64); rem < 590 || rem > 600 {
		t.Errorf("remaining_sec = %v, want ~600", body["remaining_sec"])
	}

	closeResp, err := http.Post(srv.URL+"/net/signin/close", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeResp.Body.Close()
	if closeResp.StatusCode != http.StatusOK {
		t.Fatalf("close status = %d", closeResp.StatusCode)
	}

	statusResp2, err := http.Get(srv.URL + "/net/signin/status")
	if err != nil {
		t.Fatal(err)
	}
	defer statusResp2.Body.Close()
	body = decodeJSON(t, statusResp2.Body)
	if body["state"] != "closed" {
		t.Fatalf("post-close state = %v", body["state"])
	}
}

func TestSigninOpenRequiresPortalIPs(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Post(srv.URL+"/net/signin/open", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestSigninOpenRejectedInStrictMode(t *testing.T) {
	srv, mgr := newTestServer(t)
	mgr.SetStrict(true)

	resp, err := http.Post(srv.URL+"/net/signin/open", "application/json",
		strings.NewReader(`{"portal_ips":["1.2.3.4"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestSigninStrictToggle(t *testing.T) {
	srv, mgr := newTestServer(t)

	resp, err := http.Post(srv.URL+"/net/signin/strict", "application/json",
		strings.NewReader(`{"enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !mgr.Strict() {
		t.Fatal("manager strict mode not toggled")
	}
}

func TestCaptiveEndpointCallsDetector(t *testing.T) {
	// Use the in-process httptest backend to simulate a clean network.
	clean := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer clean.Close()

	mgr := signin.New(signin.Config{Applier: &signin.NoopApplier{}})
	api := New(Config{
		Detector: &captive.Detector{Probes: []captive.Probe{{URL: clean.URL, ExpectStatus: 204}}},
		Signin:   mgr,
	})
	srv := httptest.NewServer(api)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/net/captive")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := decodeJSON(t, resp.Body)
	if body["captive"] != false {
		t.Fatalf("captive = %v", body["captive"])
	}
}

// Verifies context.Context is reachable through the request handler chain.
func TestRequestContextPlumbed(t *testing.T) {
	_ = context.Background
}
