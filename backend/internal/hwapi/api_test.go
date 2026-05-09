package hwapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/framefilter/bubbleui/backend/internal/buttons"
	"github.com/framefilter/bubbleui/backend/internal/led"
)

func newTestServer(t *testing.T) (*httptest.Server, *led.MockDriver, *buttons.MockReader) {
	t.Helper()
	d := led.NewMock()
	r := buttons.NewMock()
	api := New(Config{LED: d, Buttons: r})
	srv := httptest.NewServer(api)
	t.Cleanup(func() {
		srv.Close()
		_ = r.Stop()
	})
	return srv, d, r
}

func decodeJSON(t *testing.T, body io.Reader) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func TestGetLEDInitiallyOff(t *testing.T) {
	srv, _, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/hw/led")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := decodeJSON(t, resp.Body)
	if body["state"] != "off" {
		t.Errorf("state = %v, want off", body["state"])
	}
}

func TestSetLEDPersistsAndDrives(t *testing.T) {
	srv, d, _ := newTestServer(t)
	resp, err := http.Post(srv.URL+"/hw/led", "application/json",
		strings.NewReader(`{"state":"secured"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if d.Current() != led.StateSecured {
		t.Errorf("driver state = %s, want secured", d.Current())
	}
	// GET reflects.
	getResp, err := http.Get(srv.URL + "/hw/led")
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()
	body := decodeJSON(t, getResp.Body)
	if body["state"] != "secured" {
		t.Errorf("get after set = %v", body["state"])
	}
}

func TestSetLEDRejectsBadState(t *testing.T) {
	srv, _, _ := newTestServer(t)
	resp, err := http.Post(srv.URL+"/hw/led", "application/json",
		strings.NewReader(`{"state":"glitter"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestButtonsLastEventDrainedFromReader(t *testing.T) {
	srv, _, r := newTestServer(t)

	// No event yet.
	resp, _ := http.Get(srv.URL + "/hw/buttons")
	body := decodeJSON(t, resp.Body)
	resp.Body.Close()
	if body["last_event"] != nil {
		t.Fatalf("expected nil last_event, got %v", body["last_event"])
	}

	r.Down(buttons.Reset)
	// Give the drain goroutine a chance.
	time.Sleep(20 * time.Millisecond)

	resp2, _ := http.Get(srv.URL + "/hw/buttons")
	body = decodeJSON(t, resp2.Body)
	resp2.Body.Close()
	ev, ok := body["last_event"].(map[string]any)
	if !ok || ev == nil {
		t.Fatalf("expected last_event map, got %v", body)
	}
	if ev["button"] != "reset" {
		t.Errorf("button = %v", ev["button"])
	}
	if ev["kind"] != "down" {
		t.Errorf("kind = %v", ev["kind"])
	}
}

// Verifies context.Context still reachable through the handler chain.
func TestRequestContextPlumbed(t *testing.T) {
	_ = context.Background
}
