package vpnapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/framefilter/bubbleui/backend/internal/prober"
	"github.com/framefilter/bubbleui/backend/internal/wgpool"
)

const sampleCfg = `[Interface]
PrivateKey = abc

[Peer]
PublicKey = def
Endpoint = host.example:51820
`

type testRig struct {
	srv  *httptest.Server
	pool *wgpool.Pool
	conn *StubConnector
}

func newRig(t *testing.T) *testRig {
	t.Helper()
	pool, err := wgpool.Open(context.Background(), filepath.Join(t.TempDir(), "vpn.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	conn := &StubConnector{}
	server := New(Config{Pool: pool, Connector: conn,
		Probe: prober.Config{
			PerProbeTimeout: 100 * time.Millisecond,
			Dialer:          &fakeDialer{ok: map[string]time.Duration{"host.example:51820": 12 * time.Millisecond}},
		},
	})
	srv := httptest.NewServer(server)
	t.Cleanup(srv.Close)
	return &testRig{srv: srv, pool: pool, conn: conn}
}

type fakeDialer struct {
	ok  map[string]time.Duration
	err map[string]error
}

func (f *fakeDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	if e, ok := f.err[address]; ok {
		return nil, e
	}
	if d, ok := f.ok[address]; ok {
		time.Sleep(d)
		a, _ := net.Pipe()
		return a, nil
	}
	return nil, errors.New("dialer: unknown address")
}

func decodeJSON(t *testing.T, body io.Reader) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func TestImportAndList(t *testing.T) {
	rig := newRig(t)

	body := `{"label":"ch","raw":` + jsonString(sampleCfg) + `}`
	resp, err := http.Post(rig.srv.URL+"/vpn/configs", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("import: status = %d", resp.StatusCode)
	}

	listResp, err := http.Get(rig.srv.URL + "/vpn/configs")
	if err != nil {
		t.Fatal(err)
	}
	defer listResp.Body.Close()
	got := decodeJSON(t, listResp.Body)
	configs, _ := got["configs"].([]any)
	if len(configs) != 1 {
		t.Fatalf("len(configs) = %d, want 1", len(configs))
	}
	first, _ := configs[0].(map[string]any)
	if first["endpoint"] != "host.example:51820" {
		t.Fatalf("endpoint = %v", first["endpoint"])
	}
}

func TestImportRejectsBadConfig(t *testing.T) {
	rig := newRig(t)
	resp, err := http.Post(rig.srv.URL+"/vpn/configs", "application/json",
		strings.NewReader(`{"label":"x","raw":"not a wireguard config"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestProbeRanksByRTT(t *testing.T) {
	rig := newRig(t)
	_, _ = rig.pool.Add(context.Background(), "ch", sampleCfg)

	resp, err := http.Post(rig.srv.URL+"/vpn/probe", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := decodeJSON(t, resp.Body)
	if body["probed"].(float64) != 1 {
		t.Fatalf("probed = %v", body["probed"])
	}
	ranked, _ := body["ranked"].([]any)
	if len(ranked) != 1 {
		t.Fatalf("ranked len = %d", len(ranked))
	}
	row, _ := ranked[0].(map[string]any)
	if _, ok := row["probe_rtt_ms"]; !ok {
		t.Fatalf("expected probe_rtt_ms, got %v", row)
	}
}

func TestConnectFastest(t *testing.T) {
	rig := newRig(t)
	_, _ = rig.pool.Add(context.Background(), "ch", sampleCfg)

	resp, err := http.Post(rig.srv.URL+"/vpn/connect", "application/json", strings.NewReader(`{"strategy":"fastest"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body := decodeJSON(t, resp.Body)
	if body["status"] != "connected" {
		t.Fatalf("body = %v", body)
	}
	if rig.conn.Active() == 0 {
		t.Fatal("expected connector to record an active id")
	}
}

func TestConnectRejectsWhenNoCandidate(t *testing.T) {
	rig := newRig(t)
	resp, err := http.Post(rig.srv.URL+"/vpn/connect", "application/json", strings.NewReader(`{"strategy":"fastest"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestSetEnabledTogglesProbeInclusion(t *testing.T) {
	rig := newRig(t)
	id, _ := rig.pool.Add(context.Background(), "ch", sampleCfg)

	body := `{"enabled":false}`
	resp, err := http.Post(rig.srv.URL+"/vpn/configs/"+jsonInt(id)+"/enabled", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	probeResp, err := http.Post(rig.srv.URL+"/vpn/probe", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer probeResp.Body.Close()
	got := decodeJSON(t, probeResp.Body)
	if got["probed"].(float64) != 0 {
		t.Fatalf("probed = %v, want 0 (disabled config skipped)", got["probed"])
	}
	if got["skipped"].(float64) != 1 {
		t.Fatalf("skipped = %v, want 1", got["skipped"])
	}
}

func TestDeleteRemoves(t *testing.T) {
	rig := newRig(t)
	id, _ := rig.pool.Add(context.Background(), "ch", sampleCfg)

	req, err := http.NewRequest("DELETE", rig.srv.URL+"/vpn/configs/"+jsonInt(id), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	listResp, err := http.Get(rig.srv.URL + "/vpn/configs")
	if err != nil {
		t.Fatal(err)
	}
	defer listResp.Body.Close()
	got := decodeJSON(t, listResp.Body)
	if configs, _ := got["configs"].([]any); len(configs) != 0 {
		t.Fatalf("expected empty pool, got %v", configs)
	}
}

func TestDisconnectClearsActive(t *testing.T) {
	rig := newRig(t)
	rig.conn.Connect(context.Background(), wgpool.Config{ID: 7})

	resp, err := http.Post(rig.srv.URL+"/vpn/disconnect", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if rig.conn.Active() != 0 {
		t.Fatalf("expected active=0, got %d", rig.conn.Active())
	}
}

// --- json helpers (avoiding stdlib for tiny one-liners in test bodies) ---

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
func jsonInt(n int64) string {
	if n == 0 {
		return "0"
	}
	out := ""
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		out = string(rune('0'+(n%10))) + out
		n /= 10
	}
	if neg {
		out = "-" + out
	}
	return out
}
