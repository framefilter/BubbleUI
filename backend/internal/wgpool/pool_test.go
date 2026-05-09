package wgpool

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newPool(t *testing.T) *Pool {
	t.Helper()
	p, err := Open(context.Background(), filepath.Join(t.TempDir(), "vpn.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

const sampleConfig = `[Interface]
PrivateKey = aGVsbG8td29ybGQtcHJpdmF0ZS1rZXk=
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = c29tZS1wdWJsaWMta2V5LWdvZXMtaGVyZQ==
Endpoint = vpn-ch-zurich-12.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`

func TestParseEndpoint(t *testing.T) {
	host, port, err := ParseEndpoint(sampleConfig)
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if host != "vpn-ch-zurich-12.example.com" {
		t.Errorf("host = %q", host)
	}
	if port != 51820 {
		t.Errorf("port = %d", port)
	}
}

func TestParseEndpointIPv6(t *testing.T) {
	cfg := "[Peer]\nEndpoint = [2001:db8::1]:51820\n"
	host, port, err := ParseEndpoint(cfg)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if host != "2001:db8::1" {
		t.Errorf("host = %q", host)
	}
	if port != 51820 {
		t.Errorf("port = %d", port)
	}
}

func TestParseEndpointRejectsMissingPort(t *testing.T) {
	if _, _, err := ParseEndpoint("[Peer]\nEndpoint = vpn.example.com\n"); err == nil {
		t.Fatal("expected error on missing port")
	}
}

func TestParseEndpointRejectsConfigWithNoPeer(t *testing.T) {
	if _, _, err := ParseEndpoint("[Interface]\nPrivateKey = abc\n"); err == nil {
		t.Fatal("expected error on missing Peer section")
	}
}

func TestParseEndpointIgnoresInterfaceLines(t *testing.T) {
	// An [Interface] section with an Endpoint-named field would be
	// nonsense, but we still shouldn't pick it up as the Peer's endpoint.
	cfg := `[Interface]
Endpoint = decoy.example:1234
[Peer]
Endpoint = real.example:51820
`
	host, _, err := ParseEndpoint(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if host != "real.example" {
		t.Fatalf("picked wrong endpoint: %q", host)
	}
}

func TestAddListGetDelete(t *testing.T) {
	p := newPool(t)
	ctx := context.Background()

	id, err := p.Add(ctx, "ch-zurich", sampleConfig)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if id == 0 {
		t.Fatal("expected nonzero id")
	}

	list, err := p.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("List len = %d", len(list))
	}
	c := list[0]
	if c.Label != "ch-zurich" {
		t.Errorf("label = %q", c.Label)
	}
	if c.EndpointHost != "vpn-ch-zurich-12.example.com" || c.EndpointPort != 51820 {
		t.Errorf("endpoint = %s:%d", c.EndpointHost, c.EndpointPort)
	}
	if !c.Enabled {
		t.Error("new config should default to enabled=true")
	}

	got, err := p.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != id {
		t.Fatal("Get returned wrong id")
	}

	if err := p.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get(ctx, id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows after delete, got %v", err)
	}
}

func TestAddDefaultsLabelToEndpoint(t *testing.T) {
	p := newPool(t)
	id, err := p.Add(context.Background(), "", sampleConfig)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := p.Get(context.Background(), id)
	if c.Label != "vpn-ch-zurich-12.example.com:51820" {
		t.Errorf("default label = %q", c.Label)
	}
}

func TestAddRejectsUnparseable(t *testing.T) {
	p := newPool(t)
	if _, err := p.Add(context.Background(), "x", "garbage with no peer"); err == nil {
		t.Fatal("expected error on unparseable config")
	}
}

func TestSetEnabled(t *testing.T) {
	p := newPool(t)
	id, _ := p.Add(context.Background(), "x", sampleConfig)

	if err := p.SetEnabled(context.Background(), id, false); err != nil {
		t.Fatal(err)
	}
	c, _ := p.Get(context.Background(), id)
	if c.Enabled {
		t.Error("expected disabled")
	}

	if err := p.SetEnabled(context.Background(), 99999, true); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("SetEnabled on missing id: expected sql.ErrNoRows, got %v", err)
	}
}

func TestRecordProbe(t *testing.T) {
	p := newPool(t)
	id, _ := p.Add(context.Background(), "x", sampleConfig)

	// Successful probe.
	if err := p.RecordProbe(context.Background(), id, 23*time.Millisecond, ""); err != nil {
		t.Fatal(err)
	}
	c, _ := p.Get(context.Background(), id)
	if c.LastProbeRTT != 23*time.Millisecond {
		t.Errorf("rtt = %v", c.LastProbeRTT)
	}
	if c.LastProbeErr != "" {
		t.Errorf("expected empty err, got %q", c.LastProbeErr)
	}

	// Failed probe.
	if err := p.RecordProbe(context.Background(), id, 0, "connect: timeout"); err != nil {
		t.Fatal(err)
	}
	c, _ = p.Get(context.Background(), id)
	if c.LastProbeRTT != 0 {
		t.Errorf("expected zero rtt on failed probe, got %v", c.LastProbeRTT)
	}
	if c.LastProbeErr != "connect: timeout" {
		t.Errorf("err = %q", c.LastProbeErr)
	}
}

func TestMarkHandshake(t *testing.T) {
	p := newPool(t)
	id, _ := p.Add(context.Background(), "x", sampleConfig)
	if err := p.MarkHandshake(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	c, _ := p.Get(context.Background(), id)
	if c.LastHandshake.IsZero() {
		t.Fatal("expected non-zero LastHandshake")
	}
}
