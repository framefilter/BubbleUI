package webauthn

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Config{
		RPID:          "bubble.local",
		RPDisplayName: "BubbleUI test",
		Origins:       []string{"https://bubble.local"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestNewRequiresRPID(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for empty RPID")
	}
}

func TestBeginRegisterReturnsOptions(t *testing.T) {
	e := newTestEngine(t)
	user := &User{
		ID:   bytes.Repeat([]byte{0xab}, 16),
		Name: "bubbleui",
	}
	handle, options, err := e.BeginRegister(user)
	if err != nil {
		t.Fatalf("BeginRegister: %v", err)
	}
	if handle == "" {
		t.Fatal("empty handle")
	}
	var parsed map[string]any
	if err := json.Unmarshal(options, &parsed); err != nil {
		t.Fatalf("options not JSON: %v", err)
	}
	pk, ok := parsed["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("expected publicKey field, got %v", parsed)
	}
	for _, key := range []string{"challenge", "rp", "user", "pubKeyCredParams"} {
		if _, ok := pk[key]; !ok {
			t.Errorf("publicKey missing %s", key)
		}
	}
	if e.PendingCount() != 1 {
		t.Fatalf("PendingCount = %d, want 1", e.PendingCount())
	}
}

func TestBeginLoginRequiresCredentials(t *testing.T) {
	e := newTestEngine(t)
	user := &User{ID: bytes.Repeat([]byte{0xab}, 16), Name: "bubbleui"}
	if _, _, err := e.BeginLogin(user); err == nil {
		t.Fatal("BeginLogin should fail with no credentials")
	}
}

func TestFinishWithUnknownHandle(t *testing.T) {
	e := newTestEngine(t)
	user := &User{ID: bytes.Repeat([]byte{0x12}, 16), Name: "bubbleui"}
	if _, err := e.FinishRegister(user, "totally-bogus", []byte("{}")); !errors.Is(err, ErrUnknownHandle) {
		t.Fatalf("expected ErrUnknownHandle, got %v", err)
	}
	if _, err := e.FinishLogin(user, "totally-bogus", []byte("{}")); !errors.Is(err, ErrUnknownHandle) {
		t.Fatalf("expected ErrUnknownHandle, got %v", err)
	}
}

func TestFinishWithMalformedBody(t *testing.T) {
	e := newTestEngine(t)
	user := &User{ID: bytes.Repeat([]byte{0xab}, 16), Name: "bubbleui"}
	handle, _, err := e.BeginRegister(user)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.FinishRegister(user, handle, []byte("not-a-real-attestation"))
	if err == nil {
		t.Fatal("expected error for malformed body")
	}
	if !errors.Is(err, ErrParse) && !errors.Is(err, ErrValidate) {
		t.Fatalf("expected ErrParse or ErrValidate, got %v", err)
	}
}

func TestPendingHandleConsumedOnce(t *testing.T) {
	e := newTestEngine(t)
	user := &User{ID: bytes.Repeat([]byte{0xab}, 16), Name: "bubbleui"}
	handle, _, _ := e.BeginRegister(user)

	// First finish consumes the handle (even if it fails).
	_, _ = e.FinishRegister(user, handle, []byte("garbage"))
	// Second finish must report unknown handle, not retry.
	if _, err := e.FinishRegister(user, handle, []byte("garbage")); !errors.Is(err, ErrUnknownHandle) {
		t.Fatalf("second finish should report ErrUnknownHandle, got %v", err)
	}
}

func TestPendingExpiry(t *testing.T) {
	e, err := New(Config{
		RPID:       "bubble.local",
		Origins:    []string{"https://bubble.local"},
		PendingTTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	now := t0
	e.SetClock(func() time.Time { return now })

	user := &User{ID: bytes.Repeat([]byte{0xab}, 16), Name: "bubbleui"}
	handle, _, _ := e.BeginRegister(user)

	now = t0.Add(2 * time.Hour) // past TTL
	if _, err := e.FinishRegister(user, handle, []byte("{}")); !errors.Is(err, ErrUnknownHandle) {
		t.Fatalf("expired handle: expected ErrUnknownHandle, got %v", err)
	}
}

func TestSweepRemovesExpired(t *testing.T) {
	e, _ := New(Config{
		RPID:       "bubble.local",
		Origins:    []string{"https://bubble.local"},
		PendingTTL: 1 * time.Hour,
	})
	t0 := time.Now()
	now := t0
	e.SetClock(func() time.Time { return now })

	user := &User{ID: bytes.Repeat([]byte{0xab}, 16), Name: "bubbleui"}
	_, _, _ = e.BeginRegister(user) // first ceremony, expires at t0+1h

	now = t0.Add(30 * time.Minute)
	_, _, _ = e.BeginRegister(user) // second ceremony, expires at t0+30m+1h

	if e.PendingCount() != 2 {
		t.Fatalf("PendingCount = %d, want 2", e.PendingCount())
	}

	now = t0.Add(75 * time.Minute) // first expired, second not
	e.Sweep()
	if e.PendingCount() != 1 {
		t.Fatalf("PendingCount after sweep = %d, want 1", e.PendingCount())
	}
}
