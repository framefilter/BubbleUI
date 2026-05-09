package session

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/framefilter/bubbleui/backend/internal/store"
)

func newManager(t *testing.T) *Manager {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "creds.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	m, err := NewManager(context.Background(), s.DB())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestCreateAndValidate(t *testing.T) {
	m := newManager(t)
	ctx := context.Background()

	tok, sess, err := m.Create(ctx, 7)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	if sess.CredentialID != 7 {
		t.Fatalf("CredentialID = %d, want 7", sess.CredentialID)
	}

	got, err := m.Validate(ctx, tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.ID != sess.ID {
		t.Fatalf("validate returned id %d, want %d", got.ID, sess.ID)
	}
}

func TestValidateRejectsUnknownToken(t *testing.T) {
	m := newManager(t)
	if _, err := m.Validate(context.Background(), "totally-bogus"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if _, err := m.Validate(context.Background(), ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken on empty, got %v", err)
	}
}

func TestExpiry(t *testing.T) {
	m := newManager(t)
	m.SetLifetime(1 * time.Hour)

	now := time.Now()
	m.SetClock(func() time.Time { return now })

	tok, _, err := m.Create(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}

	// Jump past expiration.
	now = now.Add(2 * time.Hour)
	if _, err := m.Validate(context.Background(), tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}

	// After expiry, the row is cleaned up; subsequent validates report
	// ErrInvalidToken (the session is gone, not just expired).
	if _, err := m.Validate(context.Background(), tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken after cleanup, got %v", err)
	}
}

func TestSlidingExpiration(t *testing.T) {
	m := newManager(t)
	m.SetLifetime(1 * time.Hour)

	t0 := time.Now()
	now := t0
	m.SetClock(func() time.Time { return now })

	tok, sess, _ := m.Create(context.Background(), 1)
	originalExpires := sess.ExpiresAt

	// Validate 30 min later — expiry should slide forward.
	now = t0.Add(30 * time.Minute)
	got, err := m.Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !got.ExpiresAt.After(originalExpires) {
		t.Fatalf("expected sliding expiry, got %v vs original %v", got.ExpiresAt, originalExpires)
	}

	// Now jump 90 min from the original create — without sliding this would be expired.
	now = t0.Add(90 * time.Minute)
	if _, err := m.Validate(context.Background(), tok); err != nil {
		t.Fatalf("Validate after slide should still be valid, got %v", err)
	}
}

func TestRevoke(t *testing.T) {
	m := newManager(t)
	ctx := context.Background()

	tok, _, _ := m.Create(ctx, 1)
	if err := m.Revoke(ctx, tok); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := m.Validate(ctx, tok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken after revoke, got %v", err)
	}

	// Revoking unknown token is a no-op, not an error.
	if err := m.Revoke(ctx, "unknown-token"); err != nil {
		t.Fatalf("Revoke of unknown should not error, got %v", err)
	}
}

func TestRevokeAll(t *testing.T) {
	m := newManager(t)
	ctx := context.Background()

	t1, _, _ := m.Create(ctx, 1)
	t2, _, _ := m.Create(ctx, 2)

	if err := m.RevokeAll(ctx); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	for _, tok := range []string{t1, t2} {
		if _, err := m.Validate(ctx, tok); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken for %s, got %v", tok[:10], err)
		}
	}
}

func TestPurgeExpired(t *testing.T) {
	m := newManager(t)
	m.SetLifetime(1 * time.Hour)
	t0 := time.Now()
	now := t0
	m.SetClock(func() time.Time { return now })

	t1, _, _ := m.Create(context.Background(), 1)
	t2, _, _ := m.Create(context.Background(), 2)

	// Slide t2's expiry forward so it survives the purge.
	now = t0.Add(30 * time.Minute)
	if _, err := m.Validate(context.Background(), t2); err != nil {
		t.Fatal(err)
	}

	// At t0+75min: past t1's expiry (t0+60min), before t2's slid expiry (t0+90min).
	now = t0.Add(75 * time.Minute)
	if err := m.PurgeExpired(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := m.Validate(context.Background(), t1); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("t1 should have been purged, got %v", err)
	}
	if _, err := m.Validate(context.Background(), t2); err != nil {
		t.Fatalf("t2 should still be valid, got %v", err)
	}
}

func TestTokensAreUnique(t *testing.T) {
	m := newManager(t)
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		tok, _, err := m.Create(context.Background(), 1)
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] {
			t.Fatalf("collision at iter %d", i)
		}
		seen[tok] = true
	}
}
