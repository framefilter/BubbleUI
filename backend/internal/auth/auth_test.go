package auth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/framefilter/bubbleui/backend/internal/store"
	"github.com/framefilter/bubbleui/backend/internal/yubikey"
)

func newTestAuth(t *testing.T) (*Authenticator, *yubikey.Mock) {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "creds.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	mock := yubikey.NewMock()
	return New(s, mock), mock
}

func TestProvisionAndLogin(t *testing.T) {
	a, yk := newTestAuth(t)
	ctx := context.Background()

	res, err := a.ProvisionYubiKey(ctx, "")
	if err != nil {
		t.Fatalf("ProvisionYubiKey: %v", err)
	}
	if res.CredentialID == 0 {
		t.Fatal("expected nonzero CredentialID")
	}
	if res.RecoveryCode == "" {
		t.Fatal("expected nonempty RecoveryCode")
	}
	if len(res.Secret) != SecretLen {
		t.Fatalf("Secret len = %d, want %d", len(res.Secret), SecretLen)
	}

	// Simulate the user programming their physical key with the secret.
	yk.Program(yubikey.Slot2, res.Secret)
	yk.Plug()

	id, err := a.LoginYubiKey(ctx)
	if err != nil {
		t.Fatalf("LoginYubiKey: %v", err)
	}
	if id != res.CredentialID {
		t.Fatalf("login matched id %d, want %d", id, res.CredentialID)
	}
}

func TestLoginRejectsWrongKey(t *testing.T) {
	a, yk := newTestAuth(t)
	ctx := context.Background()

	res, _ := a.ProvisionYubiKey(ctx, "")

	// Programmed with wrong secret.
	wrong := make([]byte, SecretLen)
	for i := range wrong {
		wrong[i] = 0xff
	}
	yk.Program(yubikey.Slot2, wrong)
	yk.Plug()

	if _, err := a.LoginYubiKey(ctx); !errors.Is(err, ErrChallengeFail) {
		t.Fatalf("expected ErrChallengeFail, got %v", err)
	}

	// Programming with the right key now should succeed.
	yk.Program(yubikey.Slot2, res.Secret)
	if _, err := a.LoginYubiKey(ctx); err != nil {
		t.Fatalf("LoginYubiKey after correction: %v", err)
	}
}

func TestLoginRequiresKeyPresent(t *testing.T) {
	a, yk := newTestAuth(t)
	ctx := context.Background()

	res, _ := a.ProvisionYubiKey(ctx, "")
	yk.Program(yubikey.Slot2, res.Secret)
	// Don't plug in.

	if _, err := a.LoginYubiKey(ctx); !errors.Is(err, ErrChallengeFail) {
		t.Fatalf("expected ErrChallengeFail, got %v", err)
	}
}

func TestLoginRequiresProvisioning(t *testing.T) {
	a, _ := newTestAuth(t)
	if _, err := a.LoginYubiKey(context.Background()); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("expected ErrNoCredential, got %v", err)
	}
}

func TestRecoverHappyPath(t *testing.T) {
	a, yk := newTestAuth(t)
	ctx := context.Background()

	res, _ := a.ProvisionYubiKey(ctx, "")
	yk.Program(yubikey.Slot2, res.Secret)
	yk.Plug()

	// Confirm credential exists pre-recovery.
	if has, _ := a.HasAnyCredential(ctx); !has {
		t.Fatal("expected credential to exist pre-recovery")
	}

	if err := a.Recover(ctx, res.RecoveryCode); err != nil {
		t.Fatalf("Recover: %v", err)
	}

	// Credential should be wiped.
	if has, _ := a.HasAnyCredential(ctx); has {
		t.Fatal("expected no credentials post-recovery")
	}

	// Login should now fail with ErrNoCredential.
	if _, err := a.LoginYubiKey(ctx); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("expected ErrNoCredential post-recovery, got %v", err)
	}

	// Recovery code is single-use.
	if err := a.Recover(ctx, res.RecoveryCode); !errors.Is(err, ErrBadRecovery) {
		t.Fatalf("expected ErrBadRecovery on reuse, got %v", err)
	}
}

func TestRecoverRejectsWrongCode(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	if _, err := a.ProvisionYubiKey(ctx, ""); err != nil {
		t.Fatal(err)
	}

	cases := []string{"", "BOGUS-CODE", "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA"}
	for _, c := range cases {
		err := a.Recover(ctx, c)
		if err == nil {
			t.Errorf("Recover(%q): expected error, got nil", c)
		}
	}
}

func TestRecoverWithoutSetup(t *testing.T) {
	a, _ := newTestAuth(t)
	if err := a.Recover(context.Background(), "WHATEVER"); !errors.Is(err, ErrNoRecoveryCode) {
		t.Fatalf("expected ErrNoRecoveryCode, got %v", err)
	}
}

func TestRecoveryCodeNormalization(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	res, _ := a.ProvisionYubiKey(ctx, "")

	// User types it back lowercase with extra whitespace — should still work.
	munged := "  " + lowercase(res.RecoveryCode) + "  "
	if err := a.Recover(ctx, munged); err != nil {
		t.Fatalf("Recover(%q) failed: %v", munged, err)
	}
}

func lowercase(s string) string {
	out := make([]byte, len(s))
	for i, c := range []byte(s) {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}
