package auth

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	gowa "github.com/go-webauthn/webauthn/webauthn"

	"github.com/framefilter/bubbleui/backend/internal/store"
	"github.com/framefilter/bubbleui/backend/internal/webauthn"
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

// --- WebAuthn flow tests ---
//
// We test the wiring around go-webauthn — that begin returns valid
// options, that finish surfaces a clean ErrChallengeFail on garbage,
// that the login path requires registered credentials, that the engine
// is required when WebAuthn-anything is requested. The cryptographic
// happy path requires a real authenticator and lands in browser-based
// integration tests.

func newTestAuthWithWebAuthn(t *testing.T) *Authenticator {
	t.Helper()
	a, _ := newTestAuth(t)
	eng, err := webauthn.New(webauthn.Config{
		RPID:          "bubble.local",
		RPDisplayName: "BubbleUI test",
		Origins:       []string{"https://bubble.local"},
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	a.WebAuthn = eng
	return a
}

func TestWebAuthnRequiresEngine(t *testing.T) {
	a, _ := newTestAuth(t)
	ctx := context.Background()
	if _, _, err := a.BeginRegisterWebAuthn(ctx); !errors.Is(err, ErrNoWebAuthn) {
		t.Errorf("BeginRegister: expected ErrNoWebAuthn, got %v", err)
	}
	if _, err := a.FinishRegisterWebAuthn(ctx, "", "h", []byte("{}")); !errors.Is(err, ErrNoWebAuthn) {
		t.Errorf("FinishRegister: expected ErrNoWebAuthn, got %v", err)
	}
	if _, _, err := a.BeginLoginWebAuthn(ctx); !errors.Is(err, ErrNoWebAuthn) {
		t.Errorf("BeginLogin: expected ErrNoWebAuthn, got %v", err)
	}
	if _, err := a.FinishLoginWebAuthn(ctx, "h", []byte("{}")); !errors.Is(err, ErrNoWebAuthn) {
		t.Errorf("FinishLogin: expected ErrNoWebAuthn, got %v", err)
	}
}

func TestBeginRegisterWebAuthnIncludesPublicKey(t *testing.T) {
	a := newTestAuthWithWebAuthn(t)
	handle, options, err := a.BeginRegisterWebAuthn(context.Background())
	if err != nil {
		t.Fatalf("BeginRegisterWebAuthn: %v", err)
	}
	if handle == "" {
		t.Fatal("empty handle")
	}
	var parsed map[string]any
	if err := json.Unmarshal(options, &parsed); err != nil {
		t.Fatalf("options not JSON: %v", err)
	}
	if _, ok := parsed["publicKey"]; !ok {
		t.Fatalf("missing publicKey in options: %s", options)
	}
}

func TestFinishRegisterRejectsGarbage(t *testing.T) {
	a := newTestAuthWithWebAuthn(t)
	ctx := context.Background()
	handle, _, err := a.BeginRegisterWebAuthn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.FinishRegisterWebAuthn(ctx, "label", handle, []byte("not-an-attestation")); !errors.Is(err, ErrChallengeFail) {
		t.Fatalf("expected ErrChallengeFail, got %v", err)
	}
}

func TestBeginLoginRequiresRegisteredCredential(t *testing.T) {
	a := newTestAuthWithWebAuthn(t)
	if _, _, err := a.BeginLoginWebAuthn(context.Background()); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("expected ErrNoCredential, got %v", err)
	}
}

// fakeCredentialBlob produces a gowa.Credential JSON suitable for
// inserting into the store. The cryptographic fields are nonsense — good
// enough for BeginLogin (which only reads ID + Transport) but obviously
// not for FinishLogin's signature check.
func fakeCredentialBlob(t *testing.T, id []byte) []byte {
	t.Helper()
	c := gowa.Credential{
		ID:              id,
		PublicKey:       []byte{0xa5, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		AttestationType: "none",
	}
	blob, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	return blob
}

func TestBeginLoginIncludesAllowedCredentials(t *testing.T) {
	a := newTestAuthWithWebAuthn(t)
	ctx := context.Background()

	if _, err := a.Store.AddCredential(ctx, store.Credential{
		Kind:           store.KindWebAuthn,
		Label:          "fake",
		CredentialID:   []byte("demo-cred"),
		PublicMaterial: fakeCredentialBlob(t, []byte("demo-cred")),
	}); err != nil {
		t.Fatal(err)
	}

	handle, options, err := a.BeginLoginWebAuthn(ctx)
	if err != nil {
		t.Fatalf("BeginLoginWebAuthn: %v", err)
	}
	if handle == "" {
		t.Fatal("empty handle")
	}
	var parsed map[string]any
	if err := json.Unmarshal(options, &parsed); err != nil {
		t.Fatalf("options: %v", err)
	}
	pk, _ := parsed["publicKey"].(map[string]any)
	allow, _ := pk["allowCredentials"].([]any)
	if len(allow) == 0 {
		t.Fatalf("expected allowCredentials populated, got %v", pk)
	}
}

func TestFinishLoginRejectsGarbage(t *testing.T) {
	a := newTestAuthWithWebAuthn(t)
	ctx := context.Background()
	_, _ = a.Store.AddCredential(ctx, store.Credential{
		Kind:           store.KindWebAuthn,
		Label:          "fake",
		CredentialID:   []byte("demo-cred"),
		PublicMaterial: fakeCredentialBlob(t, []byte("demo-cred")),
	})
	handle, _, err := a.BeginLoginWebAuthn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.FinishLoginWebAuthn(ctx, handle, []byte("trash")); !errors.Is(err, ErrChallengeFail) {
		t.Fatalf("expected ErrChallengeFail, got %v", err)
	}
}
