package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

// testKindOther is a dummy CredentialKind for store tests that need to
// verify multi-kind filtering behavior. The schema accepts arbitrary
// TEXT kinds — we don't ship anything but KindWebAuthn today, but the
// store-layer filter contract should still be testable.
const testKindOther CredentialKind = "test_other"

func newStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "creds.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSchemaIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.db")
	for i := 0; i < 3; i++ {
		s, err := Open(context.Background(), path)
		if err != nil {
			t.Fatalf("Open #%d: %v", i, err)
		}
		_ = s.Close()
	}
}

func TestAddAndListCredentials(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	id1, err := s.AddCredential(ctx, Credential{
		Kind:        testKindOther,
		Label:       "legacy-kind row",
		PrivateBlob: []byte("legacy-blob-1"),
	})
	if err != nil {
		t.Fatalf("AddCredential (testKindOther): %v", err)
	}
	if id1 == 0 {
		t.Fatal("expected nonzero id")
	}

	_, err = s.AddCredential(ctx, Credential{
		Kind:           KindWebAuthn,
		Label:          "macbook touchid",
		CredentialID:   []byte("cred-id-bytes"),
		PublicMaterial: []byte("cose-public-key"),
	})
	if err != nil {
		t.Fatalf("AddCredential webauthn: %v", err)
	}

	got, err := s.ListCredentials(ctx)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d credentials, want 2", len(got))
	}
	if got[0].Kind != testKindOther || got[1].Kind != KindWebAuthn {
		t.Fatalf("ordering wrong: %v / %v", got[0].Kind, got[1].Kind)
	}
	if !bytes.Equal(got[0].PrivateBlob, []byte("legacy-blob-1")) {
		t.Fatal("private blob roundtrip failed")
	}
}

func TestGetCredentialByKind(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.GetCredentialByKind(ctx, KindWebAuthn); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
	_, err := s.AddCredential(ctx, Credential{
		Kind:           KindWebAuthn,
		Label:          "test",
		CredentialID:   []byte("id"),
		PublicMaterial: []byte("k"),
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.GetCredentialByKind(ctx, KindWebAuthn)
	if err != nil {
		t.Fatalf("GetCredentialByKind: %v", err)
	}
	if string(c.PublicMaterial) != "k" {
		t.Fatal("material mismatch")
	}
}

func TestRequiresKindAndLabel(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.AddCredential(ctx, Credential{Label: "x"}); err == nil {
		t.Fatal("expected error for missing kind")
	}
	if _, err := s.AddCredential(ctx, Credential{Kind: KindWebAuthn}); err == nil {
		t.Fatal("expected error for missing label")
	}
}

func TestRecoveryCodeRoundtrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if _, err := s.GetRecoveryCodeHash(ctx); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}

	hash := bytes.Repeat([]byte{0x55}, 32)
	if err := s.SetRecoveryCodeHash(ctx, hash); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.GetRecoveryCodeHash(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, hash) {
		t.Fatalf("roundtrip mismatch")
	}

	// Replacing should overwrite.
	hash2 := bytes.Repeat([]byte{0xaa}, 32)
	if err := s.SetRecoveryCodeHash(ctx, hash2); err != nil {
		t.Fatalf("Set replace: %v", err)
	}
	got, _ = s.GetRecoveryCodeHash(ctx)
	if !bytes.Equal(got, hash2) {
		t.Fatal("replace did not overwrite")
	}
}

func TestBurnRecoveryCode(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if err := s.BurnRecoveryCode(ctx); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows on burn-without-set, got %v", err)
	}

	original := bytes.Repeat([]byte{0x11}, 32)
	if err := s.SetRecoveryCodeHash(ctx, original); err != nil {
		t.Fatal(err)
	}
	if err := s.BurnRecoveryCode(ctx); err != nil {
		t.Fatalf("BurnRecoveryCode: %v", err)
	}
	got, err := s.GetRecoveryCodeHash(ctx)
	if err != nil {
		t.Fatalf("Get post-burn: %v", err)
	}
	if bytes.Equal(got, original) {
		t.Fatal("burn did not change hash")
	}
	if len(got) != 32 {
		t.Fatalf("post-burn hash len = %d, want 32", len(got))
	}
}

func TestDeleteAllCredentials(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, err := s.AddCredential(ctx, Credential{
			Kind:           KindWebAuthn,
			Label:          "wa",
			CredentialID:   []byte{byte(i)},
			PublicMaterial: []byte{byte(i)},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteAllCredentials(ctx); err != nil {
		t.Fatalf("DeleteAllCredentials: %v", err)
	}
	got, _ := s.ListCredentials(ctx)
	if len(got) != 0 {
		t.Fatalf("expected 0 after delete, got %d", len(got))
	}
}

func TestMarkCredentialUsed(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	id, _ := s.AddCredential(ctx, Credential{Kind: KindWebAuthn, Label: "wa", CredentialID: []byte("id"), PublicMaterial: []byte("k")})
	if err := s.MarkCredentialUsed(ctx, id); err != nil {
		t.Fatalf("MarkCredentialUsed: %v", err)
	}
	c, _ := s.GetCredentialByKind(ctx, KindWebAuthn)
	if c.LastUsedAt.IsZero() {
		t.Fatal("LastUsedAt was not updated")
	}
}

func TestMetaSetGet(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.MetaGet(ctx, "missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
	if err := s.MetaSet(ctx, "k", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	got, err := s.MetaGet(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v1" {
		t.Fatalf("got %q, want v1", got)
	}
	// Overwrite.
	if err := s.MetaSet(ctx, "k", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	got, _ = s.MetaGet(ctx, "k")
	if string(got) != "v2" {
		t.Fatalf("got %q, want v2", got)
	}
	// Empty key rejected.
	if err := s.MetaSet(ctx, "", []byte("x")); err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestEnsureUserIDStable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	a, err := s.EnsureUserID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 16 {
		t.Fatalf("user id length = %d, want 16", len(a))
	}
	b, err := s.EnsureUserID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("EnsureUserID returned a different value on second call")
	}
}

func TestListCredentialsByKind(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_, _ = s.AddCredential(ctx, Credential{Kind: testKindOther, Label: "other-1", PrivateBlob: []byte("a")})
	_, _ = s.AddCredential(ctx, Credential{Kind: KindWebAuthn, Label: "wa-1", CredentialID: []byte("id1"), PublicMaterial: []byte("k1")})
	_, _ = s.AddCredential(ctx, Credential{Kind: KindWebAuthn, Label: "wa-2", CredentialID: []byte("id2"), PublicMaterial: []byte("k2")})

	wa, err := s.ListCredentialsByKind(ctx, KindWebAuthn)
	if err != nil {
		t.Fatal(err)
	}
	if len(wa) != 2 {
		t.Fatalf("got %d webauthn rows, want 2", len(wa))
	}
	if wa[0].Label != "wa-1" || wa[1].Label != "wa-2" {
		t.Fatalf("ordering wrong: %v", []string{wa[0].Label, wa[1].Label})
	}

	other, _ := s.ListCredentialsByKind(ctx, testKindOther)
	if len(other) != 1 {
		t.Fatalf("got %d testKindOther rows, want 1", len(other))
	}
}

func TestGetCredentialByID(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	id, _ := s.AddCredential(ctx, Credential{
		Kind:           KindWebAuthn,
		Label:          "wa",
		CredentialID:   []byte("look-up-by-this"),
		PublicMaterial: []byte("pubkey"),
	})

	c, err := s.GetCredentialByID(ctx, []byte("look-up-by-this"))
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != id {
		t.Fatalf("id = %d, want %d", c.ID, id)
	}

	if _, err := s.GetCredentialByID(ctx, []byte("nope")); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestUpdateCredentialMaterial(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	id, _ := s.AddCredential(ctx, Credential{
		Kind:           KindWebAuthn,
		Label:          "wa",
		CredentialID:   []byte("cid"),
		PublicMaterial: []byte("v1"),
	})
	if err := s.UpdateCredentialMaterial(ctx, id, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	c, _ := s.GetCredentialByID(ctx, []byte("cid"))
	if string(c.PublicMaterial) != "v2" {
		t.Fatalf("public_material = %q, want v2", c.PublicMaterial)
	}
}
