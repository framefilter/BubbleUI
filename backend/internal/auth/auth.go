// Package auth implements the BubbleUI authentication flows from
// DESIGN.md §5 — provisioning a YubiKey credential, logging in via HMAC
// challenge-response, and the recovery-code path.
//
// WebAuthn registration and assertion verification are stubbed in M2; full
// integration lands in M3 alongside the HTTP surface.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"hash"

	bcrypto "github.com/framefilter/bubbleui/backend/internal/crypto"
	"github.com/framefilter/bubbleui/backend/internal/store"
	"github.com/framefilter/bubbleui/backend/internal/yubikey"
)

// SecretLen is the byte length of the YubiKey HMAC-SHA1 slot 2 secret S.
// HMAC-SHA1 accepts any key length; 20 bytes is the canonical YubiKey choice.
const SecretLen = 20

// LoginChallengeLen is the byte length of the per-login random challenge.
const LoginChallengeLen = 64

// Errors returned by the auth flows. Callers should treat any of these as
// "rejected" — never differentiate them in user-facing copy.
var (
	ErrNoCredential   = errors.New("auth: no credential of that kind registered")
	ErrChallengeFail  = errors.New("auth: challenge response did not match")
	ErrNoRecoveryCode = errors.New("auth: no recovery code set")
	ErrBadRecovery    = errors.New("auth: recovery code rejected")
)

// Authenticator wires the persistence + crypto + yubikey adapters together.
// One instance per running daemon.
type Authenticator struct {
	Store  *store.Store
	Yubi   yubikey.Oracle
	NewKey func() ([]byte, error) // override in tests; defaults to crypto/rand
}

// New returns an Authenticator with crypto/rand-backed key generation.
func New(s *store.Store, y yubikey.Oracle) *Authenticator {
	return &Authenticator{
		Store: s,
		Yubi:  y,
		NewKey: func() ([]byte, error) {
			b := make([]byte, SecretLen)
			_, err := rand.Read(b)
			return b, err
		},
	}
}

// ProvisionResult bundles the values returned by the provisioning flow.
// Callers MUST display RecoveryCode to the user exactly once and persist
// nothing — only the BLAKE2s hash lives on disk. Secret is returned so the
// caller can program slot 2 of the user's physical YubiKey via `ykman`.
type ProvisionResult struct {
	CredentialID int64
	RecoveryCode string
	Secret       []byte
}

// ProvisionYubiKey runs the §5.2 YubiKey-on-router provisioning flow.
//
// The caller is responsible for actually writing Secret to slot 2 of the
// user's physical YubiKey before the user attempts to log in. The store
// row is committed before that happens — if the user abandons the flow,
// the on-disk state references a key that doesn't exist yet, but no harm
// is done: login will simply fail until the key is programmed.
func (a *Authenticator) ProvisionYubiKey(ctx context.Context, label string) (*ProvisionResult, error) {
	if label == "" {
		label = "router yubikey"
	}
	S, err := a.NewKey()
	if err != nil {
		return nil, fmt.Errorf("auth: generate secret: %w", err)
	}

	// Compute the wrap key the same way the YubiKey will once programmed:
	// HMAC-SHA1(S, SelfWrapChallenge) → HKDF-SHA256 → 32 bytes.
	wrapResp := hmacSHA1(S, bcrypto.SelfWrapChallenge())
	wrapKey, err := bcrypto.DeriveWrapKey(wrapResp)
	if err != nil {
		return nil, err
	}
	blob, err := bcrypto.Wrap(wrapKey, S)
	if err != nil {
		return nil, err
	}

	id, err := a.Store.AddCredential(ctx, store.Credential{
		Kind:        store.KindYubiKeyHMAC,
		Label:       label,
		PrivateBlob: blob,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: persist credential: %w", err)
	}

	code, err := bcrypto.NewRecoveryCode()
	if err != nil {
		return nil, fmt.Errorf("auth: generate recovery: %w", err)
	}
	hashed, err := bcrypto.HashRecoveryCode(code)
	if err != nil {
		return nil, err
	}
	if err := a.Store.SetRecoveryCodeHash(ctx, hashed); err != nil {
		return nil, fmt.Errorf("auth: persist recovery: %w", err)
	}

	return &ProvisionResult{CredentialID: id, RecoveryCode: code, Secret: S}, nil
}

// LoginYubiKey runs the §5.3 YubiKey-on-router login flow. Returns the
// matched credential ID on success.
func (a *Authenticator) LoginYubiKey(ctx context.Context) (int64, error) {
	cred, err := a.Store.GetCredentialByKind(ctx, store.KindYubiKeyHMAC)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNoCredential
		}
		return 0, err
	}

	// Recover the wrap key from the key via the fixed self-wrap challenge,
	// then unwrap the stored S.
	wrapResp, err := a.Yubi.Challenge(ctx, yubikey.Slot2, bcrypto.SelfWrapChallenge())
	if err != nil {
		return 0, ErrChallengeFail
	}
	wrapKey, err := bcrypto.DeriveWrapKey(wrapResp)
	if err != nil {
		return 0, err
	}
	S, err := bcrypto.Unwrap(wrapKey, cred.PrivateBlob)
	if err != nil {
		// Unwrap failure means the key changed or the blob is corrupt.
		return 0, ErrChallengeFail
	}
	defer zero(S)

	// Real login challenge: random bytes → key → compare HMAC.
	challenge := make([]byte, LoginChallengeLen)
	if _, err := rand.Read(challenge); err != nil {
		return 0, fmt.Errorf("auth: rand: %w", err)
	}
	keyResp, err := a.Yubi.Challenge(ctx, yubikey.Slot2, challenge)
	if err != nil {
		return 0, ErrChallengeFail
	}
	expected := hmacSHA1(S, challenge)
	if subtle.ConstantTimeCompare(keyResp, expected) != 1 {
		return 0, ErrChallengeFail
	}

	if err := a.Store.MarkCredentialUsed(ctx, cred.ID); err != nil {
		return 0, err
	}
	return cred.ID, nil
}

// Recover runs the §5.4 recovery flow. On success, all credentials are
// wiped, the recovery code is burned, and the caller is responsible for
// returning the device to setup mode.
func (a *Authenticator) Recover(ctx context.Context, code string) error {
	hashed, err := a.Store.GetRecoveryCodeHash(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoRecoveryCode
		}
		return err
	}
	ok, err := bcrypto.VerifyRecoveryCode(code, hashed)
	if err != nil {
		return err
	}
	if !ok {
		return ErrBadRecovery
	}
	// Burn first so a crash mid-recovery still invalidates the code.
	if err := a.Store.BurnRecoveryCode(ctx); err != nil {
		return err
	}
	return a.Store.DeleteAllCredentials(ctx)
}

// HasAnyCredential reports whether at least one credential of any kind is
// registered. The wizard gates "exit setup mode" on this returning true.
func (a *Authenticator) HasAnyCredential(ctx context.Context) (bool, error) {
	creds, err := a.Store.ListCredentials(ctx)
	if err != nil {
		return false, err
	}
	return len(creds) > 0, nil
}

func hmacSHA1(key, msg []byte) []byte {
	var h hash.Hash = hmac.New(sha1.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
