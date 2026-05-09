// Package auth implements the BubbleUI authentication flows from
// DESIGN.md §5 — provisioning a YubiKey credential, logging in via HMAC
// challenge-response, registering and authenticating WebAuthn credentials,
// and the recovery-code path.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash"

	gowa "github.com/go-webauthn/webauthn/webauthn"

	bcrypto "github.com/framefilter/bubbleui/backend/internal/crypto"
	"github.com/framefilter/bubbleui/backend/internal/store"
	"github.com/framefilter/bubbleui/backend/internal/webauthn"
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
	ErrNoWebAuthn     = errors.New("auth: webauthn engine not configured")
)

// Authenticator wires the persistence + crypto + yubikey + webauthn
// adapters together. One instance per running daemon.
type Authenticator struct {
	Store      *store.Store
	Yubi       yubikey.Oracle
	Programmer yubikey.Programmer     // optional; required for ProvisionYubiKeyAndProgram
	WebAuthn   *webauthn.Engine       // optional; nil disables WebAuthn flows
	NewKey     func() ([]byte, error) // override in tests; defaults to crypto/rand
}

// New returns an Authenticator with crypto/rand-backed key generation
// and no WebAuthn engine. Set Authenticator.WebAuthn after construction
// to enable the WebAuthn flows.
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

// ProvisionYubiKeyAndProgram runs the full wizard provisioning step: it
// generates the secret, persists the wrapped credential and recovery
// code, then programs the secret into slot 2 of the attached YubiKey via
// the configured Programmer. The recovery code is the only return value
// the caller should ever display — Secret stays on the device.
//
// Programmer-failure semantics:
//   - if Programmer is nil → returns the persisted result with NotProgrammed=true
//     so the wizard can fall back to a copy-pasteable ykman command.
//   - if Programmer returns ErrUnsupported (no ykman on PATH) → same as above.
//   - if Programmer returns any other error → the credential row is rolled
//     back so the user can retry without colliding state.
type ProvisionAndProgramResult struct {
	*ProvisionResult
	NotProgrammed bool   // true if the Programmer wasn't run / couldn't run
	ProgramHint   string // guidance to surface to the user when NotProgrammed
}

func (a *Authenticator) ProvisionYubiKeyAndProgram(ctx context.Context, label string) (*ProvisionAndProgramResult, error) {
	res, err := a.ProvisionYubiKey(ctx, label)
	if err != nil {
		return nil, err
	}
	out := &ProvisionAndProgramResult{ProvisionResult: res}

	if a.Programmer == nil {
		out.NotProgrammed = true
		out.ProgramHint = "no programmer configured; run ykman manually with the secret printed by the CLI"
		return out, nil
	}
	if err := a.Programmer.Program(ctx, yubikey.Slot2, res.Secret); err != nil {
		if errors.Is(err, yubikey.ErrUnsupported) {
			out.NotProgrammed = true
			out.ProgramHint = "ykman not available; copy the printed command and run it on the router shell"
			return out, nil
		}
		// Real programming failure: roll back so the user can retry.
		_ = a.Store.DeleteAllCredentials(ctx)
		_ = a.Store.BurnRecoveryCode(ctx)
		return nil, fmt.Errorf("auth: program key: %w", err)
	}
	return out, nil
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

// --- WebAuthn flows (DESIGN.md §5.3 webauthn-from-browser path) ---

// loadUser builds the User abstraction expected by go-webauthn from
// persisted state: stable user-ID + every WebAuthn credential row,
// each rehydrated from the JSON blob in public_material.
func (a *Authenticator) loadUser(ctx context.Context) (*webauthn.User, error) {
	id, err := a.Store.EnsureUserID(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := a.Store.ListCredentialsByKind(ctx, store.KindWebAuthn)
	if err != nil {
		return nil, err
	}
	creds := make([]gowa.Credential, 0, len(rows))
	for _, r := range rows {
		var c gowa.Credential
		if err := json.Unmarshal(r.PublicMaterial, &c); err != nil {
			return nil, fmt.Errorf("auth: rehydrate credential %d: %w", r.ID, err)
		}
		creds = append(creds, c)
	}
	return &webauthn.User{
		ID:          id,
		Name:        "bubbleui",
		Credentials: creds,
	}, nil
}

// BeginRegisterWebAuthn starts a WebAuthn registration ceremony. Returns
// the opaque handle the SPA echoes back to FinishRegisterWebAuthn, plus
// the JSON-encoded options to forward to navigator.credentials.create().
func (a *Authenticator) BeginRegisterWebAuthn(ctx context.Context) (handle string, options []byte, err error) {
	if a.WebAuthn == nil {
		return "", nil, ErrNoWebAuthn
	}
	user, err := a.loadUser(ctx)
	if err != nil {
		return "", nil, err
	}
	return a.WebAuthn.BeginRegister(user)
}

// WebAuthnRegistration bundles the persisted credential ID with the
// recovery code, when one was generated as part of this registration.
// RecoveryCode is non-empty only when this was the first credential on
// the device — subsequent registrations leave the existing recovery code
// in place. Display it once and store nothing.
type WebAuthnRegistration struct {
	CredentialID int64
	RecoveryCode string // non-empty iff this was the first credential
}

// FinishRegisterWebAuthn validates an attestation response and persists
// the credential. label is what the user sees in the security UI; empty
// label gets a sensible default. If this is the first credential on the
// device (no others, no recovery code yet), a fresh recovery code is
// generated and returned in the result; the caller must surface it to
// the user exactly once.
func (a *Authenticator) FinishRegisterWebAuthn(ctx context.Context, label, handle string, body []byte) (*WebAuthnRegistration, error) {
	if a.WebAuthn == nil {
		return nil, ErrNoWebAuthn
	}
	user, err := a.loadUser(ctx)
	if err != nil {
		return nil, err
	}
	cred, err := a.WebAuthn.FinishRegister(user, handle, body)
	if err != nil {
		return nil, ErrChallengeFail
	}
	blob, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("auth: marshal credential: %w", err)
	}
	if label == "" {
		label = "webauthn credential"
	}

	// Detect first-credential state BEFORE inserting so we know whether
	// to mint a recovery code.
	firstCredential, err := isFirstCredential(ctx, a.Store)
	if err != nil {
		return nil, err
	}

	id, err := a.Store.AddCredential(ctx, store.Credential{
		Kind:           store.KindWebAuthn,
		Label:          label,
		CredentialID:   cred.ID,
		PublicMaterial: blob,
	})
	if err != nil {
		return nil, err
	}

	out := &WebAuthnRegistration{CredentialID: id}
	if firstCredential {
		code, hashed, err := generateRecoveryCode()
		if err != nil {
			return nil, err
		}
		if err := a.Store.SetRecoveryCodeHash(ctx, hashed); err != nil {
			return nil, fmt.Errorf("auth: persist recovery: %w", err)
		}
		out.RecoveryCode = code
	}
	return out, nil
}

func isFirstCredential(ctx context.Context, s *store.Store) (bool, error) {
	creds, err := s.ListCredentials(ctx)
	if err != nil {
		return false, err
	}
	if len(creds) > 0 {
		return false, nil
	}
	if _, err := s.GetRecoveryCodeHash(ctx); err == nil {
		// No credentials but a recovery code exists — not a fresh device.
		return false, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	return true, nil
}

func generateRecoveryCode() (code string, hashed []byte, err error) {
	code, err = bcrypto.NewRecoveryCode()
	if err != nil {
		return "", nil, fmt.Errorf("auth: generate recovery: %w", err)
	}
	hashed, err = bcrypto.HashRecoveryCode(code)
	if err != nil {
		return "", nil, err
	}
	return code, hashed, nil
}

// BeginLoginWebAuthn starts a WebAuthn authentication ceremony.
func (a *Authenticator) BeginLoginWebAuthn(ctx context.Context) (handle string, options []byte, err error) {
	if a.WebAuthn == nil {
		return "", nil, ErrNoWebAuthn
	}
	user, err := a.loadUser(ctx)
	if err != nil {
		return "", nil, err
	}
	if len(user.Credentials) == 0 {
		return "", nil, ErrNoCredential
	}
	return a.WebAuthn.BeginLogin(user)
}

// FinishLoginWebAuthn validates an assertion response and returns the
// matched credential's row ID. The caller then mints a session.
func (a *Authenticator) FinishLoginWebAuthn(ctx context.Context, handle string, body []byte) (int64, error) {
	if a.WebAuthn == nil {
		return 0, ErrNoWebAuthn
	}
	user, err := a.loadUser(ctx)
	if err != nil {
		return 0, err
	}
	cred, err := a.WebAuthn.FinishLogin(user, handle, body)
	if err != nil {
		return 0, ErrChallengeFail
	}
	row, err := a.Store.GetCredentialByID(ctx, cred.ID)
	if err != nil {
		return 0, ErrChallengeFail
	}
	// Persist the post-validation credential — the library may have
	// updated sign-count or clone-warning fields we want to keep.
	if blob, err := json.Marshal(cred); err == nil {
		_ = a.Store.UpdateCredentialMaterial(ctx, row.ID, blob)
	}
	if err := a.Store.MarkCredentialUsed(ctx, row.ID); err != nil {
		return 0, err
	}
	return row.ID, nil
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
