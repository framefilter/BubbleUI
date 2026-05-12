// Package auth implements the BubbleUI authentication flows from
// DESIGN.md §5 — registering and authenticating WebAuthn credentials,
// and the recovery-code path. Hardware-key auth runs through WebAuthn
// only; the formerly co-equal router-attached YubiKey HMAC path has
// been removed (see §11 / project memory for the FIDO2 hmac-secret
// follow-up that will eventually re-introduce HW-bound at-rest wrap).
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	gowa "github.com/go-webauthn/webauthn/webauthn"

	bcrypto "github.com/framefilter/bubbleui/backend/internal/crypto"
	"github.com/framefilter/bubbleui/backend/internal/store"
	"github.com/framefilter/bubbleui/backend/internal/webauthn"
)

// Errors returned by the auth flows. Callers should treat any of these as
// "rejected" — never differentiate them in user-facing copy.
var (
	ErrNoCredential   = errors.New("auth: no credential of that kind registered")
	ErrChallengeFail  = errors.New("auth: challenge response did not match")
	ErrNoRecoveryCode = errors.New("auth: no recovery code set")
	ErrBadRecovery    = errors.New("auth: recovery code rejected")
	ErrNoWebAuthn     = errors.New("auth: webauthn engine not configured")
)

// Authenticator wires the persistence + webauthn adapters together. One
// instance per running daemon.
type Authenticator struct {
	Store    *store.Store
	WebAuthn *webauthn.Engine // optional; nil disables WebAuthn flows
}

// New returns an Authenticator with no WebAuthn engine. Set
// Authenticator.WebAuthn after construction to enable the WebAuthn flows.
func New(s *store.Store) *Authenticator {
	return &Authenticator{Store: s}
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
