// Package webauthn wraps github.com/go-webauthn/webauthn with the
// pending-flow state and identity model BubbleUI needs.
//
// We hold one identity per device (DESIGN.md §5.1 — single-user model).
// Multiple credentials register against that single identity; on login
// the user can authenticate with any of them. Pending registration /
// login state lives in-process for ~5 minutes and is keyed by an opaque
// handle the SPA round-trips between begin and finish calls.
package webauthn

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowa "github.com/go-webauthn/webauthn/webauthn"
)

// Errors returned by the engine. Callers should map all of these to a
// generic 4xx for the user — they leak nothing useful externally but are
// distinguishable internally for logging.
var (
	ErrUnknownHandle = errors.New("webauthn: unknown or expired handle")
	ErrParse         = errors.New("webauthn: malformed response")
	ErrValidate      = errors.New("webauthn: validation failed")
)

// Config carries the relying-party identity. RPID is the host without
// scheme or port; Origins are the full origins the SPA loads from.
type Config struct {
	RPID          string
	RPDisplayName string
	Origins       []string
	// PendingTTL is how long a begun ceremony stays valid waiting for finish.
	// Defaults to 5 minutes.
	PendingTTL time.Duration
}

// Engine is the configured WebAuthn helper.
type Engine struct {
	wa      *gowa.WebAuthn
	pending sync.Map // handle -> pendingSession
	now     func() time.Time
	ttl     time.Duration
}

type pendingSession struct {
	data    *gowa.SessionData
	expires time.Time
}

// New constructs an Engine. The Config must include a non-empty RPID.
func New(cfg Config) (*Engine, error) {
	if cfg.RPID == "" {
		return nil, errors.New("webauthn: RPID required")
	}
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = "BubbleUI"
	}
	if cfg.PendingTTL == 0 {
		cfg.PendingTTL = 5 * time.Minute
	}
	wa, err := gowa.New(&gowa.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.Origins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	return &Engine{wa: wa, now: time.Now, ttl: cfg.PendingTTL}, nil
}

// User exposes BubbleUI's single-identity model to the upstream library.
type User struct {
	ID          []byte
	Name        string
	Credentials []gowa.Credential
}

func (u *User) WebAuthnID() []byte                     { return u.ID }
func (u *User) WebAuthnName() string                   { return u.Name }
func (u *User) WebAuthnDisplayName() string            { return u.Name }
func (u *User) WebAuthnCredentials() []gowa.Credential { return u.Credentials }
func (u *User) WebAuthnIcon() string                   { return "" } // deprecated upstream; required by interface

// BeginRegister starts a registration ceremony. Returns the opaque
// handle the SPA echoes back to FinishRegister, plus the JSON-encoded
// CredentialCreation options to forward to the browser.
func (e *Engine) BeginRegister(user *User) (handle string, options []byte, err error) {
	creation, sess, err := e.wa.BeginRegistration(user)
	if err != nil {
		return "", nil, fmt.Errorf("webauthn: begin register: %w", err)
	}
	handle, err = newHandle()
	if err != nil {
		return "", nil, err
	}
	e.stash(handle, sess)
	options, err = json.Marshal(creation)
	if err != nil {
		return "", nil, err
	}
	return handle, options, nil
}

// FinishRegister validates the SPA's attestation response. On success it
// returns the credential ready to be persisted by the caller.
func (e *Engine) FinishRegister(user *User, handle string, body []byte) (*gowa.Credential, error) {
	sess, ok := e.consume(handle)
	if !ok {
		return nil, ErrUnknownHandle
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParse, err)
	}
	cred, err := e.wa.CreateCredential(user, *sess, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrValidate, err)
	}
	return cred, nil
}

// BeginLogin starts an authentication ceremony. The user's registered
// credentials populate the allowedCredentials field so the browser knows
// which authenticators to prompt.
func (e *Engine) BeginLogin(user *User) (handle string, options []byte, err error) {
	assertion, sess, err := e.wa.BeginLogin(user)
	if err != nil {
		return "", nil, fmt.Errorf("webauthn: begin login: %w", err)
	}
	handle, err = newHandle()
	if err != nil {
		return "", nil, err
	}
	e.stash(handle, sess)
	options, err = json.Marshal(assertion)
	if err != nil {
		return "", nil, err
	}
	return handle, options, nil
}

// FinishLogin validates the SPA's assertion response. On success it
// returns the (possibly updated — sign count, etc.) credential.
func (e *Engine) FinishLogin(user *User, handle string, body []byte) (*gowa.Credential, error) {
	sess, ok := e.consume(handle)
	if !ok {
		return nil, ErrUnknownHandle
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParse, err)
	}
	cred, err := e.wa.ValidateLogin(user, *sess, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrValidate, err)
	}
	return cred, nil
}

// Sweep removes expired pending sessions. Call periodically (e.g. on the
// same ticker that purges expired HTTP sessions).
func (e *Engine) Sweep() {
	now := e.now()
	e.pending.Range(func(k, v any) bool {
		if now.After(v.(pendingSession).expires) {
			e.pending.Delete(k)
		}
		return true
	})
}

// PendingCount returns the number of in-flight ceremonies. Useful in tests.
func (e *Engine) PendingCount() int {
	n := 0
	e.pending.Range(func(_, _ any) bool { n++; return true })
	return n
}

// SetClock overrides the time source. For tests.
func (e *Engine) SetClock(f func() time.Time) { e.now = f }

func (e *Engine) stash(handle string, sess *gowa.SessionData) {
	e.pending.Store(handle, pendingSession{
		data:    sess,
		expires: e.now().Add(e.ttl),
	})
}

func (e *Engine) consume(handle string) (*gowa.SessionData, bool) {
	v, ok := e.pending.LoadAndDelete(handle)
	if !ok {
		return nil, false
	}
	p := v.(pendingSession)
	if e.now().After(p.expires) {
		return nil, false
	}
	return p.data, true
}

func newHandle() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
