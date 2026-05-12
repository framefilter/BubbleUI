// Package session manages BubbleUI's HTTP sessions. Sessions are
// SQLite-backed so they survive a reboot — users on a freshly power-cycled
// travel router don't have to re-run the WebAuthn ceremony unless their
// session has actually expired.
//
// Tokens are 32 bytes of crypto/rand entropy, base64url-encoded for the
// cookie. The DB stores a BLAKE2s-256 hash of each token — DB compromise
// does not expose live session tokens.
package session

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/blake2s"
)

// CookieName is the canonical cookie name for the session token.
const CookieName = "bubble-session"

// Default lifetime for new sessions.
const DefaultLifetime = 24 * time.Hour

// Token byte length before base64url encoding.
const tokenBytes = 32

// Errors returned by the session manager. Callers should treat any of
// these as "rejected" without leaking which specifically failed.
var (
	ErrInvalidToken = errors.New("session: invalid token")
	ErrExpired      = errors.New("session: expired")
)

// Session is a live (or expired) session record.
type Session struct {
	ID           int64
	CredentialID int64
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastSeenAt   time.Time
}

// Manager owns the sessions table.
type Manager struct {
	db       *sql.DB
	lifetime time.Duration
	now      func() time.Time
}

// NewManager opens a new session manager backed by the same SQLite
// database that the credential store uses. Schema is migrated on first use.
func NewManager(ctx context.Context, db *sql.DB) (*Manager, error) {
	m := &Manager{
		db:       db,
		lifetime: DefaultLifetime,
		now:      time.Now,
	}
	if err := m.migrate(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// SetLifetime overrides the default 24-hour lifetime. Useful in tests.
func (m *Manager) SetLifetime(d time.Duration) { m.lifetime = d }

// SetClock overrides the time source. Useful in tests.
func (m *Manager) SetClock(f func() time.Time) { m.now = f }

func (m *Manager) migrate(ctx context.Context) error {
	stmt := `CREATE TABLE IF NOT EXISTS sessions (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		token_hash    BLOB    NOT NULL UNIQUE,
		credential_id INTEGER NOT NULL,
		created_at    INTEGER NOT NULL,
		expires_at    INTEGER NOT NULL,
		last_seen_at  INTEGER NOT NULL
	)`
	_, err := m.db.ExecContext(ctx, stmt)
	if err != nil {
		return fmt.Errorf("session: migrate: %w", err)
	}
	return nil
}

// Create mints a new session bound to credentialID and returns the cookie
// token. The plaintext token is the only place the token ever exists in
// memory after this call returns; the DB sees only its hash.
func (m *Manager) Create(ctx context.Context, credentialID int64) (token string, sess *Session, err error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("session: rand: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	hash, err := hashToken(token)
	if err != nil {
		return "", nil, err
	}

	now := m.now()
	expires := now.Add(m.lifetime)
	res, err := m.db.ExecContext(ctx,
		`INSERT INTO sessions(token_hash, credential_id, created_at, expires_at, last_seen_at)
		 VALUES (?, ?, ?, ?, ?)`,
		hash, credentialID, now.Unix(), expires.Unix(), now.Unix())
	if err != nil {
		return "", nil, fmt.Errorf("session: insert: %w", err)
	}
	id, _ := res.LastInsertId()
	return token, &Session{
		ID:           id,
		CredentialID: credentialID,
		CreatedAt:    now,
		ExpiresAt:    expires,
		LastSeenAt:   now,
	}, nil
}

// Validate looks up token, sliding the expiration forward on success.
// Returns ErrInvalidToken or ErrExpired without distinguishing — the
// caller should respond with the same 401 either way.
func (m *Manager) Validate(ctx context.Context, token string) (*Session, error) {
	hash, err := hashToken(token)
	if err != nil {
		return nil, ErrInvalidToken
	}

	row := m.db.QueryRowContext(ctx,
		`SELECT id, token_hash, credential_id, created_at, expires_at, last_seen_at
		 FROM sessions WHERE token_hash = ?`, hash)

	var s Session
	var storedHash []byte
	var created, expires, lastSeen int64
	if err := row.Scan(&s.ID, &storedHash, &s.CredentialID, &created, &expires, &lastSeen); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}

	// Constant-time compare even though we already matched on the indexed
	// column — defense in depth against timing-leak refactors.
	if subtle.ConstantTimeCompare(storedHash, hash) != 1 {
		return nil, ErrInvalidToken
	}

	now := m.now()
	if now.Unix() > expires {
		// Best-effort cleanup; not failing the request on this.
		_, _ = m.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, s.ID)
		return nil, ErrExpired
	}

	// Slide expiration forward to "now + lifetime" on every validate.
	newExpires := now.Add(m.lifetime)
	_, _ = m.db.ExecContext(ctx,
		`UPDATE sessions SET expires_at = ?, last_seen_at = ? WHERE id = ?`,
		newExpires.Unix(), now.Unix(), s.ID)

	s.CreatedAt = time.Unix(created, 0)
	s.ExpiresAt = newExpires
	s.LastSeenAt = now
	return &s, nil
}

// Revoke deletes the session whose token is presented. No-op if the token
// is unknown — callers logging out shouldn't see different behavior based
// on whether they had a real session.
func (m *Manager) Revoke(ctx context.Context, token string) error {
	hash, err := hashToken(token)
	if err != nil {
		return nil
	}
	_, err = m.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hash)
	return err
}

// RevokeAll wipes every session. Called by the recovery flow.
func (m *Manager) RevokeAll(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, `DELETE FROM sessions`)
	return err
}

// PurgeExpired removes rows whose expiration has passed. Cheap to call;
// safe to schedule on a timer.
func (m *Manager) PurgeExpired(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at <= ?`, m.now().Unix())
	return err
}

func hashToken(token string) ([]byte, error) {
	if token == "" {
		return nil, errors.New("session: empty token")
	}
	h, err := blake2s.New256(nil)
	if err != nil {
		return nil, err
	}
	h.Write([]byte(token))
	return h.Sum(nil), nil
}
