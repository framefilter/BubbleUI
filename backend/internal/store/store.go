// Package store persists BubbleUI's auth state in SQLite — the resolved
// answer to DESIGN.md §11.1.
//
// The schema is intentionally narrow: one credential table that holds both
// YubiKey-self-wrapped secrets and WebAuthn credential public keys, plus a
// small recovery_code table holding the BLAKE2s hash of the (single) active
// recovery code.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// CredentialKind discriminates the rows in the credentials table.
type CredentialKind string

const (
	KindYubiKeyHMAC CredentialKind = "yk_hmac"
	KindWebAuthn    CredentialKind = "webauthn"
)

// Credential is a registered authentication factor.
//
// For KindYubiKeyHMAC: PublicMaterial is empty, PrivateBlob is the
// AES-256-GCM ciphertext of the slot-2 secret S, self-wrapped under the key
// derived from S itself (see internal/crypto).
//
// For KindWebAuthn: PublicMaterial is the credential's COSE-encoded public
// key, PrivateBlob is empty.
type Credential struct {
	ID             int64
	Kind           CredentialKind
	Label          string
	CredentialID   []byte // WebAuthn credential ID; empty for HMAC
	PublicMaterial []byte
	PrivateBlob    []byte
	CreatedAt      time.Time
	LastUsedAt     time.Time
}

// Store is a thin wrapper around *sql.DB enforcing the schema and the
// invariants we care about (e.g., at most one active recovery code).
type Store struct {
	db *sql.DB
}

// Open opens or creates the SQLite database at path and applies the schema.
func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// DB returns the underlying *sql.DB so other packages (e.g. session)
// can share the same SQLite connection. Callers must not close it; the
// store owns the lifetime.
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS credentials (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			kind            TEXT    NOT NULL,
			label           TEXT    NOT NULL,
			credential_id   BLOB,
			public_material BLOB,
			private_blob    BLOB,
			created_at      INTEGER NOT NULL,
			last_used_at    INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS credentials_credid
			ON credentials(credential_id) WHERE credential_id IS NOT NULL`,
		`CREATE TABLE IF NOT EXISTS recovery_code (
			id         INTEGER PRIMARY KEY CHECK (id = 1),
			hash       BLOB    NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS meta (
			key   TEXT PRIMARY KEY,
			value BLOB NOT NULL
		)`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("store: migrate: %w", err)
		}
	}
	return nil
}

// AddCredential inserts a new credential and returns its ID.
func (s *Store) AddCredential(ctx context.Context, c Credential) (int64, error) {
	if c.Kind == "" {
		return 0, errors.New("store: credential kind required")
	}
	if c.Label == "" {
		return 0, errors.New("store: credential label required")
	}
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO credentials(kind, label, credential_id, public_material, private_blob, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		string(c.Kind), c.Label, nullableBytes(c.CredentialID), c.PublicMaterial, c.PrivateBlob, now)
	if err != nil {
		return 0, fmt.Errorf("store: insert credential: %w", err)
	}
	return res.LastInsertId()
}

// ListCredentials returns all registered credentials, oldest first.
func (s *Store) ListCredentials(ctx context.Context) ([]Credential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, kind, label, credential_id, public_material, private_blob, created_at, last_used_at
		 FROM credentials ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list credentials: %w", err)
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		var kind string
		var created, used int64
		if err := rows.Scan(&c.ID, &kind, &c.Label, &c.CredentialID, &c.PublicMaterial, &c.PrivateBlob, &created, &used); err != nil {
			return nil, err
		}
		c.Kind = CredentialKind(kind)
		c.CreatedAt = time.Unix(created, 0)
		if used > 0 {
			c.LastUsedAt = time.Unix(used, 0)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCredentialByKind returns the first credential of the given kind, or
// sql.ErrNoRows if none exists. Useful when there is exactly one
// expected (e.g. one YubiKey-on-router HMAC credential).
func (s *Store) GetCredentialByKind(ctx context.Context, kind CredentialKind) (Credential, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, kind, label, credential_id, public_material, private_blob, created_at, last_used_at
		 FROM credentials WHERE kind = ? ORDER BY created_at ASC LIMIT 1`,
		string(kind))
	var c Credential
	var k string
	var created, used int64
	if err := row.Scan(&c.ID, &k, &c.Label, &c.CredentialID, &c.PublicMaterial, &c.PrivateBlob, &created, &used); err != nil {
		return Credential{}, err
	}
	c.Kind = CredentialKind(k)
	c.CreatedAt = time.Unix(created, 0)
	if used > 0 {
		c.LastUsedAt = time.Unix(used, 0)
	}
	return c, nil
}

// MarkCredentialUsed updates the last_used_at timestamp.
func (s *Store) MarkCredentialUsed(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE credentials SET last_used_at = ? WHERE id = ?`, time.Now().Unix(), id)
	return err
}

// DeleteAllCredentials removes every credential. Called by the recovery flow.
func (s *Store) DeleteAllCredentials(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM credentials`)
	return err
}

// SetRecoveryCodeHash stores the BLAKE2s hash of the active recovery code.
// At most one row exists; replacing it implicitly burns the previous code.
func (s *Store) SetRecoveryCodeHash(ctx context.Context, hash []byte) error {
	if len(hash) == 0 {
		return errors.New("store: empty recovery hash")
	}
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO recovery_code(id, hash, created_at) VALUES (1, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET hash = excluded.hash, created_at = excluded.created_at`,
		hash, now)
	return err
}

// GetRecoveryCodeHash returns the stored hash, or sql.ErrNoRows if unset.
func (s *Store) GetRecoveryCodeHash(ctx context.Context) ([]byte, error) {
	row := s.db.QueryRowContext(ctx, `SELECT hash FROM recovery_code WHERE id = 1`)
	var h []byte
	if err := row.Scan(&h); err != nil {
		return nil, err
	}
	return h, nil
}

// BurnRecoveryCode replaces the stored hash with random bytes, rendering
// the printed code unusable. Returns sql.ErrNoRows if no code was set.
func (s *Store) BurnRecoveryCode(ctx context.Context) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE recovery_code SET hash = randomblob(32), created_at = ? WHERE id = 1`,
		time.Now().Unix())
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// --- meta key/value ---

// MetaSet writes a value under key, replacing any existing value.
func (s *Store) MetaSet(ctx context.Context, key string, value []byte) error {
	if key == "" {
		return errors.New("store: empty meta key")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	return err
}

// MetaGet returns the stored value or sql.ErrNoRows.
func (s *Store) MetaGet(ctx context.Context, key string) ([]byte, error) {
	row := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key)
	var v []byte
	if err := row.Scan(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// EnsureUserID returns the WebAuthn user-ID for this device, generating a
// fresh 16-byte random value on first call and persisting it. Subsequent
// calls return the same value.
func (s *Store) EnsureUserID(ctx context.Context) ([]byte, error) {
	const key = "webauthn_user_id"
	if existing, err := s.MetaGet(ctx, key); err == nil {
		return existing, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	fresh := make([]byte, 16)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("store: rand: %w", err)
	}
	if err := s.MetaSet(ctx, key, fresh); err != nil {
		return nil, err
	}
	return fresh, nil
}

// --- credential lookups beyond the kind/index pair ---

// ListCredentialsByKind returns credentials of the given kind, oldest first.
func (s *Store) ListCredentialsByKind(ctx context.Context, kind CredentialKind) ([]Credential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, kind, label, credential_id, public_material, private_blob, created_at, last_used_at
		 FROM credentials WHERE kind = ? ORDER BY created_at ASC`,
		string(kind))
	if err != nil {
		return nil, fmt.Errorf("store: list by kind: %w", err)
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		var k string
		var created, used int64
		if err := rows.Scan(&c.ID, &k, &c.Label, &c.CredentialID, &c.PublicMaterial, &c.PrivateBlob, &created, &used); err != nil {
			return nil, err
		}
		c.Kind = CredentialKind(k)
		c.CreatedAt = time.Unix(created, 0)
		if used > 0 {
			c.LastUsedAt = time.Unix(used, 0)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCredentialByID returns the credential whose WebAuthn credential_id
// matches, or sql.ErrNoRows.
func (s *Store) GetCredentialByID(ctx context.Context, credentialID []byte) (Credential, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, kind, label, credential_id, public_material, private_blob, created_at, last_used_at
		 FROM credentials WHERE credential_id = ?`, credentialID)
	var c Credential
	var k string
	var created, used int64
	if err := row.Scan(&c.ID, &k, &c.Label, &c.CredentialID, &c.PublicMaterial, &c.PrivateBlob, &created, &used); err != nil {
		return Credential{}, err
	}
	c.Kind = CredentialKind(k)
	c.CreatedAt = time.Unix(created, 0)
	if used > 0 {
		c.LastUsedAt = time.Unix(used, 0)
	}
	return c, nil
}

// UpdateCredentialMaterial replaces the public_material blob for an
// existing credential. Used when go-webauthn returns an updated copy of
// the credential after login (e.g. with an incremented sign count).
func (s *Store) UpdateCredentialMaterial(ctx context.Context, id int64, material []byte) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE credentials SET public_material = ? WHERE id = ?`, material, id)
	return err
}
