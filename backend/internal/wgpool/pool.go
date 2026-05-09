// Package wgpool persists the user's collection of WireGuard configs and
// the metadata bubble-vpnd needs to probe and rank them. Per DESIGN.md
// §6.2/§11.5 (v1.0 VPN strategy: pool of saved configs with active
// TCP-connect probing), this is the storage tier; probing lives in
// internal/prober and selection in internal/selector.
package wgpool

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Config is a single WireGuard endpoint in the user's pool.
type Config struct {
	ID            int64
	Label         string
	RawConfig     string
	EndpointHost  string
	EndpointPort  int
	Enabled       bool
	CreatedAt     time.Time
	LastProbeAt   time.Time     // zero if never probed
	LastProbeRTT  time.Duration // zero if never probed or last probe failed
	LastProbeErr  string        // empty if last probe succeeded
	LastHandshake time.Time     // zero if no handshake recorded
}

// Pool wraps the SQLite-backed collection of configs.
type Pool struct {
	db *sql.DB
}

// Open opens or creates the pool DB at path and applies the schema.
func Open(ctx context.Context, path string) (*Pool, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("wgpool: open: %w", err)
	}
	p := &Pool{db: db}
	if err := p.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return p, nil
}

// Close releases the database handle.
func (p *Pool) Close() error { return p.db.Close() }

func (p *Pool) migrate(ctx context.Context) error {
	stmt := `CREATE TABLE IF NOT EXISTS wg_configs (
		id                 INTEGER PRIMARY KEY AUTOINCREMENT,
		label              TEXT    NOT NULL,
		raw_config         TEXT    NOT NULL,
		endpoint_host      TEXT    NOT NULL,
		endpoint_port      INTEGER NOT NULL,
		enabled            INTEGER NOT NULL DEFAULT 1,
		created_at         INTEGER NOT NULL,
		last_probe_at      INTEGER NOT NULL DEFAULT 0,
		last_probe_rtt_us  INTEGER NOT NULL DEFAULT 0,
		last_probe_err     TEXT    NOT NULL DEFAULT '',
		last_handshake_at  INTEGER NOT NULL DEFAULT 0
	)`
	if _, err := p.db.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("wgpool: migrate: %w", err)
	}
	return nil
}

// Add parses raw and inserts a new config row. Returns the assigned ID.
func (p *Pool) Add(ctx context.Context, label, raw string) (int64, error) {
	host, port, err := ParseEndpoint(raw)
	if err != nil {
		return 0, fmt.Errorf("wgpool: parse endpoint: %w", err)
	}
	if label == "" {
		label = fmt.Sprintf("%s:%d", host, port)
	}
	res, err := p.db.ExecContext(ctx,
		`INSERT INTO wg_configs(label, raw_config, endpoint_host, endpoint_port, enabled, created_at)
		 VALUES (?, ?, ?, ?, 1, ?)`,
		label, raw, host, port, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("wgpool: insert: %w", err)
	}
	return res.LastInsertId()
}

// List returns every config in insertion order.
func (p *Pool) List(ctx context.Context) ([]Config, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT id, label, raw_config, endpoint_host, endpoint_port, enabled, created_at,
		        last_probe_at, last_probe_rtt_us, last_probe_err, last_handshake_at
		 FROM wg_configs ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Config
	for rows.Next() {
		c, err := scanConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Get returns one config by ID, or sql.ErrNoRows.
func (p *Pool) Get(ctx context.Context, id int64) (Config, error) {
	row := p.db.QueryRowContext(ctx,
		`SELECT id, label, raw_config, endpoint_host, endpoint_port, enabled, created_at,
		        last_probe_at, last_probe_rtt_us, last_probe_err, last_handshake_at
		 FROM wg_configs WHERE id = ?`, id)
	return scanConfig(row)
}

// Delete removes a config row. No-op if it doesn't exist.
func (p *Pool) Delete(ctx context.Context, id int64) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM wg_configs WHERE id = ?`, id)
	return err
}

// SetEnabled flips the enabled flag.
func (p *Pool) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	res, err := p.db.ExecContext(ctx, `UPDATE wg_configs SET enabled = ? WHERE id = ?`, v, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// RecordProbe persists the latest probe outcome for a config. probeErr
// should be empty on success; rtt is only meaningful when probeErr is
// empty.
func (p *Pool) RecordProbe(ctx context.Context, id int64, rtt time.Duration, probeErr string) error {
	rttUS := int64(rtt / time.Microsecond)
	if probeErr != "" {
		rttUS = 0
	}
	_, err := p.db.ExecContext(ctx,
		`UPDATE wg_configs SET last_probe_at = ?, last_probe_rtt_us = ?, last_probe_err = ? WHERE id = ?`,
		time.Now().Unix(), rttUS, probeErr, id)
	return err
}

// MarkHandshake records that a successful WireGuard handshake just
// occurred. Used by the staleness UI; not a tunnel-state-of-truth.
func (p *Pool) MarkHandshake(ctx context.Context, id int64) error {
	_, err := p.db.ExecContext(ctx,
		`UPDATE wg_configs SET last_handshake_at = ? WHERE id = ?`, time.Now().Unix(), id)
	return err
}

// scanConfig is shared between List and Get. The row interface lets us
// pass either a *sql.Rows or a *sql.Row.
type scanner interface {
	Scan(dest ...any) error
}

func scanConfig(s scanner) (Config, error) {
	var c Config
	var enabled, created, probeAt, rttUS, handshakeAt int64
	if err := s.Scan(&c.ID, &c.Label, &c.RawConfig, &c.EndpointHost, &c.EndpointPort,
		&enabled, &created, &probeAt, &rttUS, &c.LastProbeErr, &handshakeAt); err != nil {
		return Config{}, err
	}
	c.Enabled = enabled != 0
	c.CreatedAt = time.Unix(created, 0)
	if probeAt > 0 {
		c.LastProbeAt = time.Unix(probeAt, 0)
	}
	if rttUS > 0 {
		c.LastProbeRTT = time.Duration(rttUS) * time.Microsecond
	}
	if handshakeAt > 0 {
		c.LastHandshake = time.Unix(handshakeAt, 0)
	}
	return c, nil
}

// ParseEndpoint extracts the Endpoint = host:port line from a WireGuard
// config and returns the host and port. The first [Peer] section's
// Endpoint wins; later sections (multi-peer configs) are ignored — we
// don't support those in v1.0.
func ParseEndpoint(raw string) (host string, port int, err error) {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	inPeer := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inPeer = strings.EqualFold(line, "[Peer]")
			continue
		}
		if !inPeer {
			continue
		}
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		if !strings.EqualFold(k, "Endpoint") {
			continue
		}
		colon := strings.LastIndex(v, ":")
		if colon < 0 {
			return "", 0, errors.New("wgpool: Endpoint missing :port")
		}
		hostPart := v[:colon]
		portPart := v[colon+1:]
		// Strip [] from IPv6 literals.
		hostPart = strings.TrimPrefix(strings.TrimSuffix(hostPart, "]"), "[")
		p, err := strconv.Atoi(portPart)
		if err != nil || p <= 0 || p > 65535 {
			return "", 0, fmt.Errorf("wgpool: bad port %q", portPart)
		}
		return hostPart, p, nil
	}
	if err := scanner.Err(); err != nil {
		return "", 0, err
	}
	return "", 0, errors.New("wgpool: no [Peer] Endpoint = found in config")
}

func splitKV(line string) (key, value string, ok bool) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:eq]), strings.TrimSpace(line[eq+1:]), true
}
