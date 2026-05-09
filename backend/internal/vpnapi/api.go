// Package vpnapi exposes bubble-vpnd's HTTP surface. The SPA's /vpn
// route consumes these endpoints (DESIGN.md §6.2 / §11.5).
//
// Auth gating: this skeleton does not validate sessions itself. In
// production these endpoints sit behind uhttpd's reverse proxy, which
// enforces a valid bubble-session cookie via bubble-authd. Direct
// requests to bubble-vpnd over the LAN should be considered trusted-
// process-only; on the router it listens on 127.0.0.1.
//
// Endpoints (all JSON):
//
//	GET    /vpn/configs                — list pool, with last-probe metadata
//	POST   /vpn/configs                — import a new .conf {label, raw}
//	DELETE /vpn/configs/{id}           — remove
//	POST   /vpn/configs/{id}/enabled   — { enabled: bool }
//	POST   /vpn/probe                  — run a one-shot probe over enabled rows
//	POST   /vpn/connect                — { id?: int, strategy?: "fastest" }
//	POST   /vpn/disconnect             — bring tunnel down
//	GET    /vpn/status                 — current daemon state
package vpnapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/framefilter/bubbleui/backend/internal/prober"
	"github.com/framefilter/bubbleui/backend/internal/selector"
	"github.com/framefilter/bubbleui/backend/internal/wgpool"
)

// Connector is the indirection over actual `wg-quick up/down` calls.
// On the router it shells out to wg-quick; in dev / tests a stub
// implementation simply records what it was asked to do.
type Connector interface {
	Connect(ctx context.Context, c wgpool.Config) error
	Disconnect(ctx context.Context) error
	// Active returns the currently-connected config ID, or 0 if none.
	Active() int64
}

// Config bundles dependencies into Server.
type Config struct {
	Pool      *wgpool.Pool
	Connector Connector
	Logger    *slog.Logger
	Probe     prober.Config // probe defaults applied to every /vpn/probe call
}

// Server implements http.Handler for the /vpn surface.
type Server struct {
	cfg    Config
	mux    *http.ServeMux
	logger *slog.Logger

	mu        sync.Mutex
	lastProbe []prober.Result // cached for /vpn/connect's "fastest" strategy
}

// New builds a configured Server.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{cfg: cfg, logger: cfg.Logger, mux: http.NewServeMux()}
	s.routes()
	return s
}

// ServeHTTP makes Server an http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler().ServeHTTP(w, r)
}

func (s *Server) handler() http.Handler {
	var h http.Handler = s.mux
	h = s.requestLogger(h)
	h = s.securityHeaders(h)
	return h
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /vpn/configs", s.handleList)
	s.mux.HandleFunc("POST /vpn/configs", s.handleImport)
	s.mux.HandleFunc("DELETE /vpn/configs/{id}", s.handleDelete)
	s.mux.HandleFunc("POST /vpn/configs/{id}/enabled", s.handleSetEnabled)
	s.mux.HandleFunc("POST /vpn/probe", s.handleProbe)
	s.mux.HandleFunc("POST /vpn/connect", s.handleConnect)
	s.mux.HandleFunc("POST /vpn/disconnect", s.handleDisconnect)
	s.mux.HandleFunc("GET /vpn/status", s.handleStatus)
}

// --- handlers ---

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	configs, err := s.cfg.Pool.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configs": serializeConfigs(configs)})
}

type importRequest struct {
	Label string `json:"label"`
	Raw   string `json:"raw"`
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	if strings.TrimSpace(req.Raw) == "" {
		writeError(w, http.StatusBadRequest, "raw config required")
		return
	}
	id, err := s.cfg.Pool.Add(r.Context(), strings.TrimSpace(req.Label), req.Raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.cfg.Pool.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

type setEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleSetEnabled(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req setEnabledRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := s.cfg.Pool.SetEnabled(r.Context(), id, req.Enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	configs, err := s.cfg.Pool.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	candidates := make([]prober.Candidate, 0, len(configs))
	for _, c := range configs {
		if !c.Enabled {
			continue
		}
		candidates = append(candidates, prober.Candidate{ID: c.ID, Host: c.EndpointHost, Port: c.EndpointPort})
	}
	results := prober.Probe(r.Context(), candidates, s.cfg.Probe)

	// Persist outcomes for staleness UI; note that disabled configs were
	// excluded from the candidate list so we don't trample their state.
	for _, res := range results {
		errStr := ""
		if res.Err != nil {
			errStr = res.Err.Error()
		}
		_ = s.cfg.Pool.RecordProbe(r.Context(), res.ID, res.RTT, errStr)
	}

	s.mu.Lock()
	s.lastProbe = results
	s.mu.Unlock()

	// Re-fetch so the response reflects the freshly-persisted last_probe_*.
	configs, _ = s.cfg.Pool.List(r.Context())
	ranked := selector.Rank(configs, results)
	writeJSON(w, http.StatusOK, map[string]any{
		"ranked":  serializeRanked(ranked),
		"probed":  len(candidates),
		"skipped": len(configs) - len(candidates),
	})
}

type connectRequest struct {
	ID       int64  `json:"id"`
	Strategy string `json:"strategy"` // "fastest" or "" (manual via id)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req connectRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // empty body allowed

	var target wgpool.Config
	switch {
	case req.Strategy == "fastest" || (req.ID == 0 && req.Strategy == ""):
		// Use cached probe if recent; otherwise probe inline.
		s.mu.Lock()
		results := s.lastProbe
		s.mu.Unlock()
		if len(results) == 0 {
			s.handleProbe(noopWriter{}, r) // populate cache
			s.mu.Lock()
			results = s.lastProbe
			s.mu.Unlock()
		}
		configs, err := s.cfg.Pool.List(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list failed")
			return
		}
		best, err := selector.Best(configs, results)
		if err != nil {
			writeError(w, http.StatusBadRequest, "no usable candidate; import or enable a config first")
			return
		}
		target = best.Config

	default:
		c, err := s.cfg.Pool.Get(r.Context(), req.ID)
		if err != nil {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		target = c
	}

	if err := s.cfg.Connector.Connect(r.Context(), target); err != nil {
		s.logger.Error("connect failed", "id", target.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "connect failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "connected",
		"id":       target.ID,
		"label":    target.Label,
		"endpoint": fmt.Sprintf("%s:%d", target.EndpointHost, target.EndpointPort),
	})
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.Connector.Disconnect(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "disconnect failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "disconnected"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	active := s.cfg.Connector.Active()
	body := map[string]any{"active_id": active}
	if active != 0 {
		c, err := s.cfg.Pool.Get(r.Context(), active)
		if err == nil {
			body["label"] = c.Label
			body["endpoint"] = fmt.Sprintf("%s:%d", c.EndpointHost, c.EndpointPort)
		}
	}
	writeJSON(w, http.StatusOK, body)
}

// --- middleware ---

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &statusWriter{ResponseWriter: w, code: 200}
		next.ServeHTTP(ww, r)
		s.logger.Info("vpnapi",
			"method", r.Method, "path", r.URL.Path,
			"status", ww.code, "dur_ms", time.Since(start).Milliseconds(),
		)
	})
}

// --- helpers ---

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

// noopWriter swallows writes during the inline-probe call from
// handleConnect — we just want the side effects (cache populated +
// last_probe_* persisted), not the response body.
type noopWriter struct{}

func (noopWriter) Header() http.Header         { return http.Header{} }
func (noopWriter) Write(b []byte) (int, error) { return len(b), nil }
func (noopWriter) WriteHeader(int)             {}

func parseID(r *http.Request) (int64, bool) {
	s := r.PathValue("id")
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func serializeConfigs(in []wgpool.Config) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, c := range in {
		out = append(out, configToJSON(c))
	}
	return out
}

func serializeRanked(in []selector.Ranked) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, r := range in {
		row := configToJSON(r.Config)
		if r.Result.Err != nil {
			row["probe_err"] = r.Result.Err.Error()
		} else if r.Result.RTT > 0 {
			row["probe_rtt_ms"] = r.Result.RTT.Milliseconds()
		}
		out = append(out, row)
	}
	return out
}

func configToJSON(c wgpool.Config) map[string]any {
	m := map[string]any{
		"id":            c.ID,
		"label":         c.Label,
		"endpoint":      fmt.Sprintf("%s:%d", c.EndpointHost, c.EndpointPort),
		"endpoint_host": c.EndpointHost,
		"endpoint_port": c.EndpointPort,
		"enabled":       c.Enabled,
		"created_at":    c.CreatedAt.Unix(),
	}
	if !c.LastProbeAt.IsZero() {
		m["last_probe_at"] = c.LastProbeAt.Unix()
	}
	if c.LastProbeRTT > 0 {
		m["last_probe_rtt_ms"] = c.LastProbeRTT.Milliseconds()
	}
	if c.LastProbeErr != "" {
		m["last_probe_err"] = c.LastProbeErr
	}
	if !c.LastHandshake.IsZero() {
		m["last_handshake_at"] = c.LastHandshake.Unix()
	}
	return m
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

// Ensure compile-time that *Server satisfies http.Handler.
var _ http.Handler = (*Server)(nil)
