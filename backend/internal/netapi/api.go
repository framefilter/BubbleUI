// Package netapi exposes bubble-netd's HTTP surface. Endpoints (all JSON):
//
//	GET  /net/captive             — run a captive-portal probe and report
//	GET  /net/signin/status       — current sign-in window state
//	POST /net/signin/open         — open the §6.5 firewall hole {portal_ips, duration_sec?}
//	POST /net/signin/close        — close the window early
//	POST /net/signin/strict       — toggle strict mode {enabled: bool}
//
// Auth gating: same model as bubble-vpnd — this skeleton sits behind
// uhttpd in production; bind to 127.0.0.1 in dev/test.
package netapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/framefilter/bubbleui/backend/internal/captive"
	"github.com/framefilter/bubbleui/backend/internal/signin"
)

// Config bundles dependencies into Server.
type Config struct {
	Detector *captive.Detector
	Signin   *signin.Manager
	Logger   *slog.Logger
}

// Server implements http.Handler for /net/*.
type Server struct {
	cfg    Config
	mux    *http.ServeMux
	logger *slog.Logger
}

// New configures a Server.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Detector == nil {
		cfg.Detector = &captive.Detector{}
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
	s.mux.HandleFunc("GET /net/captive", s.handleCaptive)
	s.mux.HandleFunc("GET /net/signin/status", s.handleSigninStatus)
	s.mux.HandleFunc("POST /net/signin/open", s.handleSigninOpen)
	s.mux.HandleFunc("POST /net/signin/close", s.handleSigninClose)
	s.mux.HandleFunc("POST /net/signin/strict", s.handleSigninStrict)
}

func (s *Server) handleCaptive(w http.ResponseWriter, r *http.Request) {
	v := s.cfg.Detector.Detect(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"captive":      v.Captive,
		"portal_ips":   v.PortalIPs,
		"evidence_url": v.EvidenceURL,
	})
}

func (s *Server) handleSigninStatus(w http.ResponseWriter, _ *http.Request) {
	st := s.cfg.Signin.Status()
	body := map[string]any{
		"state":         st.State.String(),
		"strict_mode":   st.StrictMode,
		"allowed_ports": st.AllowedPorts,
	}
	if !st.OpenedAt.IsZero() {
		body["opened_at"] = st.OpenedAt.Unix()
	}
	if !st.Deadline.IsZero() {
		body["deadline"] = st.Deadline.Unix()
		body["remaining_sec"] = st.RemainingSec
	}
	if len(st.PortalIPs) > 0 {
		body["portal_ips"] = st.PortalIPs
	}
	writeJSON(w, http.StatusOK, body)
}

type openReq struct {
	PortalIPs   []string `json:"portal_ips"`
	DurationSec int64    `json:"duration_sec"`
}

func (s *Server) handleSigninOpen(w http.ResponseWriter, r *http.Request) {
	var req openReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	d := time.Duration(req.DurationSec) * time.Second
	err := s.cfg.Signin.Open(r.Context(), req.PortalIPs, d)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"status": "open"})
	case errors.Is(err, signin.ErrStrictMode):
		writeError(w, http.StatusForbidden, "strict mode")
	case errors.Is(err, signin.ErrAlreadyOpen):
		writeError(w, http.StatusConflict, "already open")
	case errors.Is(err, signin.ErrNoPortalIPs):
		writeError(w, http.StatusBadRequest, "portal_ips required")
	default:
		s.logger.Error("signin open", "err", err)
		writeError(w, http.StatusInternalServerError, "open failed")
	}
}

func (s *Server) handleSigninClose(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.Signin.Close(r.Context()); err != nil {
		s.logger.Error("signin close", "err", err)
		writeError(w, http.StatusInternalServerError, "close failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "closed"})
}

type strictReq struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleSigninStrict(w http.ResponseWriter, r *http.Request) {
	var req strictReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	s.cfg.Signin.SetStrict(req.Enabled)
	writeJSON(w, http.StatusOK, map[string]any{"strict_mode": req.Enabled})
}

// --- middleware (mirror of httpapi/vpnapi) ---

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
		s.logger.Info("netapi",
			"method", r.Method, "path", r.URL.Path,
			"status", ww.code, "dur_ms", time.Since(start).Milliseconds(),
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

// nopContext keeps the import honest for older Go-vet versions; remove
// once we have a handler that explicitly uses context.Context.
var _ = context.Background

// Ensure compile-time http.Handler conformance.
var _ http.Handler = (*Server)(nil)
