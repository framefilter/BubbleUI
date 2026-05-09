// Package httpapi exposes the auth daemon's flows over HTTP for the SPA
// to consume. M2 PoC was CLI-only; this is the bridge to M3.
//
// Routing surface (all paths return JSON):
//
//	POST /auth/yubikey/login    — run §5.3 YubiKey login, mint a session
//	POST /auth/recover          — run §5.4 recovery; wipes credentials
//	GET  /auth/session/whoami   — return the current session, if any
//	POST /auth/session/logout   — revoke the current session
//	POST /api/time/sync         — accept browser-supplied time per §6.6
//
// Cookies: bubble-session, HttpOnly, SameSite=Strict, Secure (when TLS),
// Path=/. CSRF defense is layered: SameSite=Strict + an Origin allowlist.
package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/framefilter/bubbleui/backend/internal/auth"
	"github.com/framefilter/bubbleui/backend/internal/session"
)

// Config controls Server construction.
type Config struct {
	// Auth is the authenticator wired with a store + yubikey oracle.
	Auth *auth.Authenticator

	// Sessions is the session manager backed by the same SQLite DB.
	Sessions *session.Manager

	// AllowedOrigins is the set of Origin header values accepted on
	// state-changing requests. Typically the LAN-side scheme+host(+port)
	// the SPA loads from. Empty disables Origin checking — only safe for
	// tests.
	AllowedOrigins []string

	// Logger is the structured logger used for request logging.
	// Defaults to slog.Default() when nil.
	Logger *slog.Logger

	// Insecure controls whether session cookies omit the Secure flag.
	// Set true only for plain-HTTP development.
	Insecure bool

	// Now overrides the time source for the time-sync endpoint. Defaults
	// to time.Now.
	Now func() time.Time

	// SetSystemTime is invoked by /api/time/sync after validating a
	// browser-supplied timestamp. Production wiring on OpenWRT calls
	// settimeofday(2) via a tiny shell-out. Tests inject a stub.
	SetSystemTime func(t time.Time) error
}

// Server is the configured HTTP handler tree.
type Server struct {
	cfg    Config
	mux    *http.ServeMux
	logger *slog.Logger
}

// New returns a Server ready to be passed to http.Server.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
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
	h = s.originCheck(h)
	h = s.securityHeaders(h)
	return h
}

func (s *Server) routes() {
	s.mux.HandleFunc("POST /auth/yubikey/login", s.handleYubiKeyLogin)
	s.mux.HandleFunc("POST /auth/recover", s.handleRecover)
	s.mux.HandleFunc("GET /auth/session/whoami", s.handleWhoami)
	s.mux.HandleFunc("POST /auth/session/logout", s.handleLogout)
	s.mux.HandleFunc("POST /api/time/sync", s.handleTimeSync)
}

// --- handlers ---

func (s *Server) handleYubiKeyLogin(w http.ResponseWriter, r *http.Request) {
	credID, err := s.cfg.Auth.LoginYubiKey(r.Context())
	if err != nil {
		// Don't differentiate ErrNoCredential / ErrChallengeFail to clients —
		// every failure is "rejected."
		writeError(w, http.StatusUnauthorized, "rejected")
		return
	}
	token, sess, err := s.cfg.Sessions.Create(r.Context(), credID)
	if err != nil {
		s.logger.Error("session create failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.setSessionCookie(w, token, sess.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{
		"credential_id": credID,
		"expires_at":    sess.ExpiresAt.Unix(),
	})
}

type recoverRequest struct {
	Code string `json:"code"`
}

func (s *Server) handleRecover(w http.ResponseWriter, r *http.Request) {
	var req recoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	if strings.TrimSpace(req.Code) == "" {
		writeError(w, http.StatusBadRequest, "code required")
		return
	}
	if err := s.cfg.Auth.Recover(r.Context(), req.Code); err != nil {
		writeError(w, http.StatusUnauthorized, "rejected")
		return
	}
	// Invalidate every session — anything that might have been live before
	// the recovery is now considered compromised.
	if err := s.cfg.Sessions.RevokeAll(r.Context()); err != nil {
		s.logger.Error("revoke all failed", "err", err)
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"status": "wiped"})
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	sess, ok := sessionFromRequest(r, s.cfg.Sessions)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"credential_id": sess.CredentialID,
		"expires_at":    sess.ExpiresAt.Unix(),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(session.CookieName)
	if err == nil && c.Value != "" {
		_ = s.cfg.Sessions.Revoke(r.Context(), c.Value)
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

type timeSyncRequest struct {
	Now   int64 `json:"now"`   // milliseconds since epoch (Date.now())
	Force bool  `json:"force"` // user has acknowledged the skew and wants to apply
}

// handleTimeSync implements §6.6's browser-supplied-time bootstrap.
//
// Behavior:
//   - within ±5 min of router clock: silently accept; no action.
//   - outside tolerance, force=false: report the skew (action="skew_detected")
//     so the SPA can show a confirmation prompt. Clock is unchanged.
//   - outside tolerance, force=true: apply (action="applied"). If the
//     daemon has no SetSystemTime hook configured, return "skew_unhandled"
//     and 503 — the daemon is running in a mode that can't change the clock.
func (s *Server) handleTimeSync(w http.ResponseWriter, r *http.Request) {
	var req timeSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Now <= 0 {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	browserTime := time.UnixMilli(req.Now)
	routerTime := s.cfg.Now()
	delta := browserTime.Sub(routerTime)

	const tol = 5 * time.Minute
	respond := func(action string, applied bool) {
		body := map[string]any{
			"status":       "ok",
			"action":       action,
			"router_time":  routerTime.UnixMilli(),
			"browser_time": browserTime.UnixMilli(),
			"delta_ms":     delta.Milliseconds(),
		}
		if applied {
			body["router_time"] = browserTime.UnixMilli()
		}
		writeJSON(w, http.StatusOK, body)
	}

	if delta > -tol && delta < tol {
		respond("accepted", false)
		return
	}
	if !req.Force {
		respond("skew_detected", false)
		return
	}
	if s.cfg.SetSystemTime == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status":       "unhandled",
			"action":       "skew_unhandled",
			"reason":       "daemon was started without permission to set the system clock",
			"router_time":  routerTime.UnixMilli(),
			"browser_time": browserTime.UnixMilli(),
			"delta_ms":     delta.Milliseconds(),
		})
		return
	}
	if err := s.cfg.SetSystemTime(browserTime); err != nil {
		s.logger.Error("set system time failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	respond("applied", true)
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

func (s *Server) originCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe methods don't change state; skip origin check.
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if len(s.cfg.AllowedOrigins) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		origin := r.Header.Get("Origin")
		if origin == "" {
			// Allow same-origin requests where browser omitted Origin
			// (e.g. some POST forms). The SPA always sends Origin from
			// fetch().
			next.ServeHTTP(w, r)
			return
		}
		for _, allowed := range s.cfg.AllowedOrigins {
			if origin == allowed {
				next.ServeHTTP(w, r)
				return
			}
		}
		writeError(w, http.StatusForbidden, "origin not allowed")
	})
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &statusWriter{ResponseWriter: w, code: 200}
		next.ServeHTTP(ww, r)
		s.logger.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.code,
			"dur_ms", time.Since(start).Milliseconds(),
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

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     session.CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.cfg.Insecure,
		SameSite: http.SameSiteStrictMode,
		Expires:  expires,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     session.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.cfg.Insecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func sessionFromRequest(r *http.Request, m *session.Manager) (*session.Session, bool) {
	c, err := r.Cookie(session.CookieName)
	if err != nil || c.Value == "" {
		return nil, false
	}
	sess, err := m.Validate(r.Context(), c.Value)
	if err != nil {
		if errors.Is(err, session.ErrInvalidToken) || errors.Is(err, session.ErrExpired) {
			return nil, false
		}
		return nil, false
	}
	return sess, true
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