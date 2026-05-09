// Package httpapi exposes the auth daemon's flows over HTTP for the SPA
// to consume. M2 PoC was CLI-only; this is the bridge to M3.
//
// Routing surface (all paths return JSON):
//
//	POST /auth/yubikey/provision            — first-boot wizard: program slot 2
//	POST /auth/yubikey/login                — run §5.3 YubiKey login
//	POST /auth/webauthn/register/begin      — start a WebAuthn registration
//	POST /auth/webauthn/register/finish     — finish registration, persist
//	POST /auth/webauthn/login/begin         — start a WebAuthn login
//	POST /auth/webauthn/login/finish        — finish login, mint session
//	POST /auth/recover                      — run §5.4 recovery
//	GET  /auth/session/whoami               — current session, if any
//	POST /auth/session/logout               — revoke the current session
//	GET  /auth/setup-status                 — has-any-credential gate for the wizard
//	GET  /auth/health                       — credential + YubiKey-present (composer feed)
//	POST /api/time/sync                     — browser-supplied time per §6.6
//
// Cookies: bubble-session, HttpOnly, SameSite=Strict, Secure (when TLS),
// Path=/. CSRF defense is layered: SameSite=Strict + an Origin allowlist.
//
// WebAuthn registration is "auth-required unless no credentials exist
// yet" — bootstrap mode lets the wizard register the first credential
// without a session, after which adding more credentials requires being
// logged in.
package httpapi

import (
	"encoding/hex"
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
	s.mux.HandleFunc("POST /auth/yubikey/provision", s.handleYubiKeyProvision)
	s.mux.HandleFunc("POST /auth/yubikey/login", s.handleYubiKeyLogin)
	s.mux.HandleFunc("POST /auth/webauthn/register/begin", s.handleWebAuthnRegisterBegin)
	s.mux.HandleFunc("POST /auth/webauthn/register/finish", s.handleWebAuthnRegisterFinish)
	s.mux.HandleFunc("POST /auth/webauthn/login/begin", s.handleWebAuthnLoginBegin)
	s.mux.HandleFunc("POST /auth/webauthn/login/finish", s.handleWebAuthnLoginFinish)
	s.mux.HandleFunc("POST /auth/recover", s.handleRecover)
	s.mux.HandleFunc("GET /auth/session/whoami", s.handleWhoami)
	s.mux.HandleFunc("POST /auth/session/logout", s.handleLogout)
	s.mux.HandleFunc("GET /auth/setup-status", s.handleSetupStatus)
	s.mux.HandleFunc("GET /auth/health", s.handleHealth)
	s.mux.HandleFunc("POST /api/time/sync", s.handleTimeSync)
}

// --- handlers ---

// handleYubiKeyProvision is the wizard's "program this YubiKey on the
// router USB" endpoint. Bootstrap-only: rejects with 409 if any
// credential is already registered, so it can never be used to overwrite
// an existing setup. Returns the recovery code, the slot-2 secret hex
// (in case ykman programming fails and the user has to copy-paste a
// command), and a flag indicating whether ykman ran successfully.
func (s *Server) handleYubiKeyProvision(w http.ResponseWriter, r *http.Request) {
	has, err := s.cfg.Auth.HasAnyCredential(r.Context())
	if err != nil {
		s.logger.Error("HasAnyCredential", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if has {
		writeError(w, http.StatusConflict, "device is already provisioned; use /auth/recover to reset")
		return
	}
	res, err := s.cfg.Auth.ProvisionYubiKeyAndProgram(r.Context(), "")
	if err != nil {
		s.logger.Error("provision yubikey", "err", err)
		writeError(w, http.StatusInternalServerError, "provision failed")
		return
	}
	body := map[string]any{
		"credential_id":  res.CredentialID,
		"recovery_code":  res.RecoveryCode,
		"not_programmed": res.NotProgrammed,
	}
	if res.NotProgrammed {
		// Surface the secret hex only when the daemon couldn't program
		// the key automatically — the user needs it to run ykman manually.
		body["secret_hex"] = hexEncode(res.Secret)
		body["program_hint"] = res.ProgramHint
	}
	writeJSON(w, http.StatusOK, body)
}

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

// --- WebAuthn handlers ---

type webAuthnFinishRequest struct {
	Handle   string          `json:"handle"`
	Response json.RawMessage `json:"response"`
	Label    string          `json:"label"` // optional; ignored on login
}

type webAuthnBeginResponse struct {
	Handle  string          `json:"handle"`
	Options json.RawMessage `json:"options"`
}

func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if !s.requireBootstrapOrSession(w, r) {
		return
	}
	handle, options, err := s.cfg.Auth.BeginRegisterWebAuthn(r.Context())
	if err != nil {
		s.logger.Error("webauthn begin register", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, webAuthnBeginResponse{Handle: handle, Options: options})
}

func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if !s.requireBootstrapOrSession(w, r) {
		return
	}
	var req webAuthnFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Handle == "" || len(req.Response) == 0 {
		writeError(w, http.StatusBadRequest, "handle and response required")
		return
	}
	reg, err := s.cfg.Auth.FinishRegisterWebAuthn(r.Context(), req.Label, req.Handle, req.Response)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "rejected")
		return
	}
	body := map[string]any{"credential_id": reg.CredentialID}
	if reg.RecoveryCode != "" {
		// First credential on this device — surface the recovery code
		// once. Caller MUST display this to the user and never store it.
		body["recovery_code"] = reg.RecoveryCode
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	handle, options, err := s.cfg.Auth.BeginLoginWebAuthn(r.Context())
	if err != nil {
		// Treat "no credential of that kind" the same as "rejected" — we
		// don't want to advertise whether any WebAuthn credentials exist.
		writeError(w, http.StatusUnauthorized, "rejected")
		return
	}
	writeJSON(w, http.StatusOK, webAuthnBeginResponse{Handle: handle, Options: options})
}

func (s *Server) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req webAuthnFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Handle == "" || len(req.Response) == 0 {
		writeError(w, http.StatusBadRequest, "handle and response required")
		return
	}
	credID, err := s.cfg.Auth.FinishLoginWebAuthn(r.Context(), req.Handle, req.Response)
	if err != nil {
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

// requireBootstrapOrSession allows the request if either no credentials
// have been registered yet (first-boot wizard) OR the request carries a
// valid session. Writes a 401 and returns false on rejection.
func (s *Server) requireBootstrapOrSession(w http.ResponseWriter, r *http.Request) bool {
	has, err := s.cfg.Auth.HasAnyCredential(r.Context())
	if err != nil {
		s.logger.Error("HasAnyCredential", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return false
	}
	if !has {
		return true
	}
	if _, ok := sessionFromRequest(r, s.cfg.Sessions); ok {
		return true
	}
	writeError(w, http.StatusUnauthorized, "auth required")
	return false
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

// handleSetupStatus returns whether the device has at least one
// credential registered. The SPA uses this on first load to decide
// between the wizard and the login screen. Reachable without auth
// because there is no auth to gate it on when the device is fresh,
// and the answer leaks nothing useful — anyone can probe an unprovisioned
// device by simply trying to log in.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	has, err := s.cfg.Auth.HasAnyCredential(r.Context())
	if err != nil {
		s.logger.Error("HasAnyCredential", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"has_credentials": has,
	})
}

// handleHealth reports the live state of the auth daemon's
// dependencies. Today that's just "is a YubiKey currently visible to
// the router-side oracle?" which the bubble-hwd composer uses to
// drive the §13.5 NoKey LED state. Reachable without auth: the
// answer is non-secret (an attacker on the LAN can probe the USB
// state by trying to log in anyway) and bubble-hwd has no session
// to present.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	hasCred, err := s.cfg.Auth.HasAnyCredential(r.Context())
	if err != nil {
		s.logger.Error("HasAnyCredential", "err", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	// "yubikey_present" is meaningful only when a YubiKey credential
	// is registered AND the oracle is the live ykchalresp adapter
	// (Mock always reports present for whatever it has plugged in).
	yubiPresent := s.cfg.Auth.Yubi != nil && s.cfg.Auth.Yubi.Present(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"has_credentials": hasCred,
		"yubikey_present": yubiPresent,
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

func hexEncode(b []byte) string { return hex.EncodeToString(b) }

// Ensure compile-time that *Server satisfies http.Handler.
var _ http.Handler = (*Server)(nil)
