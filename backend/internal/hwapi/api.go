// Package hwapi exposes bubble-hwd's HTTP surface. Endpoints (all JSON):
//
//	GET  /hw/led          — current LED state
//	POST /hw/led          — { state: "secured" | ... } set the LED
//	GET  /hw/buttons      — last button event + age (polling-friendly)
//
// The other daemons drive the LED based on their own state. Right now
// the SPA also has direct write access for the future Settings page
// "test the LED" flow; in production this might get gated to
// trusted-process callers only.
package hwapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/framefilter/bubbleui/backend/internal/buttons"
	"github.com/framefilter/bubbleui/backend/internal/led"
)

// Config bundles deps.
type Config struct {
	LED     led.Driver
	Buttons buttons.Reader
	Logger  *slog.Logger
}

// Server is the configured handler tree.
type Server struct {
	cfg    Config
	mux    *http.ServeMux
	logger *slog.Logger

	mu        sync.Mutex
	current   led.State
	lastEvent *buttons.Event
}

// New constructs a Server. The caller is responsible for keeping the
// LED state in sync via Render() — Server only mediates the HTTP
// surface. Server starts a goroutine that drains the buttons reader
// into its lastEvent state so polling clients can see what just
// happened.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{cfg: cfg, logger: cfg.Logger, mux: http.NewServeMux()}
	s.routes()
	if cfg.Buttons != nil {
		go s.drainButtons()
	}
	return s
}

// ServeHTTP makes Server an http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler().ServeHTTP(w, r)
}

// Set programmatically renders the LED to st and updates the tracked
// state so /hw/led GETs reflect it. The daemon main uses this for
// boot-time state (e.g. StateBooting) instead of poking the driver
// directly, which would leave the API's tracked state out of sync.
func (s *Server) Set(st led.State) error {
	if err := s.cfg.LED.Render(st); err != nil {
		return err
	}
	s.mu.Lock()
	s.current = st
	s.mu.Unlock()
	return nil
}

func (s *Server) handler() http.Handler {
	var h http.Handler = s.mux
	h = s.requestLogger(h)
	h = s.securityHeaders(h)
	return h
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /hw/led", s.handleGetLED)
	s.mux.HandleFunc("POST /hw/led", s.handleSetLED)
	s.mux.HandleFunc("GET /hw/buttons", s.handleGetButtons)
}

// drainButtons keeps Server.lastEvent fresh.
func (s *Server) drainButtons() {
	for ev := range s.cfg.Buttons.Events() {
		ev := ev
		s.mu.Lock()
		s.lastEvent = &ev
		s.mu.Unlock()
	}
}

func (s *Server) handleGetLED(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	cur := s.current
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"state": cur.String()})
}

type setLEDReq struct {
	State string `json:"state"`
}

func (s *Server) handleSetLED(w http.ResponseWriter, r *http.Request) {
	var req setLEDReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	st, err := led.ParseState(req.State)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.cfg.LED.Render(st); err != nil {
		s.logger.Error("led render", "err", err)
		writeError(w, http.StatusInternalServerError, "render failed")
		return
	}
	s.mu.Lock()
	s.current = st
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"state": st.String()})
}

func (s *Server) handleGetButtons(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	ev := s.lastEvent
	s.mu.Unlock()
	if ev == nil {
		writeJSON(w, http.StatusOK, map[string]any{"last_event": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"last_event": map[string]any{
			"button":  string(ev.Button),
			"kind":    ev.Kind.String(),
			"at":      ev.At.Unix(),
			"age_sec": int64(time.Since(ev.At).Seconds()),
		},
	})
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
		s.logger.Info("hwapi",
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

var _ http.Handler = (*Server)(nil)
