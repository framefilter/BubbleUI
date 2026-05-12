// bubble-authd is BubbleUI's authentication daemon. CLI verbs cover
// the administrative paths that don't need a browser; `serve` exposes
// the WebAuthn ceremony + session endpoints over HTTP for the SPA.
//
// The ubus integration on top of this is M3 territory; for now the
// daemon listens on plain HTTP behind uhttpd's TLS termination, or on
// HTTPS directly when started with -tls-cert/-tls-key.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/framefilter/bubbleui/backend/internal/auth"
	"github.com/framefilter/bubbleui/backend/internal/httpapi"
	"github.com/framefilter/bubbleui/backend/internal/session"
	"github.com/framefilter/bubbleui/backend/internal/store"
	"github.com/framefilter/bubbleui/backend/internal/webauthn"
)

const usage = `bubble-authd — BubbleUI auth daemon

usage: bubble-authd [-db PATH] <command> [args]

Commands:
  recover <code>      Burn the recovery code and wipe credentials.
  status              Show registered credentials.
  serve [-listen ADDR] [-allowed-origin URL] [-insecure] [-rp-id HOST]
                      Run the HTTP server. Defaults to 127.0.0.1:8765,
                      cookies marked Secure, no Origin allowlist.
                      Pass -rp-id to enable WebAuthn (matches the
                      hostname the SPA is loaded from, no scheme/port).
  -h, --help          Show this help.

Flags:
  -db   PATH   credentials.db path (default: $XDG_STATE_HOME/bubbleui/credentials.db
               or ~/.local/state/bubbleui/credentials.db)

Hardware-key auth runs through WebAuthn (FIDO2) only. Register and log in
from a browser pointed at the SPA; there is no router-side hardware-key
flow in this build.
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bubble-authd:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dbPath   string
		showHelp bool
	)
	flag.StringVar(&dbPath, "db", "", "credentials.db path")
	flag.BoolVar(&showHelp, "help", false, "show help")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if showHelp || flag.NArg() == 0 {
		fmt.Fprint(os.Stdout, usage)
		return nil
	}

	if dbPath == "" {
		var err error
		dbPath, err = defaultDBPath()
		if err != nil {
			return err
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := os.MkdirAll(dirOf(dbPath), 0o700); err != nil {
		return fmt.Errorf("create db dir: %w", err)
	}
	s, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()

	a := auth.New(s)

	cmd := flag.Arg(0)
	args := flag.Args()[1:]
	switch cmd {
	case "recover":
		if len(args) == 0 {
			return errors.New("recover requires the recovery code as argument")
		}
		return cmdRecover(ctx, a, strings.Join(args, " "))
	case "status":
		return cmdStatus(ctx, s)
	case "serve":
		return cmdServe(ctx, a, s, args)
	default:
		return fmt.Errorf("unknown command %q (try -h)", cmd)
	}
}

func cmdRecover(ctx context.Context, a *auth.Authenticator, code string) error {
	if err := a.Recover(ctx, code); err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	fmt.Println("OK: recovery code burned, all credentials wiped. Re-provision required.")
	return nil
}

func cmdStatus(ctx context.Context, s *store.Store) error {
	creds, err := s.ListCredentials(ctx)
	if err != nil {
		return err
	}
	if len(creds) == 0 {
		fmt.Println("No credentials registered.")
		return nil
	}
	fmt.Printf("%d credential(s) registered:\n", len(creds))
	for _, c := range creds {
		used := "never"
		if !c.LastUsedAt.IsZero() {
			used = c.LastUsedAt.Format("2006-01-02 15:04:05")
		}
		fmt.Printf("  id=%d kind=%s label=%q created=%s last_used=%s\n",
			c.ID, c.Kind, c.Label, c.CreatedAt.Format("2006-01-02 15:04:05"), used)
	}
	return nil
}

func cmdServe(ctx context.Context, a *auth.Authenticator, s *store.Store, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8765", "address to listen on")
	tlsCert := fs.String("tls-cert", "", "path to TLS cert (omit for plain HTTP behind uhttpd)")
	tlsKey := fs.String("tls-key", "", "path to TLS key")
	insecure := fs.Bool("insecure", false, "drop the Secure flag from session cookies (plain HTTP only)")
	originList := fs.String("allowed-origin", "", "comma-separated Origin allowlist; empty = no check")
	allowSetTime := fs.Bool("allow-set-time", false, "allow /api/time/sync with force=true to actually call date -s; without this flag, time-sync only reports skew")
	rpID := fs.String("rp-id", "", "WebAuthn relying party ID (hostname without scheme/port). Empty disables WebAuthn endpoints.")
	rpName := fs.String("rp-name", "BubbleUI", "WebAuthn relying party display name")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mgr, err := session.NewManager(ctx, s.DB())
	if err != nil {
		return fmt.Errorf("session manager: %w", err)
	}

	// Configure WebAuthn if -rp-id was provided. WebAuthn requires at
	// least one origin to be allowed; if -allowed-origin wasn't passed,
	// derive a sensible default from the RP ID (https in normal mode,
	// http in -insecure mode).
	if *rpID != "" {
		origins := splitNonEmpty(*originList)
		if len(origins) == 0 {
			scheme := "https"
			if *insecure || *tlsCert == "" {
				scheme = "http"
			}
			origins = []string{scheme + "://" + *rpID}
		}
		eng, err := webauthn.New(webauthn.Config{
			RPID:          *rpID,
			RPDisplayName: *rpName,
			Origins:       origins,
		})
		if err != nil {
			return fmt.Errorf("webauthn: %w", err)
		}
		a.WebAuthn = eng
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := httpapi.Config{
		Auth:           a,
		Sessions:       mgr,
		AllowedOrigins: splitNonEmpty(*originList),
		Logger:         logger,
		Insecure:       *insecure || (*tlsCert == ""),
	}
	if *allowSetTime {
		cfg.SetSystemTime = setSystemTime
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           httpapi.New(cfg),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	// Periodic sweep: HTTP sessions and (if enabled) pending WebAuthn
	// ceremonies. Cheap; runs every 15 minutes.
	go func() {
		t := time.NewTicker(15 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = mgr.PurgeExpired(context.Background())
				if a.WebAuthn != nil {
					a.WebAuthn.Sweep()
				}
			}
		}
	}()

	logger.Info("bubble-authd listening", "addr", *listen, "tls", *tlsCert != "")
	if *tlsCert != "" && *tlsKey != "" {
		err = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// setSystemTime is the default SetSystemTime hook: shells out to `date -s`.
// On OpenWRT we'd swap this for a settimeofday(2) syscall in a privileged
// helper.
//
// This is wired into the httpapi only when bubble-authd was started with
// -allow-set-time. Without that flag, the daemon never modifies the
// system clock and the time-sync endpoint can only *report* skew.
func setSystemTime(t time.Time) error {
	if os.Geteuid() != 0 {
		return errors.New("setSystemTime: not root; rerun the daemon with privileges to set the clock")
	}
	cmd := exec.CommandContext(context.Background(), "date", "-s", t.UTC().Format("2006-01-02 15:04:05"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("date -s: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func defaultDBPath() (string, error) {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return d + "/bubbleui/credentials.db", nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return home + "/.local/state/bubbleui/credentials.db", nil
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}
