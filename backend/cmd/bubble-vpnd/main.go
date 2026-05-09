// bubble-vpnd is BubbleUI's VPN daemon. M3-prep skeleton: it owns the
// pool of WireGuard configs (DESIGN.md §11.5), runs TCP-connect probes
// over them, ranks by RTT, and exposes a /vpn/* HTTP surface.
//
// `wg-quick up` / `wg-quick down` integration lives behind the
// Connector interface; the dev binary uses StubConnector which records
// state but does not actually bring up a tunnel. The real router-side
// implementation lands when we have hardware in front of us.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/framefilter/bubbleui/backend/internal/prober"
	"github.com/framefilter/bubbleui/backend/internal/vpnapi"
	"github.com/framefilter/bubbleui/backend/internal/wgpool"
)

const usage = `bubble-vpnd — BubbleUI VPN daemon

usage: bubble-vpnd [flags]

Flags:
  -db PATH        path to vpn.db (default: $XDG_STATE_HOME/bubbleui/vpn.db
                  or ~/.local/state/bubbleui/vpn.db)
  -listen ADDR    HTTP listen address (default 127.0.0.1:8766)
  -probe-timeout  per-probe TCP-connect deadline (default 1.5s)
  -probe-parallel max in-flight probes (default 16)
  -h, --help      show this help

The daemon currently uses an in-memory StubConnector that does not
actually bring up a tunnel. Real wg-quick integration lands when we
target the AXT1800; for now /vpn/connect just records "active" state.
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bubble-vpnd:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dbPath        string
		listen        string
		probeTimeout  time.Duration
		probeParallel int
		showHelp      bool
	)
	flag.StringVar(&dbPath, "db", "", "vpn.db path")
	flag.StringVar(&listen, "listen", "127.0.0.1:8766", "HTTP listen address")
	flag.DurationVar(&probeTimeout, "probe-timeout", 1500*time.Millisecond, "per-probe TCP-connect timeout")
	flag.IntVar(&probeParallel, "probe-parallel", 16, "max concurrent probes")
	flag.BoolVar(&showHelp, "help", false, "show help")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	if showHelp {
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
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return fmt.Errorf("create db dir: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	pool, err := wgpool.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	defer pool.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	api := vpnapi.New(vpnapi.Config{
		Pool:      pool,
		Connector: &vpnapi.StubConnector{},
		Logger:    logger,
		Probe: prober.Config{
			PerProbeTimeout: probeTimeout,
			Concurrency:     probeParallel,
		},
	})

	srv := &http.Server{
		Addr:              listen,
		Handler:           api,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	logger.Info("bubble-vpnd listening",
		"addr", listen, "db", dbPath,
		"probe_timeout", probeTimeout, "probe_parallel", probeParallel,
		"connector", "stub")

	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func defaultDBPath() (string, error) {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "bubbleui", "vpn.db"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "bubbleui", "vpn.db"), nil
}
