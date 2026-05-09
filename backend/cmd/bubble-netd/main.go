// bubble-netd is BubbleUI's network/firewall daemon. M3-prep skeleton:
// owns the captive-portal detection probe and the §6.5 sign-in window
// state machine. It does NOT yet apply nftables rules — the dev binary
// uses signin.NoopApplier and logs what it would have done.
//
// The router-side wiring (real Applier shelling out to `nft` plus a
// scoped dnsmasq instance) lands when we're targeting the AXT1800.
// Until then, the daemon's job is to expose the API surface the SPA
// will eventually consume.
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
	"syscall"
	"time"

	"github.com/framefilter/bubbleui/backend/internal/captive"
	"github.com/framefilter/bubbleui/backend/internal/netapi"
	"github.com/framefilter/bubbleui/backend/internal/signin"
)

const usage = `bubble-netd — BubbleUI network / firewall daemon

usage: bubble-netd [flags]

Flags:
  -listen ADDR        HTTP listen address (default 127.0.0.1:8767)
  -window-duration    sign-in window default lifetime (default 10m)
  -captive-timeout    per-probe timeout for captive detection (default 3s)
  -h, --help          show this help

The daemon currently uses signin.NoopApplier — open/close requests are
recorded but no nftables rules are applied. Real router-side wiring
(nft + scoped dnsmasq) lands with M3 hardware bring-up.
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bubble-netd:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen         string
		windowDuration time.Duration
		captiveTimeout time.Duration
		showHelp       bool
	)
	flag.StringVar(&listen, "listen", "127.0.0.1:8767", "HTTP listen address")
	flag.DurationVar(&windowDuration, "window-duration", 10*time.Minute, "sign-in window default lifetime")
	flag.DurationVar(&captiveTimeout, "captive-timeout", 3*time.Second, "per-probe captive-detection timeout")
	flag.BoolVar(&showHelp, "help", false, "show help")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	if showHelp {
		fmt.Fprint(os.Stdout, usage)
		return nil
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	mgr := signin.New(signin.Config{
		Applier:         &signin.NoopApplier{},
		DefaultDuration: windowDuration,
	})
	api := netapi.New(netapi.Config{
		Detector: &captive.Detector{PerProbeTimeout: captiveTimeout},
		Signin:   mgr,
		Logger:   logger,
	})

	srv := &http.Server{
		Addr:              listen,
		Handler:           api,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Periodic tick: closes the sign-in window when the deadline passes.
	// Cheap: locks once, returns early when state is Closed.
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				mgr.Tick(context.Background())
			}
		}
	}()

	go func() {
		<-ctx.Done()
		shutdown, c2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer c2()
		_ = srv.Shutdown(shutdown)
	}()

	logger.Info("bubble-netd listening",
		"addr", listen, "window", windowDuration, "captive_timeout", captiveTimeout,
		"applier", "noop")
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
