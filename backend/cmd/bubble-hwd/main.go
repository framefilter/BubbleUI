// bubble-hwd is BubbleUI's hardware adapter daemon. It owns the
// router's status LED and any GPIO inputs (reset button, mode switch)
// per DESIGN.md §13.5/§13.6.
//
// On the router we drive /sys/class/leds/* via internal/led.SysfsDriver
// and read /dev/input/eventN via internal/buttons.LinuxReader. On dev
// machines we fall back to mock implementations that record state
// changes for inspection. The daemon doesn't actually need real
// hardware to run — it just won't blink anything physical.
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

	"github.com/framefilter/bubbleui/backend/internal/buttons"
	"github.com/framefilter/bubbleui/backend/internal/hwapi"
	"github.com/framefilter/bubbleui/backend/internal/led"
)

const usage = `bubble-hwd — BubbleUI hardware adapter daemon

usage: bubble-hwd [flags]

Flags:
  -listen ADDR        HTTP listen address (default 127.0.0.1:8768)
  -led NAME           preferred /sys/class/leds entry (default: first found)
  -mock               force mock LED + buttons even if sysfs is available
  -h, --help          show this help

Without -mock the daemon attempts to bind to /sys/class/leds and
/dev/input/event* and falls back to mocks if those aren't usable.
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bubble-hwd:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen    string
		ledName   string
		forceMock bool
		showHelp  bool
	)
	flag.StringVar(&listen, "listen", "127.0.0.1:8768", "HTTP listen address")
	flag.StringVar(&ledName, "led", "", "preferred /sys/class/leds entry name")
	flag.BoolVar(&forceMock, "mock", false, "force mock implementations")
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

	// LED selection: try sysfs unless -mock; on failure log and fall back.
	var ledDriver led.Driver
	ledMode := "mock"
	if !forceMock {
		if d, err := led.NewSysfs(ledName); err == nil {
			ledDriver = d
			ledMode = "sysfs"
		} else {
			logger.Info("led sysfs unavailable, using mock", "err", err)
		}
	}
	if ledDriver == nil {
		ledDriver = led.NewMock()
	}

	// Buttons: same pattern. The Linux evdev reader is not yet
	// implemented (NewLinux() always returns ErrNotImplemented); we
	// always fall back to mock. The daemon still exposes /hw/buttons
	// so HTTP callers can poll without surprise.
	var btn buttons.Reader = buttons.NewMock()
	btnMode := "mock"
	if !forceMock {
		if r, err := buttons.NewLinux(); err == nil {
			btn = r
			btnMode = "linux"
		}
	}

	api := hwapi.New(hwapi.Config{
		LED:     ledDriver,
		Buttons: btn,
		Logger:  logger,
	})

	srv := &http.Server{
		Addr:              listen,
		Handler:           api,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Booting → off on shutdown. The driver decides what these mean.
	// Use api.Set so the API's tracked state stays in sync with reality.
	_ = api.Set(led.StateBooting)

	go func() {
		<-ctx.Done()
		_ = api.Set(led.StateOff)
		_ = btn.Stop()
		shutdown, c2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer c2()
		_ = srv.Shutdown(shutdown)
		_ = ledDriver.Close()
	}()

	logger.Info("bubble-hwd listening",
		"addr", listen, "led_mode", ledMode, "buttons_mode", btnMode)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
