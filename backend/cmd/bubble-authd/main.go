// bubble-authd is BubbleUI's authentication daemon. The M2 PoC is a CLI
// that exercises the same flows the eventual ubus-attached daemon will —
// provision a credential, log in via YubiKey HMAC, run the recovery flow.
//
// HTTP and ubus surfaces land in M3.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/framefilter/bubbleui/backend/internal/auth"
	"github.com/framefilter/bubbleui/backend/internal/store"
	"github.com/framefilter/bubbleui/backend/internal/yubikey"
)

const usage = `bubble-authd — BubbleUI auth daemon (M2 PoC)

usage: bubble-authd [-db PATH] [-mock] <command> [args]

Commands:
  provision           Generate a new YubiKey HMAC credential and recovery code.
                      Prints the recovery code (display once) and the slot-2
                      secret in hex (program with: ykman otp chalresp 2 <hex>).
  login               Run the login flow against the attached YubiKey.
  recover <code>      Burn the recovery code and wipe credentials.
  status              Show registered credentials.
  -h, --help          Show this help.

Flags:
  -db   PATH   credentials.db path (default: $XDG_STATE_HOME/bubbleui/credentials.db
               or ~/.local/state/bubbleui/credentials.db)
  -mock        Use the in-memory mock YubiKey. The CLI prompts for the slot-2
               secret in hex on every challenge — useful for end-to-end testing
               without hardware. Never use this on a real router.

A real YubiKey requires the ykchalresp tool (yubikey-personalization package).
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
		useMock  bool
		showHelp bool
	)
	flag.StringVar(&dbPath, "db", "", "credentials.db path")
	flag.BoolVar(&useMock, "mock", false, "use in-memory mock YubiKey")
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

	yk := buildOracle(useMock)
	a := auth.New(s, yk)

	cmd := flag.Arg(0)
	args := flag.Args()[1:]
	switch cmd {
	case "provision":
		return cmdProvision(ctx, a, dbPath, useMock)
	case "login":
		return cmdLogin(ctx, a, dbPath, useMock, yk)
	case "recover":
		if len(args) == 0 {
			return errors.New("recover requires the recovery code as argument")
		}
		return cmdRecover(ctx, a, strings.Join(args, " "))
	case "status":
		return cmdStatus(ctx, s)
	default:
		return fmt.Errorf("unknown command %q (try -h)", cmd)
	}
}

func cmdProvision(ctx context.Context, a *auth.Authenticator, dbPath string, useMock bool) error {
	res, err := a.ProvisionYubiKey(ctx, "")
	if err != nil {
		return fmt.Errorf("provision: %w", err)
	}
	fmt.Println("Provisioning complete.")
	fmt.Println()
	fmt.Println("Recovery code (write this down — shown ONCE):")
	fmt.Println("    " + res.RecoveryCode)
	fmt.Println()
	fmt.Println("Slot-2 secret (program your YubiKey with this):")
	fmt.Println("    " + hex.EncodeToString(res.Secret))
	fmt.Println()
	fmt.Println("On real hardware:")
	fmt.Println("    ykman otp chalresp --touch 2 " + hex.EncodeToString(res.Secret))

	if useMock {
		// Persist the mock secret to a sidecar file so subsequent CLI
		// invocations can re-create the same virtual key state.
		sidecar := dbPath + ".mock-secret"
		if err := os.WriteFile(sidecar, []byte(hex.EncodeToString(res.Secret)), 0o600); err != nil {
			return fmt.Errorf("write mock sidecar: %w", err)
		}
		fmt.Println()
		fmt.Println("(mock secret saved to " + sidecar + " for subsequent -mock login)")
	}
	return nil
}

func cmdLogin(ctx context.Context, a *auth.Authenticator, dbPath string, useMock bool, yk yubikey.Oracle) error {
	if useMock {
		secret, err := loadMockSecret(dbPath)
		if err != nil {
			return fmt.Errorf("mock secret: %w", err)
		}
		m, ok := yk.(*yubikey.Mock)
		if !ok {
			return errors.New("internal: -mock did not yield a Mock oracle")
		}
		m.Program(yubikey.Slot2, secret)
		m.Plug()
	}

	id, err := a.LoginYubiKey(ctx)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	fmt.Printf("OK: authenticated as credential id=%d\n", id)
	return nil
}

func loadMockSecret(dbPath string) ([]byte, error) {
	if envHex := os.Getenv("BUBBLE_MOCK_SECRET_HEX"); envHex != "" {
		return hex.DecodeString(envHex)
	}
	sidecar := dbPath + ".mock-secret"
	data, err := os.ReadFile(sidecar)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w (provision first, or set BUBBLE_MOCK_SECRET_HEX)", sidecar, err)
	}
	return hex.DecodeString(strings.TrimSpace(string(data)))
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

func buildOracle(useMock bool) yubikey.Oracle {
	if useMock {
		return yubikey.NewMock()
	}
	return yubikey.NewCLI()
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
