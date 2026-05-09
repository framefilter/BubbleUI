// Package yubikey adapts the OpenWRT-side `ykchalresp` tool into a small
// HMAC-SHA1 challenge-response oracle. Used by bubble-authd at provisioning
// (writing slot 2) and at login (verifying possession of the key).
//
// On a workstation, install `yubikey-personalization` (Debian/Ubuntu) or
// `ykpers` (Arch) for `ykchalresp`. On OpenWRT, install `yubikey-personalization`
// from the package feed.
package yubikey

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Slot identifies which YubiKey OTP slot we use. Slot 2 is conventionally
// reserved for HMAC challenge-response and is the slot we program at setup.
type Slot int

const (
	Slot1 Slot = 1
	Slot2 Slot = 2
)

// Oracle is anything that can compute HMAC-SHA1(S, challenge) for the
// router-attached YubiKey. The real implementation shells out to ykchalresp;
// tests use the in-memory mock.
type Oracle interface {
	// Challenge sends challenge bytes to the named slot and returns the
	// 20-byte HMAC-SHA1 response. Errors should be treated as authentication
	// failures, not retried, and never surfaced verbatim to users.
	Challenge(ctx context.Context, slot Slot, challenge []byte) ([]byte, error)

	// Present reports whether a compatible YubiKey is currently attached.
	Present(ctx context.Context) bool
}

// Programmer writes an HMAC-SHA1 secret into a slot of an attached YubiKey.
// Used by the wizard's provision flow to set up slot 2 without making the
// user run ykman manually.
//
// On the router we shell out to `ykman otp chalresp --touch <slot> <hex>`.
// On dev workstations without ykman, the bound implementation returns
// ErrUnsupported and the wizard surfaces a copy-pasteable command for the
// user to run themselves.
type Programmer interface {
	Program(ctx context.Context, slot Slot, secret []byte) error
}

// ErrUnsupported is returned when the bound Programmer cannot service a
// request — typically because `ykman` is not installed on this machine.
var ErrUnsupported = errors.New("yubikey: programming unsupported (ykman missing or not allowed)")

// CLI is an Oracle that shells out to the ykchalresp command-line tool.
type CLI struct {
	// Path overrides the ykchalresp binary path for testing.
	Path string
}

// NewCLI returns a default-configured CLI oracle.
func NewCLI() *CLI { return &CLI{Path: "ykchalresp"} }

// Challenge implements Oracle.
func (c *CLI) Challenge(ctx context.Context, slot Slot, challenge []byte) ([]byte, error) {
	if slot != Slot1 && slot != Slot2 {
		return nil, fmt.Errorf("yubikey: invalid slot %d", slot)
	}
	if len(challenge) == 0 {
		return nil, errors.New("yubikey: empty challenge")
	}
	args := []string{
		fmt.Sprintf("-%d", int(slot)),
		"-x",
		hex.EncodeToString(challenge),
	}
	cmd := exec.CommandContext(ctx, c.Path, args...)
	out, err := cmd.Output()
	if err != nil {
		// Don't propagate stderr verbatim — keys not plugged in or wrong
		// slot configuration can leak hints we don't want.
		return nil, fmt.Errorf("yubikey: challenge failed: %w", err)
	}
	hexResp := strings.TrimSpace(string(out))
	resp, err := hex.DecodeString(hexResp)
	if err != nil {
		return nil, fmt.Errorf("yubikey: response decode: %w", err)
	}
	if len(resp) != 20 {
		return nil, fmt.Errorf("yubikey: unexpected response length %d", len(resp))
	}
	return resp, nil
}

// Present implements Oracle by attempting a low-cost interaction.
//
// Note: ykchalresp itself requires a slot to be configured. We instead rely
// on `ykinfo -v` if available; falling back to "not present" if neither tool
// can answer cleanly. Callers should treat Present() as advisory — the only
// real test is whether Challenge succeeds.
func (c *CLI) Present(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "ykinfo", "-v")
	if err := cmd.Run(); err == nil {
		return true
	}
	return false
}

// YkmanProgrammer writes secrets via `ykman otp chalresp`. Returns
// ErrUnsupported when ykman is not on PATH.
type YkmanProgrammer struct {
	// Path overrides the ykman binary location (mostly for testing).
	Path string
}

// NewYkmanProgrammer returns a default-configured programmer.
func NewYkmanProgrammer() *YkmanProgrammer { return &YkmanProgrammer{Path: "ykman"} }

// Program implements Programmer.
func (p *YkmanProgrammer) Program(ctx context.Context, slot Slot, secret []byte) error {
	if slot != Slot1 && slot != Slot2 {
		return fmt.Errorf("yubikey: invalid slot %d", slot)
	}
	if len(secret) == 0 {
		return errors.New("yubikey: empty secret")
	}
	bin := p.Path
	if bin == "" {
		bin = "ykman"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return ErrUnsupported
	}
	args := []string{"otp", "chalresp", "--force", "--touch", fmt.Sprintf("%d", int(slot)), hex.EncodeToString(secret)}
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("yubikey: ykman: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
