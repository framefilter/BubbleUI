// Package led abstracts the router's status LED. DESIGN.md §13.7 maps
// BubbleUI states to LED behaviors; this package owns that mapping.
//
// The Driver interface is small (Render(state) + Close()) so we can ship
// multiple implementations:
//
//   - MockDriver:   for dev / tests, records the last state in memory.
//   - SysfsDriver:  drives /sys/class/leds/<name>/{brightness,trigger}
//     on Linux. Auto-detects mono vs RGB from sibling
//     entry naming.
//
// SysfsDriver follows DESIGN.md §14's resolution ladder: it asks UCI
// (`uci show system`) first to find the OpenWRT-declared status LED,
// and only falls back to scanning /sys/class/leds when UCI doesn't
// answer. That's what lets one binary cover every Tier-2 device
// without per-board code. See uci.go.
package led

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// State is the user-facing meaning of "what should the LED show right now."
type State int

const (
	StateOff        State = iota
	StateBooting          // pulse fade
	StateSetup            // solid (or solid-blue on RGB)
	StateSecured          // solid green
	StateKillswitch       // slow red blink — kill switch active, no internet
	StateSigninOpen       // double-pulse heartbeat — §6.5 sign-in window open
	StateNoKey            // fast blink — YubiKey expected but missing
	StateFault            // very fast blink — hardware fault
)

func (s State) String() string {
	switch s {
	case StateOff:
		return "off"
	case StateBooting:
		return "booting"
	case StateSetup:
		return "setup"
	case StateSecured:
		return "secured"
	case StateKillswitch:
		return "killswitch_up"
	case StateSigninOpen:
		return "signin_open"
	case StateNoKey:
		return "no_key"
	case StateFault:
		return "fault"
	default:
		return "unknown"
	}
}

// ParseState converts a serialized state name back to a State, or
// returns an error.
func ParseState(s string) (State, error) {
	switch s {
	case "off":
		return StateOff, nil
	case "booting":
		return StateBooting, nil
	case "setup":
		return StateSetup, nil
	case "secured":
		return StateSecured, nil
	case "killswitch_up":
		return StateKillswitch, nil
	case "signin_open":
		return StateSigninOpen, nil
	case "no_key":
		return StateNoKey, nil
	case "fault":
		return StateFault, nil
	default:
		return StateOff, fmt.Errorf("led: unknown state %q", s)
	}
}

// Driver is what bubble-hwd talks to. Implementations are responsible
// for translating the abstract State into actual LED behavior.
type Driver interface {
	Render(s State) error
	Close() error
}

// --- Mock ---

// MockDriver is the dev/test driver. Records every state transition.
type MockDriver struct {
	mu      sync.Mutex
	current State
	history []transition
}

type transition struct {
	at    time.Time
	state State
}

// NewMock returns a fresh MockDriver in StateOff.
func NewMock() *MockDriver { return &MockDriver{current: StateOff} }

func (d *MockDriver) Render(s State) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.current = s
	d.history = append(d.history, transition{at: time.Now(), state: s})
	return nil
}

func (d *MockDriver) Close() error { return nil }

// Current returns the most-recently-rendered state.
func (d *MockDriver) Current() State {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.current
}

// History returns the recorded sequence of state changes.
func (d *MockDriver) History() []State {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]State, len(d.history))
	for i, t := range d.history {
		out[i] = t.state
	}
	return out
}

// --- Sysfs (Linux/router) ---

// SysfsDriver writes to /sys/class/leds/<name>/{brightness,trigger,delay_on,delay_off}.
// Capability is auto-detected at New time: if RGB-named entries exist
// alongside the primary, we drive them as a multi-color LED; otherwise
// we fall back to brightness-only mono with blink patterns.
//
// On non-Linux dev hosts, NewSysfs returns ErrNoSysfs and the daemon
// substitutes MockDriver.
type SysfsDriver struct {
	primary string            // e.g. "/sys/class/leds/blue:system"
	rgb     map[string]string // optional: "red", "green", "blue" → path
	maxBrt  int
}

// ErrNoSysfs is returned by NewSysfs when no usable LED entries exist
// at /sys/class/leds.
var ErrNoSysfs = errors.New("led: /sys/class/leds has no usable entries")

// NewSysfs scans /sys/class/leds and constructs a driver.
//
// Resolution order, per DESIGN.md §14:
//
//  1. If preferredName is set, ask UCI: does OpenWRT declare an LED by
//     this name (or section ID)? If yes, use the declared sysfs path.
//  2. If preferredName is empty, ask UCI for the conventional status
//     LED ("status" / "system" / "power").
//  3. Fall back to scanning /sys/class/leds directly: explicit
//     preferredName as a literal sysfs name first, then auto-detect
//     mono vs RGB from color-prefixed siblings.
//
// On non-Linux dev hosts, NewSysfs returns ErrNoSysfs and the daemon
// substitutes MockDriver.
func NewSysfs(preferredName string) (*SysfsDriver, error) {
	// Step 1+2: try UCI. We pass through to direct sysfs probing on
	// any UCI-side error (no uci, timeout, no entries) — those aren't
	// fatal, they just mean we can't take the shortcut.
	resolved, err := ResolveUCIName(context.Background(), preferredName, nil)
	if err == nil && resolved != "" {
		preferredName = resolved
	}

	entries, err := os.ReadDir("/sys/class/leds")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoSysfs, err)
	}
	if len(entries) == 0 {
		return nil, ErrNoSysfs
	}

	// Look for color-named siblings ("red:foo", "green:foo", "blue:foo")
	// to detect RGB capability. Bare-name fallback otherwise.
	rgb := make(map[string]string)
	primary := ""
	for _, e := range entries {
		name := e.Name()
		if preferredName != "" && name != preferredName {
			continue
		}
		path := filepath.Join("/sys/class/leds", name)
		switch {
		case strings.HasPrefix(name, "red:"):
			rgb["red"] = path
		case strings.HasPrefix(name, "green:"):
			rgb["green"] = path
		case strings.HasPrefix(name, "blue:"):
			rgb["blue"] = path
		default:
			if primary == "" {
				primary = path
			}
		}
	}
	if primary == "" && len(rgb) == 0 {
		return nil, ErrNoSysfs
	}
	if primary == "" {
		// All-RGB; pick green as the conventional "primary" for status.
		primary = rgb["green"]
	}

	maxBrt := 255
	if v, err := os.ReadFile(filepath.Join(primary, "max_brightness")); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(v))); err == nil && n > 0 {
			maxBrt = n
		}
	}
	if len(rgb) < 3 {
		rgb = nil // not full RGB — treat as mono
	}
	return &SysfsDriver{primary: primary, rgb: rgb, maxBrt: maxBrt}, nil
}

// Render translates state into sysfs writes. The mapping below applies
// regardless of whether we ended up mono or RGB; full-color handling
// just sets the per-channel brightness instead of using blink triggers.
func (d *SysfsDriver) Render(s State) error {
	pattern := patternFor(s)
	if d.rgb != nil {
		return d.renderRGB(pattern)
	}
	return d.renderMono(pattern)
}

func (d *SysfsDriver) Close() error {
	// Best-effort: leave the LED off on shutdown.
	_ = writeFile(filepath.Join(d.primary, "trigger"), "none")
	_ = writeFile(filepath.Join(d.primary, "brightness"), "0")
	return nil
}

func (d *SysfsDriver) renderMono(p pattern) error {
	if err := writeFile(filepath.Join(d.primary, "trigger"), p.trigger); err != nil {
		return err
	}
	if p.trigger == "timer" {
		_ = writeFile(filepath.Join(d.primary, "delay_on"), strconv.Itoa(p.delayOnMs))
		_ = writeFile(filepath.Join(d.primary, "delay_off"), strconv.Itoa(p.delayOffMs))
	}
	return writeFile(filepath.Join(d.primary, "brightness"), strconv.Itoa(p.brightness*d.maxBrt/255))
}

func (d *SysfsDriver) renderRGB(p pattern) error {
	for color, path := range d.rgb {
		v := p.rgb[color] * d.maxBrt / 255
		if err := writeFile(filepath.Join(path, "brightness"), strconv.Itoa(v)); err != nil {
			return err
		}
		if p.trigger == "timer" {
			_ = writeFile(filepath.Join(path, "trigger"), "timer")
			_ = writeFile(filepath.Join(path, "delay_on"), strconv.Itoa(p.delayOnMs))
			_ = writeFile(filepath.Join(path, "delay_off"), strconv.Itoa(p.delayOffMs))
		} else {
			_ = writeFile(filepath.Join(path, "trigger"), "none")
		}
	}
	return nil
}

// pattern is the resolved LED behavior for a given State.
type pattern struct {
	trigger    string         // "none" or "timer"
	brightness int            // mono: 0-255
	rgb        map[string]int // RGB: "red"/"green"/"blue" → 0-255
	delayOnMs  int
	delayOffMs int
}

// patternFor maps state → LED behavior. Mirrors §13.5 of DESIGN.md.
func patternFor(s State) pattern {
	switch s {
	case StateOff:
		return pattern{trigger: "none", brightness: 0, rgb: rgbFor(0, 0, 0)}
	case StateBooting:
		// Slow heartbeat: 1500 ms on, 500 ms off, white-ish.
		return pattern{trigger: "timer", brightness: 200, rgb: rgbFor(180, 180, 220), delayOnMs: 1500, delayOffMs: 500}
	case StateSetup:
		return pattern{trigger: "none", brightness: 255, rgb: rgbFor(0, 0, 255)}
	case StateSecured:
		return pattern{trigger: "none", brightness: 200, rgb: rgbFor(0, 200, 0)}
	case StateKillswitch:
		return pattern{trigger: "timer", brightness: 220, rgb: rgbFor(220, 0, 0), delayOnMs: 500, delayOffMs: 500}
	case StateSigninOpen:
		// Double-pulse heartbeat: 200 on / 200 off / 200 on / 1400 off.
		// Linux gpio-keys 'timer' trigger only supports a single on/off
		// cycle; we approximate with a 4 Hz blink that's visually distinct.
		return pattern{trigger: "timer", brightness: 220, rgb: rgbFor(220, 200, 0), delayOnMs: 250, delayOffMs: 250}
	case StateNoKey:
		return pattern{trigger: "timer", brightness: 220, rgb: rgbFor(220, 0, 0), delayOnMs: 200, delayOffMs: 200}
	case StateFault:
		return pattern{trigger: "timer", brightness: 220, rgb: rgbFor(220, 0, 0), delayOnMs: 100, delayOffMs: 100}
	}
	return pattern{trigger: "none", brightness: 0, rgb: rgbFor(0, 0, 0)}
}

func rgbFor(r, g, b int) map[string]int {
	return map[string]int{"red": r, "green": g, "blue": b}
}

func writeFile(path, value string) error {
	return os.WriteFile(path, []byte(value), 0)
}
