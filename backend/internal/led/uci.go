package led

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ErrNoUCI is returned by ResolveUCIName when uci isn't on PATH or
// returns no LED entries — i.e., we're not on an OpenWRT device.
var ErrNoUCI = errors.New("led: uci not available")

// UCIRunner is the indirection over `uci show system`. The default
// runs the local uci binary; tests inject a fake.
type UCIRunner func(ctx context.Context) (string, error)

// DefaultUCIRunner shells out to `uci show system` with a 1s deadline.
// Returns ErrNoUCI when uci isn't on PATH.
func DefaultUCIRunner(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("uci"); err != nil {
		return "", ErrNoUCI
	}
	c, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "uci", "-q", "show", "system").Output()
	if err != nil {
		return "", fmt.Errorf("led: uci show: %w", err)
	}
	return string(out), nil
}

// ResolveUCIName looks up the OpenWRT-declared sysfs path for an LED.
// preferredName is matched against the LED's name= or section ID; if
// found, the corresponding sysfs= value is returned. Returns ErrNoUCI
// if uci is unavailable, or "" with no error if the lookup ran but no
// matching entry exists (caller falls through to direct sysfs probe).
//
// OpenWRT's /etc/config/system declares LEDs like:
//
//	config led 'led_status'
//	    option name 'status'
//	    option sysfs 'green:status'
//	    option trigger 'none'
//
// `uci show system` flattens this to:
//
//	system.led_status=led
//	system.led_status.name='status'
//	system.led_status.sysfs='green:status'
//	system.led_status.trigger='none'
func ResolveUCIName(ctx context.Context, preferredName string, runner UCIRunner) (string, error) {
	if runner == nil {
		runner = DefaultUCIRunner
	}
	out, err := runner(ctx)
	if err != nil {
		return "", err
	}
	leds := parseUCILEDs(out)
	if len(leds) == 0 {
		// uci ran but declared no LEDs (some devices don't bother).
		// Treat as "nothing to resolve" — caller falls through.
		return "", nil
	}

	// Match strategy:
	//   1. Exact name match on `option name '...'`.
	//   2. Section-ID match (the bit after led_, e.g. led_status → "status").
	//   3. If preferredName is empty, return the first LED whose name
	//      contains "status", "system", or "power" — those are the
	//      conventional "use this for status" labels across most
	//      OpenWRT board configs.
	if preferredName != "" {
		for _, l := range leds {
			if l.Name == preferredName || l.Section == "led_"+preferredName {
				return l.Sysfs, nil
			}
		}
		return "", nil // explicit lookup, no hit, no fallback
	}
	for _, want := range []string{"status", "system", "power"} {
		for _, l := range leds {
			n := strings.ToLower(l.Name)
			if n == want || strings.Contains(n, want) {
				return l.Sysfs, nil
			}
		}
	}
	return "", nil
}

// uciLED is a parsed entry from `uci show system`.
type uciLED struct {
	Section string // e.g. "led_status"
	Name    string // option name
	Sysfs   string // option sysfs
}

// parseUCILEDs extracts every `system.led_*` section from `uci show
// system` output. Lines like:
//
//	system.led_status=led
//	system.led_status.name='status'
//	system.led_status.sysfs='green:status'
//
// become uciLED{Section:"led_status", Name:"status", Sysfs:"green:status"}.
func parseUCILEDs(showOutput string) []uciLED {
	bySection := make(map[string]*uciLED)
	for _, line := range strings.Split(showOutput, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "system.led_") {
			continue
		}
		// Trim the leading "system." prefix.
		rest := line[len("system."):]

		// Two shapes:
		//   "led_foo=led"           — declaring the section
		//   "led_foo.name='bar'"    — declaring an option
		eq := strings.IndexByte(rest, '=')
		dot := strings.IndexByte(rest, '.')
		if eq < 0 {
			continue
		}
		var section, key, value string
		if dot < 0 || dot > eq {
			// "led_foo=led"
			section = rest[:eq]
			// Skip the type-declaration line; we only care about options.
			if _, ok := bySection[section]; !ok {
				bySection[section] = &uciLED{Section: section}
			}
			continue
		}
		// "led_foo.name='bar'"
		section = rest[:dot]
		key = rest[dot+1 : eq]
		value = strings.Trim(rest[eq+1:], "'\"")

		entry, ok := bySection[section]
		if !ok {
			entry = &uciLED{Section: section}
			bySection[section] = entry
		}
		switch key {
		case "name":
			entry.Name = value
		case "sysfs":
			entry.Sysfs = value
		}
	}
	out := make([]uciLED, 0, len(bySection))
	for _, e := range bySection {
		if e.Sysfs == "" {
			continue // entries without a sysfs path are useless to us
		}
		out = append(out, *e)
	}
	return out
}
