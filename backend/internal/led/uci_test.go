package led

import (
	"context"
	"errors"
	"testing"
)

const sampleUCIShow = `system.@system[0]=system
system.@system[0].hostname='OpenWrt'
system.led_wan=led
system.led_wan.name='WAN'
system.led_wan.sysfs='green:wan'
system.led_wan.trigger='netdev'
system.led_wan.dev='wan'
system.led_status=led
system.led_status.name='status'
system.led_status.sysfs='blue:system'
system.led_status.trigger='none'
system.led_internet=led
system.led_internet.name='Internet'
system.led_internet.sysfs='red:internet'
`

func runner(out string, err error) UCIRunner {
	return func(_ context.Context) (string, error) { return out, err }
}

func TestParseUCILEDsExtractsSysfs(t *testing.T) {
	got := parseUCILEDs(sampleUCIShow)
	if len(got) != 3 {
		t.Fatalf("got %d LEDs, want 3: %+v", len(got), got)
	}
	bySysfs := map[string]string{}
	for _, l := range got {
		bySysfs[l.Sysfs] = l.Name
	}
	if bySysfs["green:wan"] != "WAN" {
		t.Errorf("green:wan name = %q", bySysfs["green:wan"])
	}
	if bySysfs["blue:system"] != "status" {
		t.Errorf("blue:system name = %q", bySysfs["blue:system"])
	}
}

func TestParseUCILEDsSkipsEntriesWithoutSysfs(t *testing.T) {
	in := `system.led_naked=led
system.led_naked.name='no path'
`
	got := parseUCILEDs(in)
	if len(got) != 0 {
		t.Errorf("expected 0 (no sysfs), got %+v", got)
	}
}

func TestResolveByExplicitName(t *testing.T) {
	path, err := ResolveUCIName(context.Background(), "status", runner(sampleUCIShow, nil))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if path != "blue:system" {
		t.Errorf("got %q, want blue:system", path)
	}
}

func TestResolveByEmptyNameFindsConventionalStatusLED(t *testing.T) {
	path, err := ResolveUCIName(context.Background(), "", runner(sampleUCIShow, nil))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if path != "blue:system" {
		t.Errorf("got %q, want blue:system (conventional 'status')", path)
	}
}

func TestResolveByEmptyNameFallsThroughWhenNoStatusLED(t *testing.T) {
	in := `system.led_wan=led
system.led_wan.name='WAN'
system.led_wan.sysfs='green:wan'
`
	path, err := ResolveUCIName(context.Background(), "", runner(in, nil))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if path != "" {
		t.Errorf("got %q, want empty (no conventional status LED in config)", path)
	}
}

func TestResolveExplicitMissNoFallback(t *testing.T) {
	// User asked for "ledfoo"; UCI has none. Should NOT silently
	// substitute the conventional status LED — the user's preference
	// was explicit.
	path, err := ResolveUCIName(context.Background(), "ledfoo", runner(sampleUCIShow, nil))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if path != "" {
		t.Errorf("got %q, want empty (explicit miss, no fallback)", path)
	}
}

func TestResolvePropagatesNoUCI(t *testing.T) {
	_, err := ResolveUCIName(context.Background(), "", runner("", ErrNoUCI))
	if !errors.Is(err, ErrNoUCI) {
		t.Errorf("got %v, want ErrNoUCI", err)
	}
}

func TestResolveEmptyOutputReturnsEmpty(t *testing.T) {
	path, err := ResolveUCIName(context.Background(), "status", runner("", nil))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if path != "" {
		t.Errorf("got %q, want empty (no LEDs declared)", path)
	}
}

func TestResolveSectionIDMatch(t *testing.T) {
	// preferredName "status" should match section ID "led_status" too.
	in := `system.led_status=led
system.led_status.sysfs='green:something'
`
	// Note: no `option name`, so name match fails, but section-ID match wins.
	path, err := ResolveUCIName(context.Background(), "status", runner(in, nil))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if path != "green:something" {
		t.Errorf("got %q, want green:something (section-ID match)", path)
	}
}
