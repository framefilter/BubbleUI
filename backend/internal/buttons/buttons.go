// Package buttons abstracts the router's GPIO-driven inputs (reset
// button, mode switch). Two implementations:
//
//   - MockReader: dev/test, lets test code synthesize Press events.
//   - LinuxReader: stub for /dev/input/eventN (real impl lands when we
//     have hardware to validate against). Currently returns a quiet
//     reader that emits no events; documented as not yet wired.
//
// Long-press detection lives outside this package: callers receive raw
// Down/Up events with a timestamp and decide what counts as a "long
// press" themselves. See cmd/bubble-hwd for the §6.7-aligned reset
// button behavior (5+ s = factory reset).
package buttons

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Button is the named source of an event.
type Button string

const (
	Reset Button = "reset"
	Mode1 Button = "mode-1" // 3-position switch position 1 (left)
	Mode2 Button = "mode-2" // 3-position switch position 2 (middle)
	Mode3 Button = "mode-3" // 3-position switch position 3 (right)
)

// EventKind discriminates Down (press began) from Up (released).
type EventKind int

const (
	Down EventKind = iota
	Up
)

func (k EventKind) String() string {
	if k == Down {
		return "down"
	}
	return "up"
}

// Event is the raw input we surface upstream.
type Event struct {
	Button Button
	Kind   EventKind
	At     time.Time
}

// Reader streams Events to its caller until the context is cancelled.
type Reader interface {
	Events() <-chan Event
	// Stop releases any underlying resources. After Stop the Events
	// channel will be closed.
	Stop() error
}

// --- Mock ---

// MockReader is the dev/test reader. Test code calls Press(button) to
// synthesize a Down→Up pair, or Down/Up separately for long-press
// scenarios.
type MockReader struct {
	ch     chan Event
	once   sync.Once
	closed bool
	mu     sync.Mutex
}

// NewMock returns a buffered MockReader.
func NewMock() *MockReader {
	return &MockReader{ch: make(chan Event, 16)}
}

func (r *MockReader) Events() <-chan Event { return r.ch }

func (r *MockReader) Stop() error {
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		close(r.ch)
		r.mu.Unlock()
	})
	return nil
}

// Down synthesizes a Down event for button. Safe to call concurrently;
// returns silently if the reader has been Stop()'d.
func (r *MockReader) Down(b Button) {
	r.send(Event{Button: b, Kind: Down, At: time.Now()})
}

// Up synthesizes an Up event.
func (r *MockReader) Up(b Button) {
	r.send(Event{Button: b, Kind: Up, At: time.Now()})
}

// Press synthesizes a Down event followed by an Up event after the
// specified hold duration. Returns when both have been delivered.
func (r *MockReader) Press(ctx context.Context, b Button, hold time.Duration) {
	r.Down(b)
	select {
	case <-time.After(hold):
	case <-ctx.Done():
	}
	r.Up(b)
}

func (r *MockReader) send(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	select {
	case r.ch <- e:
	default:
		// Drop if buffer is full; tests should drain.
	}
}

// --- Linux/sysfs/evdev (stub) ---

// ErrNotImplemented is returned by NewLinux when the daemon is built
// on a non-Linux host or when the configured input devices are not
// available. The router-side implementation lands when we have
// hardware to validate against.
var ErrNotImplemented = errors.New("buttons: linux/evdev reader not yet implemented")

// NewLinux is a placeholder for the real /dev/input/eventN reader. For
// now it's a stub that always returns ErrNotImplemented; cmd/bubble-hwd
// falls back to MockReader if this errors.
func NewLinux() (Reader, error) {
	return nil, ErrNotImplemented
}
