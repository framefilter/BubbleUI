package buttons

import (
	"context"
	"sync"
	"time"
)

// LongPress is a stateful watcher that consumes raw Down/Up events
// from a Reader and emits "the user has been holding this button for
// at least this long" notifications at configurable thresholds.
//
// DESIGN.md §6.7 needs this for the reset-button factory-reset
// countdown: 2-5 s shows amber LED feedback, 5-10 s shows red,
// >10 s triggers the actual reset. We model that as a list of
// thresholds; the watcher emits a Stage event each time the press
// crosses one. Releases (Up) before a threshold cancel the press.
//
// The watcher runs as a background goroutine; callers consume from
// Stages() until ctx is cancelled. Multi-button setups instantiate
// one LongPress per button.
type LongPress struct {
	button     Button
	thresholds []time.Duration

	out chan Stage
	now func() time.Time

	mu     sync.Mutex
	closed bool
}

// Stage is emitted when a held press crosses a configured threshold.
// Released indicates the user let go before reaching this Stage —
// always emitted with the highest reached threshold so callers can
// undo any countdown UI they were showing.
type Stage struct {
	Button   Button
	Index    int           // 0-based position in the configured thresholds
	Hold     time.Duration // how long the press has been active
	Released bool          // true if the user let go before/at this stage
}

// NewLongPress wires a LongPress watcher to the given Reader. The
// watcher reads from r.Events() in a goroutine and writes Stage
// events to the returned channel. Stop the watcher by cancelling
// ctx; the channel is closed afterward.
//
// Thresholds must be in strictly ascending order. An empty list
// disables the watcher (it forwards no Stages but still cleans up
// on ctx cancellation).
func NewLongPress(ctx context.Context, r Reader, button Button, thresholds []time.Duration) *LongPress {
	lp := &LongPress{
		button:     button,
		thresholds: thresholds,
		out:        make(chan Stage, 16),
		now:        time.Now,
	}
	go lp.loop(ctx, r)
	return lp
}

// Stages returns the channel of emitted Stage events. Closed when
// the watcher exits (ctx cancellation).
func (l *LongPress) Stages() <-chan Stage { return l.out }

// SetClock overrides the time source for tests.
func (l *LongPress) SetClock(f func() time.Time) {
	l.mu.Lock()
	l.now = f
	l.mu.Unlock()
}

func (l *LongPress) loop(ctx context.Context, r Reader) {
	defer l.close()

	var (
		pressedAt time.Time
		lastStage = -1
		timer     *time.Timer
		timerCh   <-chan time.Time
	)

	resetTimer := func() {
		if timer != nil {
			timer.Stop()
			timer = nil
			timerCh = nil
		}
	}
	scheduleNext := func() {
		resetTimer()
		next := lastStage + 1
		if next >= len(l.thresholds) {
			return
		}
		l.mu.Lock()
		now := l.now()
		l.mu.Unlock()
		fireAt := pressedAt.Add(l.thresholds[next])
		delay := fireAt.Sub(now)
		if delay < 0 {
			delay = 0
		}
		timer = time.NewTimer(delay)
		timerCh = timer.C
	}

	emit := func(s Stage) {
		select {
		case l.out <- s:
		default:
			// Drop if consumer is slow; we don't want to block the loop.
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-r.Events():
			if !ok {
				return
			}
			if ev.Button != l.button {
				continue
			}
			switch ev.Kind {
			case Down:
				if !pressedAt.IsZero() {
					// Already pressed (event repeat?). Ignore.
					continue
				}
				l.mu.Lock()
				pressedAt = l.now()
				l.mu.Unlock()
				lastStage = -1
				scheduleNext()
			case Up:
				if pressedAt.IsZero() {
					continue
				}
				if lastStage >= 0 {
					// Notify caller of release at the highest reached stage
					// so UI countdowns can revert.
					l.mu.Lock()
					hold := l.now().Sub(pressedAt)
					l.mu.Unlock()
					emit(Stage{
						Button:   l.button,
						Index:    lastStage,
						Hold:     hold,
						Released: true,
					})
				}
				resetTimer()
				pressedAt = time.Time{}
				lastStage = -1
			}
		case <-timerCh:
			if pressedAt.IsZero() {
				resetTimer()
				continue
			}
			next := lastStage + 1
			l.mu.Lock()
			hold := l.now().Sub(pressedAt)
			l.mu.Unlock()
			emit(Stage{
				Button: l.button,
				Index:  next,
				Hold:   hold,
			})
			lastStage = next
			scheduleNext()
		}
	}
}

func (l *LongPress) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	close(l.out)
}
