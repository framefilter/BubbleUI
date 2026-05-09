package yubikey

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"sync"
)

// Mock is an in-memory Oracle that simulates a YubiKey programmed with a
// known secret. It's the dependency injected into tests and into the dev
// CLI when no hardware is attached.
type Mock struct {
	mu     sync.Mutex
	slots  map[Slot][]byte // secret per slot
	online bool
}

// NewMock returns an empty Mock with no slots programmed and "no key
// present" until Plug() is called.
func NewMock() *Mock {
	return &Mock{slots: make(map[Slot][]byte)}
}

// Plug marks a virtual key as attached. Unplug removes it. Program() (the
// Programmer interface implementation, below) implicitly plugs in.
func (m *Mock) Plug()   { m.mu.Lock(); m.online = true; m.mu.Unlock() }
func (m *Mock) Unplug() { m.mu.Lock(); m.online = false; m.mu.Unlock() }

// Challenge implements Oracle by computing HMAC-SHA1(secret, challenge).
func (m *Mock) Challenge(_ context.Context, slot Slot, challenge []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.online {
		return nil, errors.New("yubikey: no key present (mock)")
	}
	secret, ok := m.slots[slot]
	if !ok {
		return nil, errors.New("yubikey: slot not programmed (mock)")
	}
	mac := hmac.New(sha1.New, secret)
	mac.Write(challenge)
	return mac.Sum(nil), nil
}

// Present implements Oracle.
func (m *Mock) Present(_ context.Context) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.online
}

// Program implements Programmer by writing the secret into the named slot
// and marking the mock as plugged in (programming a real key requires a
// connected device, so the post-condition matches reality). Tests that
// want "programmed but disconnected" should call Unplug() afterward.
func (m *Mock) Program(_ context.Context, slot Slot, secret []byte) error {
	if slot != Slot1 && slot != Slot2 {
		return errors.New("yubikey: invalid slot (mock)")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(secret))
	copy(cp, secret)
	m.slots[slot] = cp
	m.online = true
	return nil
}
