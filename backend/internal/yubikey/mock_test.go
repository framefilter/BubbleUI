package yubikey

import (
	"bytes"
	"context"
	"testing"
)

func TestMockNotPresent(t *testing.T) {
	m := NewMock()
	if m.Present(context.Background()) {
		t.Fatal("freshly created mock should not be present")
	}
	if _, err := m.Challenge(context.Background(), Slot2, []byte("c")); err == nil {
		t.Fatal("Challenge should fail when not plugged in")
	}
}

func TestMockChallengeRoundtrip(t *testing.T) {
	m := NewMock()
	secret := bytes.Repeat([]byte{0x42}, 20)
	if err := m.Program(context.Background(), Slot2, secret); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	resp, err := m.Challenge(ctx, Slot2, []byte("hello"))
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if len(resp) != 20 {
		t.Fatalf("len(resp) = %d, want 20", len(resp))
	}

	// Same challenge produces same response.
	resp2, _ := m.Challenge(ctx, Slot2, []byte("hello"))
	if !bytes.Equal(resp, resp2) {
		t.Fatal("HMAC-SHA1 should be deterministic")
	}

	// Different challenge produces different response.
	resp3, _ := m.Challenge(ctx, Slot2, []byte("world"))
	if bytes.Equal(resp, resp3) {
		t.Fatal("different challenge should produce different response")
	}
}

func TestMockUnprogrammedSlot(t *testing.T) {
	m := NewMock()
	m.Plug()
	if _, err := m.Challenge(context.Background(), Slot1, []byte("c")); err == nil {
		t.Fatal("Challenge should fail on unprogrammed slot")
	}
}
