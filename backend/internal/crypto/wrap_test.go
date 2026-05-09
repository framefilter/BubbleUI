package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"testing"
)

func TestSelfWrapRoundtrip(t *testing.T) {
	// Simulate the YubiKey's HMAC oracle in-process.
	S := bytes.Repeat([]byte{0x42}, 20)
	mac := hmac.New(sha1.New, S)
	mac.Write(SelfWrapChallenge())
	hmacResp := mac.Sum(nil)

	wrapKey, err := DeriveWrapKey(hmacResp)
	if err != nil {
		t.Fatalf("DeriveWrapKey: %v", err)
	}
	if len(wrapKey) != 32 {
		t.Fatalf("wrap key length = %d, want 32", len(wrapKey))
	}

	blob, err := Wrap(wrapKey, S)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if bytes.Contains(blob, S) {
		t.Fatal("ciphertext contains plaintext bytes")
	}

	got, err := Unwrap(wrapKey, blob)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, S) {
		t.Fatalf("unwrapped = %x, want %x", got, S)
	}
}

func TestUnwrapRejectsTampered(t *testing.T) {
	S := bytes.Repeat([]byte{0xab}, 20)
	mac := hmac.New(sha1.New, S)
	mac.Write(SelfWrapChallenge())
	wrapKey, _ := DeriveWrapKey(mac.Sum(nil))
	blob, _ := Wrap(wrapKey, S)

	// Flip a byte in the ciphertext (after the nonce).
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0x01

	if _, err := Unwrap(wrapKey, tampered); err == nil {
		t.Fatal("Unwrap of tampered blob should fail")
	}
}

func TestUnwrapRejectsWrongKey(t *testing.T) {
	S := bytes.Repeat([]byte{0xcd}, 20)
	mac := hmac.New(sha1.New, S)
	mac.Write(SelfWrapChallenge())
	wrapKey, _ := DeriveWrapKey(mac.Sum(nil))
	blob, _ := Wrap(wrapKey, S)

	wrongKey := bytes.Repeat([]byte{0x00}, 32)
	if _, err := Unwrap(wrongKey, blob); err == nil {
		t.Fatal("Unwrap with wrong key should fail")
	}
}

func TestDeriveWrapKeyDeterministic(t *testing.T) {
	resp := []byte("0123456789abcdefghij") // 20 bytes
	a, _ := DeriveWrapKey(resp)
	b, _ := DeriveWrapKey(resp)
	if !bytes.Equal(a, b) {
		t.Fatal("DeriveWrapKey is not deterministic")
	}
}

func TestDeriveWrapKeyEmptyRejected(t *testing.T) {
	if _, err := DeriveWrapKey(nil); err == nil {
		t.Fatal("expected error on empty hmac response")
	}
}

func TestWrapWrongKeyLength(t *testing.T) {
	if _, err := Wrap(make([]byte, 16), []byte("data")); err == nil {
		t.Fatal("expected error for wrong-length key")
	}
}
