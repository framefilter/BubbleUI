// Package crypto implements the at-rest protection of the YubiKey HMAC
// secret S and the recovery-code primitives, per DESIGN.md §5.4 and §5.5.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// SelfWrapTag is the fixed application-tagged challenge used to derive the
// self-wrap key from the YubiKey's own HMAC oracle. Changing this string
// breaks compatibility with previously-wrapped secrets.
const SelfWrapTag = "bubble-at-rest-v1"

const aesKeyLen = 32

// SelfWrapChallenge returns the bytes that should be sent to the YubiKey's
// HMAC-SHA1 slot to produce the wrap-key seed. The router stores no copy of
// this value — it's a constant of the protocol.
func SelfWrapChallenge() []byte {
	return []byte(SelfWrapTag)
}

// DeriveWrapKey expands the YubiKey's 20-byte HMAC-SHA1 response into a
// 32-byte AES-256 key via HKDF-SHA256.
func DeriveWrapKey(hmacResp []byte) ([]byte, error) {
	if len(hmacResp) == 0 {
		return nil, errors.New("crypto: empty hmac response")
	}
	r := hkdf.New(sha256.New, hmacResp, nil, []byte("bubble-aes-256-v1"))
	key := make([]byte, aesKeyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("crypto: hkdf expand: %w", err)
	}
	return key, nil
}

// Wrap encrypts plaintext under key using AES-256-GCM. The returned blob is
// nonce || ciphertext || tag; callers store it verbatim.
func Wrap(key, plaintext []byte) ([]byte, error) {
	if len(key) != aesKeyLen {
		return nil, fmt.Errorf("crypto: wrap key must be %d bytes, got %d", aesKeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Unwrap reverses Wrap. The blob format is nonce || ciphertext || tag.
func Unwrap(key, blob []byte) ([]byte, error) {
	if len(key) != aesKeyLen {
		return nil, fmt.Errorf("crypto: unwrap key must be %d bytes, got %d", aesKeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm: %w", err)
	}
	ns := aead.NonceSize()
	if len(blob) < ns+aead.Overhead() {
		return nil, errors.New("crypto: blob too short")
	}
	plaintext, err := aead.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: open: %w", err)
	}
	return plaintext, nil
}
