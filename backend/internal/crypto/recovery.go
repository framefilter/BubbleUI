package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2s"
)

// RecoveryCodeBytes is the entropy of a recovery code, in bytes (128 bits).
const RecoveryCodeBytes = 16

// RecoveryCodeGroups is the number of dash-separated groups in the printed form.
const RecoveryCodeGroups = 5

// NewRecoveryCode generates a fresh recovery code. The returned string is the
// human-presentable form; the caller stores the BLAKE2s-256 hash via HashRecoveryCode.
func NewRecoveryCode() (string, error) {
	raw := make([]byte, RecoveryCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("crypto: recovery rand: %w", err)
	}
	return formatRecoveryCode(raw), nil
}

// HashRecoveryCode returns the BLAKE2s-256 hash of the *normalized* code.
// Normalization: uppercase, dashes/spaces removed.
func HashRecoveryCode(code string) ([]byte, error) {
	norm := normalizeRecoveryCode(code)
	if norm == "" {
		return nil, errors.New("crypto: empty recovery code")
	}
	h, err := blake2s.New256(nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: blake2s: %w", err)
	}
	h.Write([]byte(norm))
	return h.Sum(nil), nil
}

// VerifyRecoveryCode compares a candidate code against a stored hash in
// constant time. It returns true iff the candidate normalizes to a value
// whose BLAKE2s hash equals stored.
func VerifyRecoveryCode(candidate string, stored []byte) (bool, error) {
	got, err := HashRecoveryCode(candidate)
	if err != nil {
		return false, err
	}
	if len(got) != len(stored) {
		return false, nil
	}
	return subtle.ConstantTimeCompare(got, stored) == 1, nil
}

// formatRecoveryCode renders raw bytes as a Crockford-base32-style string
// split into RecoveryCodeGroups groups. Example: "K9F4A-2BX7M-PR3VZ-W8H6Q-N5DC1".
func formatRecoveryCode(raw []byte) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	enc = strings.ToUpper(enc)
	groupLen := len(enc) / RecoveryCodeGroups
	if groupLen*RecoveryCodeGroups != len(enc) {
		groupLen = (len(enc) + RecoveryCodeGroups - 1) / RecoveryCodeGroups
	}
	var b strings.Builder
	for i := 0; i < len(enc); i += groupLen {
		if i > 0 {
			b.WriteByte('-')
		}
		end := i + groupLen
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
	}
	return b.String()
}

// normalizeRecoveryCode removes whitespace and dashes, and uppercases.
// I/O/0/1 ambiguities are NOT collapsed — base32 already excludes those
// characters from its alphabet, so they can't appear in legitimate codes.
func normalizeRecoveryCode(in string) string {
	var b strings.Builder
	for _, r := range in {
		switch {
		case r == ' ' || r == '-' || r == '\t' || r == '\n':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return strings.ToUpper(b.String())
}
