package crypto

import (
	"strings"
	"testing"
)

func TestRecoveryCodeRoundtrip(t *testing.T) {
	code, err := NewRecoveryCode()
	if err != nil {
		t.Fatalf("NewRecoveryCode: %v", err)
	}
	if len(code) < 20 {
		t.Fatalf("recovery code seems too short: %q", code)
	}
	if !strings.Contains(code, "-") {
		t.Fatalf("recovery code should be grouped with dashes: %q", code)
	}

	hash, err := HashRecoveryCode(code)
	if err != nil {
		t.Fatalf("HashRecoveryCode: %v", err)
	}
	if len(hash) != 32 {
		t.Fatalf("hash len = %d, want 32 (BLAKE2s-256)", len(hash))
	}

	ok, err := VerifyRecoveryCode(code, hash)
	if err != nil {
		t.Fatalf("VerifyRecoveryCode: %v", err)
	}
	if !ok {
		t.Fatal("Verify should accept the original code")
	}
}

func TestRecoveryCodeNormalization(t *testing.T) {
	code, _ := NewRecoveryCode()
	hash, _ := HashRecoveryCode(code)

	cases := []string{
		strings.ToLower(code),                  // lowercase
		strings.ReplaceAll(code, "-", ""),      // dashes stripped
		strings.ReplaceAll(code, "-", " "),     // dashes -> spaces
		strings.ReplaceAll(code, "-", "  -  "), // weird spacing
		" " + code + " ",                       // surrounding whitespace
	}
	for _, c := range cases {
		ok, err := VerifyRecoveryCode(c, hash)
		if err != nil {
			t.Errorf("Verify(%q): %v", c, err)
			continue
		}
		if !ok {
			t.Errorf("Verify rejected normalized variant %q", c)
		}
	}
}

func TestRecoveryCodeRejectsWrong(t *testing.T) {
	a, _ := NewRecoveryCode()
	b, _ := NewRecoveryCode()
	hashA, _ := HashRecoveryCode(a)

	ok, _ := VerifyRecoveryCode(b, hashA)
	if ok {
		t.Fatal("Verify should reject a different code")
	}
}

func TestRecoveryCodeRejectsEmpty(t *testing.T) {
	if _, err := HashRecoveryCode(""); err == nil {
		t.Fatal("Hash should reject empty code")
	}
	if _, err := HashRecoveryCode("    --   "); err == nil {
		t.Fatal("Hash should reject whitespace-only code")
	}
}

func TestRecoveryCodeUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		c, err := NewRecoveryCode()
		if err != nil {
			t.Fatalf("NewRecoveryCode: %v", err)
		}
		if seen[c] {
			t.Fatalf("collision at iter %d: %q", i, c)
		}
		seen[c] = true
	}
}
