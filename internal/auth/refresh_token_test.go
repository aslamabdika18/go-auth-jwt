package auth

import (
	"regexp"
	"testing"
	"time"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestGenerateRefreshToken(t *testing.T) {
	ttl := 24 * time.Hour

	before := time.Now()
	rt, err := GenerateRefreshToken(ttl)
	after := time.Now()
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}

	// 32 byte acak -> 43 karakter base64 raw URL.
	if len(rt.Token) != 43 {
		t.Errorf("token length = %d, want 43", len(rt.Token))
	}
	if !hex64.MatchString(rt.TokenHash) {
		t.Errorf("token hash should be 64 hex chars, got %q", rt.TokenHash)
	}
	if rt.TokenHash == rt.Token {
		t.Error("token hash must differ from the raw token")
	}
	if rt.TokenHash != HashRefreshToken(rt.Token) {
		t.Error("TokenHash must equal HashRefreshToken(Token)")
	}

	if rt.ExpiresAt.Before(before.Add(ttl)) || rt.ExpiresAt.After(after.Add(ttl)) {
		t.Errorf("ExpiresAt %v is outside the expected window", rt.ExpiresAt)
	}
}

func TestGenerateRefreshToken_Unique(t *testing.T) {
	seen := make(map[string]struct{})

	for i := 0; i < 200; i++ {
		rt, err := GenerateRefreshToken(time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[rt.Token]; dup {
			t.Fatalf("duplicate refresh token generated: %q", rt.Token)
		}
		seen[rt.Token] = struct{}{}
	}
}

func TestHashRefreshToken(t *testing.T) {
	// SHA-256("abc") adalah test vector standar.
	const abcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	if got := HashRefreshToken("abc"); got != abcHash {
		t.Fatalf("HashRefreshToken(abc) = %q, want %q", got, abcHash)
	}

	if HashRefreshToken("token-a") != HashRefreshToken("token-a") {
		t.Error("hashing must be deterministic")
	}
	if HashRefreshToken("token-a") == HashRefreshToken("token-b") {
		t.Error("different tokens must have different hashes")
	}
}
