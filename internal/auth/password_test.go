package auth

import (
	"strings"
	"testing"
)

func TestHashPassword_AndCompare(t *testing.T) {
	const password = "S3cure-Passw0rd!"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hash == "" || hash == password {
		t.Fatalf("hash must be non-empty and differ from the password, got %q", hash)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("hash should be a bcrypt hash, got %q", hash)
	}

	if err := ComparePassword(hash, password); err != nil {
		t.Fatalf("ComparePassword() with correct password error = %v", err)
	}
}

func TestComparePassword_WrongPassword(t *testing.T) {
	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	for _, wrong := range []string{"wrong-password", "", "Correct-Password", "correct-password "} {
		if err := ComparePassword(hash, wrong); err == nil {
			t.Errorf("ComparePassword(%q) should fail", wrong)
		}
	}
}

func TestComparePassword_InvalidHash(t *testing.T) {
	if err := ComparePassword("not-a-bcrypt-hash", "password"); err == nil {
		t.Fatal("expected error for an invalid hash")
	}
	if err := ComparePassword("", "password"); err == nil {
		t.Fatal("expected error for an empty hash")
	}
}

func TestHashPassword_UsesRandomSalt(t *testing.T) {
	first, err := HashPassword("same-password")
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword("same-password")
	if err != nil {
		t.Fatal(err)
	}

	if first == second {
		t.Fatal("hashing the same password twice must produce different hashes")
	}
}

func TestHashPassword_Length72Bytes(t *testing.T) {
	if _, err := HashPassword(strings.Repeat("a", 72)); err != nil {
		t.Fatalf("72 byte password should be accepted, got %v", err)
	}

	if _, err := HashPassword(strings.Repeat("a", 73)); err == nil {
		t.Fatal("73 byte password should be rejected by bcrypt")
	}
}
