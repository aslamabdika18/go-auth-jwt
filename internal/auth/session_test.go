package auth

import (
	"regexp"
	"testing"
)

func TestGenerateSessionID(t *testing.T) {
	urlSafe := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

	id, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error = %v", err)
	}

	if len(id) != 43 {
		t.Errorf("session ID length = %d, want 43", len(id))
	}
	if !urlSafe.MatchString(id) {
		t.Errorf("session ID should be URL-safe without padding, got %q", id)
	}
}

func TestGenerateSessionID_Unique(t *testing.T) {
	seen := make(map[string]struct{})

	for i := 0; i < 200; i++ {
		id, err := GenerateSessionID()
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate session ID generated: %q", id)
		}
		seen[id] = struct{}{}
	}
}
