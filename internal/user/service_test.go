package user

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/aslamabdika18/go-auth-jwt/internal/auth"
)

// Service dibuat dengan repository nil. Test di file ini hanya menjalankan
// jalur validasi yang berhenti sebelum repository dipanggil.
func newValidationService() *Service {
	return NewService(nil, auth.NewJWT("secret", 15), time.Hour)
}

func TestNewService(t *testing.T) {
	jwtService := auth.NewJWT("secret", 15)
	s := NewService(nil, jwtService, 2*time.Hour)

	if s.jwt != jwtService {
		t.Error("jwt service not stored")
	}
	if s.refreshTokenTTL != 2*time.Hour {
		t.Errorf("refreshTokenTTL = %v, want 2h", s.refreshTokenTTL)
	}
}

func TestService_ListUsers_InvalidPagination(t *testing.T) {
	s := newValidationService()

	tests := []struct {
		name     string
		page     int
		pageSize int
	}{
		{"page zero", 0, 20},
		{"page negative", -1, 20},
		{"page size zero", 1, 0},
		{"page size negative", 1, -5},
		{"page size above max", 1, 101},
		{"page overflow", math.MaxInt, 100},
		{"page overflow with small size", math.MaxInt, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := s.ListUsers(context.Background(), tt.page, tt.pageSize)

			if !errors.Is(err, ErrInvalidPagination) {
				t.Fatalf("error = %v, want ErrInvalidPagination", err)
			}
			if resp != nil {
				t.Fatalf("response should be nil, got %+v", resp)
			}
		})
	}
}

func TestService_Refresh_EmptyToken(t *testing.T) {
	s := newValidationService()

	for _, token := range []string{"", " ", "   ", "\t\n"} {
		result, err := s.Refresh(context.Background(), token)

		if !errors.Is(err, ErrRefreshTokenNotFound) {
			t.Errorf("Refresh(%q) error = %v, want ErrRefreshTokenNotFound", token, err)
		}
		if result != nil {
			t.Errorf("Refresh(%q) result should be nil", token)
		}
	}
}

func TestService_Logout_InvalidIdentity(t *testing.T) {
	s := newValidationService()

	tests := []struct {
		name      string
		sessionID string
		userID    int
	}{
		{"empty session", "", 1},
		{"blank session", "   ", 1},
		{"zero user", "sess", 0},
		{"negative user", "sess", -1},
		{"both invalid", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.Logout(context.Background(), tt.sessionID, tt.userID)

			if err == nil || err.Error() != "invalid session identity" {
				t.Fatalf("error = %v, want invalid session identity", err)
			}
		})
	}
}
