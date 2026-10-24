package user

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin/binding"
)

func TestRegisterRequest_Validation(t *testing.T) {
	validEmail := "user@example.com"
	longEmail := strings.Repeat("a", 244) + "@example.com" // 256 karakter

	tests := []struct {
		name  string
		req   RegisterRequest
		valid bool
	}{
		{"valid", RegisterRequest{"Aslam", validEmail, "password123"}, true},
		{"name min length 3", RegisterRequest{"Abc", validEmail, "password123"}, true},
		{"name max length 100", RegisterRequest{strings.Repeat("a", 100), validEmail, "password123"}, true},
		{"password min length 8", RegisterRequest{"Aslam", validEmail, "12345678"}, true},
		{"password max length 72", RegisterRequest{"Aslam", validEmail, strings.Repeat("p", 72)}, true},

		{"name missing", RegisterRequest{"", validEmail, "password123"}, false},
		{"name too short", RegisterRequest{"Ab", validEmail, "password123"}, false},
		{"name too long", RegisterRequest{strings.Repeat("a", 101), validEmail, "password123"}, false},
		{"email missing", RegisterRequest{"Aslam", "", "password123"}, false},
		{"email invalid", RegisterRequest{"Aslam", "not-an-email", "password123"}, false},
		{"email without domain", RegisterRequest{"Aslam", "user@", "password123"}, false},
		{"email too long", RegisterRequest{"Aslam", longEmail, "password123"}, false},
		{"password missing", RegisterRequest{"Aslam", validEmail, ""}, false},
		{"password too short", RegisterRequest{"Aslam", validEmail, "1234567"}, false},
		{"password too long", RegisterRequest{"Aslam", validEmail, strings.Repeat("p", 73)}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := binding.Validator.ValidateStruct(tt.req)

			if tt.valid && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoginRequest_Validation(t *testing.T) {
	tests := []struct {
		name  string
		req   LoginRequest
		valid bool
	}{
		{"valid", LoginRequest{"user@example.com", "anything"}, true},
		// Login tidak membatasi panjang password agar akun lama tetap bisa masuk.
		{"short password allowed", LoginRequest{"user@example.com", "x"}, true},
		{"email missing", LoginRequest{"", "pw"}, false},
		{"email invalid", LoginRequest{"nope", "pw"}, false},
		{"password missing", LoginRequest{"user@example.com", ""}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := binding.Validator.ValidateStruct(tt.req)

			if tt.valid && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestUpdateUserRequest_Validation(t *testing.T) {
	tests := []struct {
		name  string
		req   UpdateUserRequest
		valid bool
	}{
		{"valid", UpdateUserRequest{"Aslam", "user@example.com"}, true},
		{"name too short", UpdateUserRequest{"Ab", "user@example.com"}, false},
		{"name missing", UpdateUserRequest{"", "user@example.com"}, false},
		{"email invalid", UpdateUserRequest{"Aslam", "bad"}, false},
		{"email missing", UpdateUserRequest{"Aslam", ""}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := binding.Validator.ValidateStruct(tt.req)

			if tt.valid && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestResponse_JSONDoesNotLeakSensitiveFields(t *testing.T) {
	u := &User{
		ID: 1, Name: "Aslam", Email: "a@example.com",
		PasswordHash: "$2a$10$secret-hash", RoleID: 2, Role: "user", IsSuperadmin: true,
		CreatedAt: time.Now(),
	}

	data, err := json.Marshal(toResponse(u))
	if err != nil {
		t.Fatal(err)
	}

	body := string(data)
	for _, forbidden := range []string{"secret-hash", "password", "is_superadmin", "role_id"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("response JSON must not contain %q: %s", forbidden, body)
		}
	}

	for _, key := range []string{`"id":1`, `"name":"Aslam"`, `"email":"a@example.com"`, `"role":"user"`, `"created_at"`} {
		if !strings.Contains(body, key) {
			t.Errorf("response JSON should contain %s: %s", key, body)
		}
	}
}

func TestToResponse(t *testing.T) {
	now := time.Now()

	got := toResponse(&User{
		ID: 7, Name: "Budi", Email: "budi@example.com", Role: "admin", CreatedAt: now,
	})

	if got.ID != 7 || got.Name != "Budi" || got.Email != "budi@example.com" || got.Role != "admin" {
		t.Errorf("unexpected response: %+v", got)
	}
	if !got.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, now)
	}
}
