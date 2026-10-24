package rbac

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Service dibuat dengan repository nil. Semua test di file ini hanya
// menjalankan jalur validasi yang berhenti sebelum repository dipanggil.
func newValidationService() *Service {
	return NewService(nil)
}

func TestNormalize(t *testing.T) {
	tests := map[string]string{
		"  Admin  ":      "admin",
		"USERS.READ":     "users.read",
		"already-lower":  "already-lower",
		"":               "",
		"\tMixed Case\n": "mixed case",
	}

	for in, want := range tests {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateRoleName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"simple", "editor", true},
		{"with digits", "team1", true},
		{"starts with digit", "1team", true},
		{"with underscore", "content_manager", true},
		{"with hyphen", "content-manager", true},
		{"max length 50", strings.Repeat("a", 50), true},
		{"empty", "", false},
		{"too long 51", strings.Repeat("a", 51), false},
		{"uppercase", "Editor", false},
		{"space inside", "content manager", false},
		{"starts with hyphen", "-editor", false},
		{"starts with underscore", "_editor", false},
		{"dot not allowed", "content.manager", false},
		{"special char", "editor!", false},
		{"unicode", "pengelolaé", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRoleName(tt.input)

			if tt.valid && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !tt.valid && !errors.Is(err, ErrInvalidRoleName) {
				t.Fatalf("error = %v, want ErrInvalidRoleName", err)
			}
		})
	}
}

func TestValidatePermissionName(t *testing.T) {
	longValid := strings.Repeat("a", 49) + "." + strings.Repeat("b", 50) // 100 chars

	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"resource.action", "users.read", true},
		{"underscore", "user_roles.update", true},
		{"three segments", "reports.sales.export", true},
		{"digits", "v2.items.read", true},
		{"exactly 100 chars", longValid, true},
		{"101 chars", longValid + "b", false},
		{"empty", "", false},
		{"no dot", "users", false},
		{"trailing dot", "users.", false},
		{"leading dot", ".read", false},
		{"double dot", "users..read", false},
		{"uppercase", "Users.Read", false},
		{"space", "users read", false},
		{"hyphen", "user-roles.read", false},
		{"special char", "users.read!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePermissionName(tt.input)

			if tt.valid && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !tt.valid && !errors.Is(err, ErrInvalidPermissionName) {
				t.Fatalf("error = %v, want ErrInvalidPermissionName", err)
			}
		})
	}
}

func TestValidateDescription(t *testing.T) {
	if err := validateDescription(""); err != nil {
		t.Errorf("empty description should be valid, got %v", err)
	}
	if err := validateDescription(strings.Repeat("x", 500)); err != nil {
		t.Errorf("500 chars should be valid, got %v", err)
	}
	if err := validateDescription(strings.Repeat("x", 501)); !errors.Is(err, ErrInvalidDescription) {
		t.Errorf("501 chars error = %v, want ErrInvalidDescription", err)
	}
}

func TestIsSystemRole(t *testing.T) {
	for _, name := range []string{"user", "superadmin"} {
		if !isSystemRole(name) {
			t.Errorf("%q should be a system role", name)
		}
	}
	for _, name := range []string{"admin", "editor", "", "User", "superadmin2"} {
		if isSystemRole(name) {
			t.Errorf("%q should not be a system role", name)
		}
	}
}

func TestService_CreateRole_Validation(t *testing.T) {
	s := newValidationService()
	ctx := context.Background()

	tests := []struct {
		name        string
		roleName    string
		description string
		wantErr     error
	}{
		{"empty name", "", "", ErrInvalidRoleName},
		{"whitespace name", "   ", "", ErrInvalidRoleName},
		{"invalid characters", "bad name!", "", ErrInvalidRoleName},
		{"name too long", strings.Repeat("a", 51), "", ErrInvalidRoleName},
		{"description too long", "editor", strings.Repeat("x", 501), ErrInvalidDescription},
		{"system role user", "user", "", ErrSystemRole},
		{"system role superadmin", "superadmin", "", ErrSystemRole},
		{"system role is case insensitive", "  SuperAdmin ", "", ErrSystemRole},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role, err := s.CreateRole(ctx, tt.roleName, tt.description)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if role != nil {
				t.Fatalf("role should be nil, got %+v", role)
			}
		})
	}
}

func TestService_UpdateRole_Validation(t *testing.T) {
	s := newValidationService()
	ctx := context.Background()

	tests := []struct {
		name        string
		roleName    string
		description string
		wantErr     error
	}{
		{"invalid name", "Bad Name", "", ErrInvalidRoleName},
		{"empty name", "", "", ErrInvalidRoleName},
		{"description too long", "editor", strings.Repeat("x", 501), ErrInvalidDescription},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role, err := s.UpdateRole(ctx, 1, tt.roleName, tt.description)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if role != nil {
				t.Fatalf("role should be nil, got %+v", role)
			}
		})
	}
}

func TestService_CreatePermission_Validation(t *testing.T) {
	s := newValidationService()
	ctx := context.Background()

	tests := []struct {
		name           string
		permissionName string
		description    string
		wantErr        error
	}{
		{"empty name", "", "", ErrInvalidPermissionName},
		{"no dot", "users", "", ErrInvalidPermissionName},
		{"trailing dot", "users.", "", ErrInvalidPermissionName},
		{"invalid characters", "users read", "", ErrInvalidPermissionName},
		{"name too long", strings.Repeat("a", 60) + "." + strings.Repeat("b", 60), "", ErrInvalidPermissionName},
		{"description too long", "users.read", strings.Repeat("x", 501), ErrInvalidDescription},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := s.CreatePermission(ctx, tt.permissionName, tt.description)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if p != nil {
				t.Fatalf("permission should be nil, got %+v", p)
			}
		})
	}
}

func TestService_UpdatePermission_Validation(t *testing.T) {
	s := newValidationService()

	if _, err := s.UpdatePermission(context.Background(), 1, "nodot", ""); !errors.Is(err, ErrInvalidPermissionName) {
		t.Errorf("invalid name error = %v", err)
	}

	if _, err := s.UpdatePermission(
		context.Background(), 1, "users.read", strings.Repeat("x", 501),
	); !errors.Is(err, ErrInvalidDescription) {
		t.Errorf("long description error = %v", err)
	}
}

func TestService_GetByNonPositiveID(t *testing.T) {
	s := newValidationService()
	ctx := context.Background()

	for _, id := range []int{0, -1, -100} {
		if _, err := s.GetRole(ctx, id); !errors.Is(err, ErrRoleNotFound) {
			t.Errorf("GetRole(%d) error = %v, want ErrRoleNotFound", id, err)
		}
		if _, err := s.GetPermission(ctx, id); !errors.Is(err, ErrPermissionNotFound) {
			t.Errorf("GetPermission(%d) error = %v, want ErrPermissionNotFound", id, err)
		}
	}
}

func TestService_SetRolePermissions_Validation(t *testing.T) {
	s := newValidationService()
	ctx := context.Background()

	tests := []struct {
		name          string
		roleID        int
		permissionIDs []int
		wantErr       error
	}{
		{"role id zero", 0, []int{1}, ErrRoleNotFound},
		{"role id negative", -3, []int{1}, ErrRoleNotFound},
		{"permission id zero", 1, []int{1, 0}, ErrInvalidPermissionID},
		{"permission id negative", 1, []int{-2}, ErrInvalidPermissionID},
		{"invalid id after valid and duplicate", 1, []int{2, 2, 3, -1}, ErrInvalidPermissionID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.SetRolePermissions(ctx, tt.roleID, tt.permissionIDs)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestService_SetUserRole_Validation(t *testing.T) {
	s := newValidationService()
	ctx := context.Background()

	if err := s.SetUserRole(ctx, 0, 1); err == nil || err.Error() != "invalid user id" {
		t.Errorf("user id 0 error = %v", err)
	}
	if err := s.SetUserRole(ctx, -1, 1); err == nil {
		t.Error("negative user id should fail")
	}
	if err := s.SetUserRole(ctx, 1, 0); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("role id 0 error = %v, want ErrRoleNotFound", err)
	}
	if err := s.SetUserRole(ctx, 1, -5); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("negative role id error = %v, want ErrRoleNotFound", err)
	}
}

func TestService_HasPermission_EmptyPermission(t *testing.T) {
	s := newValidationService()

	for _, permission := range []string{"", "   ", "\t\n"} {
		allowed, err := s.HasPermission(context.Background(), 1, permission)
		if err != nil {
			t.Errorf("HasPermission(%q) error = %v", permission, err)
		}
		if allowed {
			t.Errorf("HasPermission(%q) must be false", permission)
		}
	}
}
