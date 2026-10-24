package rbac

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func newTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)

	h := NewHandler(NewService(nil))
	r := gin.New()

	r.GET("/roles/:id", h.GetRole)
	r.POST("/roles", h.CreateRole)
	r.PUT("/roles/:id", h.UpdateRole)
	r.DELETE("/roles/:id", h.DeleteRole)
	r.PUT("/roles/:id/permissions", h.UpdateRolePermissions)
	r.GET("/permissions/:id", h.GetPermission)
	r.POST("/permissions", h.CreatePermission)
	r.PUT("/permissions/:id", h.UpdatePermission)
	r.DELETE("/permissions/:id", h.DeletePermission)
	r.PUT("/users/:id/role", h.UpdateUserRole)

	return r
}

func do(r http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

func errorMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}

	msg, _ := body["error"].(string)
	return msg
}

func TestHandler_InvalidIDParam(t *testing.T) {
	r := newTestRouter()

	routes := []struct{ method, pathFmt, body string }{
		{http.MethodGet, "/roles/%s", ""},
		{http.MethodPut, "/roles/%s", `{"name":"editor"}`},
		{http.MethodDelete, "/roles/%s", ""},
		{http.MethodPut, "/roles/%s/permissions", `{"permission_ids":[1]}`},
		{http.MethodGet, "/permissions/%s", ""},
		{http.MethodPut, "/permissions/%s", `{"name":"users.read"}`},
		{http.MethodDelete, "/permissions/%s", ""},
		{http.MethodPut, "/users/%s/role", `{"role_id":1}`},
	}

	for _, id := range []string{"abc", "0", "-1", "1.5"} {
		for _, rt := range routes {
			path := fmt.Sprintf(rt.pathFmt, id)

			t.Run(rt.method+" "+path, func(t *testing.T) {
				w := do(r, rt.method, path, rt.body)

				if w.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400", w.Code)
				}
				if got := errorMessage(t, w); got != "invalid id" {
					t.Fatalf("error = %q, want invalid id", got)
				}
			})
		}
	}
}

func TestHandler_InvalidBody(t *testing.T) {
	r := newTestRouter()

	tests := []struct {
		name, method, path, body, wantErr string
	}{
		{"create role malformed json", http.MethodPost, "/roles", "{", "invalid request body"},
		{"create role missing name", http.MethodPost, "/roles", `{"description":"x"}`, "invalid request body"},
		{"create role name too long", http.MethodPost, "/roles",
			`{"name":"` + strings.Repeat("a", 51) + `"}`, "invalid request body"},
		{"create role description too long", http.MethodPost, "/roles",
			`{"name":"editor","description":"` + strings.Repeat("x", 501) + `"}`, "invalid request body"},
		{"update role missing name", http.MethodPut, "/roles/1", `{}`, "invalid request body"},
		{"create permission missing name", http.MethodPost, "/permissions", `{}`, "invalid request body"},
		{"create permission malformed json", http.MethodPost, "/permissions", `not json`, "invalid request body"},
		{"update permission missing name", http.MethodPut, "/permissions/1", `{}`, "invalid request body"},
		{"role permissions missing field", http.MethodPut, "/roles/1/permissions", `{}`, "permission_ids is required"},
		{"role permissions null", http.MethodPut, "/roles/1/permissions", `{"permission_ids":null}`, "permission_ids is required"},
		{"user role missing role_id", http.MethodPut, "/users/1/role", `{}`, "invalid request body"},
		{"user role zero", http.MethodPut, "/users/1/role", `{"role_id":0}`, "invalid request body"},
		{"user role negative", http.MethodPut, "/users/1/role", `{"role_id":-1}`, "invalid request body"},
		{"user role wrong type", http.MethodPut, "/users/1/role", `{"role_id":"abc"}`, "invalid request body"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := do(r, tt.method, tt.path, tt.body)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
			}
			if got := errorMessage(t, w); got != tt.wantErr {
				t.Fatalf("error = %q, want %q", got, tt.wantErr)
			}
		})
	}
}

// Request lolos binding tetapi ditolak oleh validasi service,
// sebelum repository dipanggil.
func TestHandler_ServiceValidationErrors(t *testing.T) {
	r := newTestRouter()

	tests := []struct {
		name, method, path, body string
		wantStatus               int
		wantErr                  string
	}{
		{"create role invalid name", http.MethodPost, "/roles",
			`{"name":"Bad Name!"}`, http.StatusBadRequest, ErrInvalidRoleName.Error()},
		{"create role system role", http.MethodPost, "/roles",
			`{"name":"superadmin"}`, http.StatusConflict, ErrSystemRole.Error()},
		{"update role invalid name", http.MethodPut, "/roles/2",
			`{"name":"-bad"}`, http.StatusBadRequest, ErrInvalidRoleName.Error()},
		{"create permission invalid name", http.MethodPost, "/permissions",
			`{"name":"nodot"}`, http.StatusBadRequest, ErrInvalidPermissionName.Error()},
		{"update permission invalid name", http.MethodPut, "/permissions/2",
			`{"name":"users read"}`, http.StatusBadRequest, ErrInvalidPermissionName.Error()},
		{"role permissions with zero id", http.MethodPut, "/roles/2/permissions",
			`{"permission_ids":[1,0]}`, http.StatusBadRequest, ErrInvalidPermissionID.Error()},
		{"role permissions with negative id", http.MethodPut, "/roles/2/permissions",
			`{"permission_ids":[-4]}`, http.StatusBadRequest, ErrInvalidPermissionID.Error()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := do(r, tt.method, tt.path, tt.body)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tt.wantStatus, w.Body.String())
			}
			if got := errorMessage(t, w); got != tt.wantErr {
				t.Fatalf("error = %q, want %q", got, tt.wantErr)
			}
		})
	}
}

func TestHandleError_StatusMapping(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantErr    string
	}{
		{"role not found", ErrRoleNotFound, http.StatusNotFound, ErrRoleNotFound.Error()},
		{"permission not found", ErrPermissionNotFound, http.StatusNotFound, ErrPermissionNotFound.Error()},
		{"user not found", ErrUserNotFound, http.StatusNotFound, ErrUserNotFound.Error()},
		{"role name exists", ErrRoleNameAlreadyExists, http.StatusConflict, ErrRoleNameAlreadyExists.Error()},
		{"permission name exists", ErrPermissionNameExists, http.StatusConflict, ErrPermissionNameExists.Error()},
		{"role in use", ErrRoleInUse, http.StatusConflict, ErrRoleInUse.Error()},
		{"permission in use", ErrPermissionInUse, http.StatusConflict, ErrPermissionInUse.Error()},
		{"system role", ErrSystemRole, http.StatusConflict, ErrSystemRole.Error()},
		{"superadmin protected", ErrSuperadminProtected, http.StatusConflict, ErrSuperadminProtected.Error()},
		{"superadmin role protected", ErrSuperadminRoleProtected, http.StatusConflict, ErrSuperadminRoleProtected.Error()},
		{"invalid role name", ErrInvalidRoleName, http.StatusBadRequest, ErrInvalidRoleName.Error()},
		{"invalid permission name", ErrInvalidPermissionName, http.StatusBadRequest, ErrInvalidPermissionName.Error()},
		{"invalid description", ErrInvalidDescription, http.StatusBadRequest, ErrInvalidDescription.Error()},
		{"invalid permission id", ErrInvalidPermissionID, http.StatusBadRequest, ErrInvalidPermissionID.Error()},
		{"wrapped sentinel still mapped", fmt.Errorf("ctx: %w", ErrRoleNotFound), http.StatusNotFound, "ctx: role not found"},
		{"unknown error hides details", errors.New("pq: connection refused"), http.StatusInternalServerError, "internal server error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			handleError(c, tt.err)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if got := errorMessage(t, w); got != tt.wantErr {
				t.Fatalf("error = %q, want %q", got, tt.wantErr)
			}
		})
	}
}

func TestToRoleResponse(t *testing.T) {
	now := time.Now()

	role := &Role{
		ID: 3, Name: "editor", Description: "can edit", IsSuperadmin: false,
		PermissionIDs: []int{1, 2}, CreatedAt: now, UpdatedAt: now,
	}

	got := toRoleResponse(role)

	if got.ID != 3 || got.Name != "editor" || got.Description != "can edit" || got.IsSuperadmin {
		t.Errorf("unexpected response: %+v", got)
	}
	if len(got.PermissionIDs) != 2 || got.PermissionIDs[0] != 1 || got.PermissionIDs[1] != 2 {
		t.Errorf("PermissionIDs = %v", got.PermissionIDs)
	}
}

func TestToRoleResponse_NilPermissionIDsBecomesEmptyArray(t *testing.T) {
	got := toRoleResponse(&Role{ID: 1, Name: "user"})

	if got.PermissionIDs == nil {
		t.Fatal("PermissionIDs must not be nil")
	}

	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"permission_ids":[]`) {
		t.Fatalf("JSON should contain an empty array, got %s", data)
	}
}

func TestToPermissionResponse(t *testing.T) {
	now := time.Now()

	got := toPermissionResponse(&Permission{
		ID: 9, Name: "users.read", Description: "read users", CreatedAt: now, UpdatedAt: now,
	})

	if got.ID != 9 || got.Name != "users.read" || got.Description != "read users" {
		t.Errorf("unexpected response: %+v", got)
	}
	if !got.CreatedAt.Equal(now) || !got.UpdatedAt.Equal(now) {
		t.Errorf("timestamps not copied: %+v", got)
	}
}
