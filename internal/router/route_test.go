package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aslamabdika18/go-auth-jwt/internal/auth"
	"github.com/aslamabdika18/go-auth-jwt/internal/rbac"
	"github.com/aslamabdika18/go-auth-jwt/internal/user"
	"github.com/gin-gonic/gin"
)

// Handler dan service dibiarkan kosong: semua route yang dites di sini
// ditolak oleh middleware Auth sebelum handler atau database tersentuh.
func newTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)

	jwtService := auth.NewJWT("router-test-secret", 15)

	return New(
		user.NewHandler(nil, jwtService, false),
		rbac.NewHandler(nil),
		jwtService,
		rbac.NewService(nil),
		user.NewService(nil, jwtService, 0),
	)
}

func TestHealth(t *testing.T) {
	r := newTestRouter()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("body = %v", body)
	}
}

func TestRoutesRegistered(t *testing.T) {
	r := newTestRouter()

	registered := make(map[string]bool)
	for _, route := range r.Routes() {
		registered[route.Method+" "+route.Path] = true
	}

	expected := []string{
		"GET /health",
		"POST /api/v1/auth/register",
		"POST /api/v1/auth/login",
		"POST /api/v1/auth/refresh",
		"POST /api/v1/auth/logout",
		"GET /api/v1/auth/me",
		"GET /api/v1/users",
		"GET /api/v1/users/:id",
		"PUT /api/v1/users/:id",
		"DELETE /api/v1/users/:id",
		"PUT /api/v1/users/:id/role",
		"GET /api/v1/roles",
		"GET /api/v1/roles/:id",
		"POST /api/v1/roles",
		"PUT /api/v1/roles/:id",
		"DELETE /api/v1/roles/:id",
		"PUT /api/v1/roles/:id/permissions",
		"GET /api/v1/permissions",
		"GET /api/v1/permissions/:id",
		"POST /api/v1/permissions",
		"PUT /api/v1/permissions/:id",
		"DELETE /api/v1/permissions/:id",
	}

	for _, route := range expected {
		if !registered[route] {
			t.Errorf("route not registered: %s", route)
		}
	}
}

func TestProtectedRoutesRequireAuthentication(t *testing.T) {
	r := newTestRouter()

	protected := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/auth/logout"},
		{http.MethodGet, "/api/v1/auth/me"},
		{http.MethodGet, "/api/v1/users"},
		{http.MethodGet, "/api/v1/users/1"},
		{http.MethodPut, "/api/v1/users/1"},
		{http.MethodDelete, "/api/v1/users/1"},
		{http.MethodPut, "/api/v1/users/1/role"},
		{http.MethodGet, "/api/v1/roles"},
		{http.MethodGet, "/api/v1/roles/1"},
		{http.MethodPost, "/api/v1/roles"},
		{http.MethodPut, "/api/v1/roles/1"},
		{http.MethodDelete, "/api/v1/roles/1"},
		{http.MethodPut, "/api/v1/roles/1/permissions"},
		{http.MethodGet, "/api/v1/permissions"},
		{http.MethodGet, "/api/v1/permissions/1"},
		{http.MethodPost, "/api/v1/permissions"},
		{http.MethodPut, "/api/v1/permissions/1"},
		{http.MethodDelete, "/api/v1/permissions/1"},
	}

	for _, tt := range protected {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
		})
	}
}

func TestProtectedRoutesRejectInvalidToken(t *testing.T) {
	r := newTestRouter()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "garbage"})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestUnknownRoute(t *testing.T) {
	r := newTestRouter()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/unknown", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
