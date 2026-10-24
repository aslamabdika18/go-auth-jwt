package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aslamabdika18/go-auth-jwt/internal/auth"
	"github.com/aslamabdika18/go-auth-jwt/internal/rbac"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "middleware-test-secret"

type fakeVerifier struct {
	active bool
	err    error

	calls     int
	gotSessID string
	gotUserID int
}

func (f *fakeVerifier) IsSessionActive(
	_ context.Context,
	sessionID string,
	userID int,
) (bool, error) {
	f.calls++
	f.gotSessID = sessionID
	f.gotUserID = userID

	return f.active, f.err
}

func newAuthRouter(j *auth.JWT, v SessionVerifier, handlerCalled *bool) *gin.Engine {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/protected", Auth(j, v), func(c *gin.Context) {
		*handlerCalled = true
		c.JSON(http.StatusOK, gin.H{
			"user_id":    c.GetInt(UserIDKey),
			"session_id": c.GetString(SessionIDKey),
		})
	})

	return r
}

func doGet(r http.Handler, path, cookieName, cookieValue string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookieName != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}

	return body
}

func TestAuth_MissingCookie(t *testing.T) {
	called := false
	v := &fakeVerifier{active: true}
	r := newAuthRouter(auth.NewJWT(testSecret, 15), v, &called)

	w := doGet(r, "/protected", "", "")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if got := decode(t, w)["error"]; got != "authentication required" {
		t.Fatalf("error = %v", got)
	}
	if called || v.calls != 0 {
		t.Fatal("handler and session verifier must not be called")
	}
}

func TestAuth_InvalidTokens(t *testing.T) {
	j := auth.NewJWT(testSecret, 15)

	expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "1",
		ID:        "sess",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}

	foreign, err := auth.NewJWT("other-secret", 15).GenerateAccessToken(1, "sess")
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		"garbage":       "not-a-jwt",
		"expired":       expired,
		"wrong secret":  foreign,
		"empty content": " ",
	}

	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			called := false
			v := &fakeVerifier{active: true}
			r := newAuthRouter(j, v, &called)

			w := doGet(r, "/protected", "access_token", token)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
			if got := decode(t, w)["error"]; got != "invalid or expired token" {
				t.Fatalf("error = %v", got)
			}
			if called || v.calls != 0 {
				t.Fatal("handler and session verifier must not be called")
			}
		})
	}
}

func TestAuth_SessionVerifierError(t *testing.T) {
	j := auth.NewJWT(testSecret, 15)
	token, _ := j.GenerateAccessToken(5, "sess-5")

	called := false
	v := &fakeVerifier{err: errors.New("db down")}
	r := newAuthRouter(j, v, &called)

	w := doGet(r, "/protected", "access_token", token)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if got := decode(t, w)["error"]; got != "failed to verify session" {
		t.Fatalf("error = %v", got)
	}
	if called {
		t.Fatal("handler must not be called")
	}
}

func TestAuth_SessionRevoked(t *testing.T) {
	j := auth.NewJWT(testSecret, 15)
	token, _ := j.GenerateAccessToken(5, "sess-5")

	called := false
	v := &fakeVerifier{active: false}
	r := newAuthRouter(j, v, &called)

	w := doGet(r, "/protected", "access_token", token)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if got := decode(t, w)["error"]; got != "session expired or revoked" {
		t.Fatalf("error = %v", got)
	}
	if called {
		t.Fatal("handler must not be called")
	}
}

func TestAuth_Success(t *testing.T) {
	j := auth.NewJWT(testSecret, 15)
	token, _ := j.GenerateAccessToken(77, "sess-77")

	called := false
	v := &fakeVerifier{active: true}
	r := newAuthRouter(j, v, &called)

	w := doGet(r, "/protected", "access_token", token)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if !called {
		t.Fatal("handler should be called")
	}

	body := decode(t, w)
	if body["user_id"] != float64(77) || body["session_id"] != "sess-77" {
		t.Fatalf("context values not propagated: %v", body)
	}

	if v.calls != 1 || v.gotUserID != 77 || v.gotSessID != "sess-77" {
		t.Fatalf("verifier got user=%d session=%q calls=%d", v.gotUserID, v.gotSessID, v.calls)
	}
}

func TestAuth_IgnoresAuthorizationHeader(t *testing.T) {
	j := auth.NewJWT(testSecret, 15)
	token, _ := j.GenerateAccessToken(1, "s")

	called := false
	r := newAuthRouter(j, &fakeVerifier{active: true}, &called)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized || called {
		t.Fatalf("only the access_token cookie should be accepted, got status %d", w.Code)
	}
}

// Jalur RequireSuperadmin dan RequirePermission yang berhenti sebelum
// menyentuh database (user ID tidak ada atau tipenya salah).

func routerWithUserIDValue(mw gin.HandlerFunc, set bool, value any) *gin.Engine {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/guarded",
		func(c *gin.Context) {
			if set {
				c.Set(UserIDKey, value)
			}
			c.Next()
		},
		mw,
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	return r
}

func TestRequireSuperadmin_ContextGuards(t *testing.T) {
	mw := RequireSuperadmin(rbac.NewService(nil))

	tests := []struct {
		name    string
		set     bool
		value   any
		wantErr string
	}{
		{"user id missing", false, nil, "authentication required"},
		{"user id wrong type string", true, "12", "invalid user context"},
		{"user id wrong type int64", true, int64(12), "invalid user context"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := doGet(routerWithUserIDValue(mw, tt.set, tt.value), "/guarded", "", "")

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
			if got := decode(t, w)["error"]; got != tt.wantErr {
				t.Fatalf("error = %v, want %s", got, tt.wantErr)
			}
		})
	}
}

func TestRequirePermission_ContextGuards(t *testing.T) {
	mw := RequirePermission(rbac.NewService(nil), "users.read")

	tests := []struct {
		name    string
		set     bool
		value   any
		wantErr string
	}{
		{"user id missing", false, nil, "authentication required"},
		{"user id wrong type string", true, "12", "invalid user context"},
		{"user id wrong type float", true, 12.0, "invalid user context"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := doGet(routerWithUserIDValue(mw, tt.set, tt.value), "/guarded", "", "")

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
			if got := decode(t, w)["error"]; got != tt.wantErr {
				t.Fatalf("error = %v, want %s", got, tt.wantErr)
			}
		})
	}
}

// Permission kosong ditolak oleh rbac.Service sebelum query dijalankan,
// sehingga middleware harus membalas 403.
func TestRequirePermission_EmptyPermissionIsDenied(t *testing.T) {
	mw := RequirePermission(rbac.NewService(nil), "   ")
	w := doGet(routerWithUserIDValue(mw, true, 1), "/guarded", "", "")

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if got := decode(t, w)["error"]; got != "permission denied" {
		t.Fatalf("error = %v", got)
	}
}
