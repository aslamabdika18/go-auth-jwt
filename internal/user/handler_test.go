package user

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aslamabdika18/go-auth-jwt/internal/auth"
	"github.com/aslamabdika18/go-auth-jwt/internal/middleware"
	"github.com/gin-gonic/gin"
)

const testRefreshTTL = 7 * 24 * time.Hour

func newTestHandler(secureCookie bool) *Handler {
	jwtService := auth.NewJWT("handler-test-secret", 15)
	service := NewService(nil, jwtService, testRefreshTTL)

	return NewHandler(service, jwtService, secureCookie)
}

func newTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)

	h := newTestHandler(false)
	r := gin.New()

	r.POST("/register", h.Register)
	r.POST("/login", h.Login)
	r.POST("/refresh", h.Refresh)
	r.GET("/users", h.ListUsers)
	r.GET("/users/:id", h.GetUser)
	r.PUT("/users/:id", h.UpdateUser)
	r.DELETE("/users/:id", h.DeleteUser)

	// Logout dites dengan nilai context yang disuntikkan lewat header,
	// meniru hasil middleware Auth.
	r.POST("/logout", func(c *gin.Context) {
		if v := c.GetHeader("X-Test-User"); v != "" {
			var id int
			for _, ch := range v {
				id = id*10 + int(ch-'0')
			}
			c.Set(middleware.UserIDKey, id)
		}
		if v := c.GetHeader("X-Test-Session"); v != "" {
			c.Set(middleware.SessionIDKey, v)
		}
		c.Next()
	}, h.Logout)

	return r
}

func send(r http.Handler, method, path, body string, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	for _, m := range mutate {
		m(req)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

func bodyMap(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}

	return m
}

func fieldsOf(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	fields, ok := bodyMap(t, w)["fields"].(map[string]any)
	if !ok {
		t.Fatalf("response has no fields object: %s", w.Body.String())
	}

	return fields
}

func TestRegister_InvalidBody(t *testing.T) {
	r := newTestRouter()

	w := send(r, http.MethodPost, "/register", "{")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if got := bodyMap(t, w)["error"]; got != "invalid request body" {
		t.Fatalf("error = %v", got)
	}
}

func TestRegister_ValidationMessages(t *testing.T) {
	r := newTestRouter()

	tests := []struct {
		name       string
		body       string
		wantFields map[string]string
	}{
		{
			"all fields missing",
			`{}`,
			map[string]string{
				"name":     "this field is required",
				"email":    "this field is required",
				"password": "this field is required",
			},
		},
		{
			"name too short",
			`{"name":"ab","email":"a@example.com","password":"password123"}`,
			map[string]string{"name": "must be at least 3 characters"},
		},
		{
			"name too long",
			`{"name":"` + strings.Repeat("a", 101) + `","email":"a@example.com","password":"password123"}`,
			map[string]string{"name": "must not exceed 100 characters"},
		},
		{
			"invalid email",
			`{"name":"Aslam","email":"nope","password":"password123"}`,
			map[string]string{"email": "must be a valid email address"},
		},
		{
			"password too short",
			`{"name":"Aslam","email":"a@example.com","password":"short"}`,
			map[string]string{"password": "must be at least 8 characters"},
		},
		{
			"password too long",
			`{"name":"Aslam","email":"a@example.com","password":"` + strings.Repeat("p", 73) + `"}`,
			map[string]string{"password": "must not exceed 72 characters"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := send(r, http.MethodPost, "/register", tt.body)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
			if got := bodyMap(t, w)["error"]; got != "validation failed" {
				t.Fatalf("error = %v, want validation failed", got)
			}

			fields := fieldsOf(t, w)
			if len(fields) != len(tt.wantFields) {
				t.Fatalf("fields = %v, want %v", fields, tt.wantFields)
			}
			for key, want := range tt.wantFields {
				if fields[key] != want {
					t.Errorf("fields[%s] = %v, want %q", key, fields[key], want)
				}
			}
		})
	}
}

func TestLogin_InvalidBody(t *testing.T) {
	r := newTestRouter()

	w := send(r, http.MethodPost, "/login", "not json")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if got := bodyMap(t, w)["error"]; got != "invalid request body" {
		t.Fatalf("error = %v", got)
	}
}

func TestLogin_ValidationMessages(t *testing.T) {
	r := newTestRouter()

	w := send(r, http.MethodPost, "/login", `{}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}

	fields := fieldsOf(t, w)
	if fields["email"] != "this field is required" || fields["password"] != "this field is required" {
		t.Fatalf("fields = %v", fields)
	}

	w = send(r, http.MethodPost, "/login", `{"email":"bad","password":"x"}`)
	if got := fieldsOf(t, w)["email"]; got != "must be a valid email address" {
		t.Fatalf("email message = %v", got)
	}
}

func TestRefresh_MissingCookie(t *testing.T) {
	r := newTestRouter()

	w := send(r, http.MethodPost, "/refresh", "")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if got := bodyMap(t, w)["error"]; got != "refresh token required" {
		t.Fatalf("error = %v", got)
	}
}

func TestRefresh_BlankCookieClearsAuthCookies(t *testing.T) {
	r := newTestRouter()

	w := send(r, http.MethodPost, "/refresh", "", func(req *http.Request) {
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "%20%20"})
	})

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if got := bodyMap(t, w)["error"]; got != "invalid or expired refresh token" {
		t.Fatalf("error = %v", got)
	}

	cleared := map[string]bool{}
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 && c.Value == "" {
			cleared[c.Name] = true
		}
	}
	if !cleared["access_token"] || !cleared["refresh_token"] {
		t.Fatalf("both auth cookies should be cleared, got %v", cleared)
	}
}

func TestLogout_RequiresIdentityInContext(t *testing.T) {
	r := newTestRouter()

	tests := []struct {
		name    string
		headers map[string]string
	}{
		{"no identity at all", nil},
		{"user without session", map[string]string{"X-Test-User": "5"}},
		{"session without user", map[string]string{"X-Test-Session": "sess"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := send(r, http.MethodPost, "/logout", "", func(req *http.Request) {
				for k, v := range tt.headers {
					req.Header.Set(k, v)
				}
			})

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
			if got := bodyMap(t, w)["error"]; got != "authentication required" {
				t.Fatalf("error = %v", got)
			}
		})
	}
}

func TestListUsers_InvalidQuery(t *testing.T) {
	r := newTestRouter()

	paginationMsg := "page must be at least 1 and page_size must be between 1 and 100"

	tests := []struct {
		name    string
		query   string
		wantErr string
	}{
		{"page not a number", "?page=abc", "page must be a positive integer"},
		{"page size not a number", "?page_size=abc", "page_size must be an integer"},
		{"page zero", "?page=0", paginationMsg},
		{"page negative", "?page=-1", paginationMsg},
		{"page size zero", "?page_size=0", paginationMsg},
		{"page size negative", "?page_size=-10", paginationMsg},
		{"page size above max", "?page_size=101", paginationMsg},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := send(r, http.MethodGet, "/users"+tt.query, "")

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
			if got := bodyMap(t, w)["error"]; got != tt.wantErr {
				t.Fatalf("error = %v, want %q", got, tt.wantErr)
			}
		})
	}
}

func TestUserRoutes_InvalidID(t *testing.T) {
	r := newTestRouter()

	for _, id := range []string{"abc", "0", "-1", "1.5"} {
		for _, tt := range []struct{ method, body string }{
			{http.MethodGet, ""},
			{http.MethodPut, `{"name":"Aslam","email":"a@example.com"}`},
			{http.MethodDelete, ""},
		} {
			t.Run(tt.method+" /users/"+id, func(t *testing.T) {
				w := send(r, tt.method, "/users/"+id, tt.body)

				if w.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400", w.Code)
				}
				if got := bodyMap(t, w)["error"]; got != "invalid user id" {
					t.Fatalf("error = %v", got)
				}
			})
		}
	}
}

func TestUpdateUser_InvalidBody(t *testing.T) {
	r := newTestRouter()

	w := send(r, http.MethodPut, "/users/1", "{")
	if w.Code != http.StatusBadRequest || bodyMap(t, w)["error"] != "invalid request body" {
		t.Fatalf("malformed json: status %d body %s", w.Code, w.Body.String())
	}

	w = send(r, http.MethodPut, "/users/1", `{}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}

	fields := fieldsOf(t, w)
	if fields["name"] != "this field is required" || fields["email"] != "this field is required" {
		t.Fatalf("fields = %v", fields)
	}
}

func parseCookies(t *testing.T, w *httptest.ResponseRecorder) map[string]*http.Cookie {
	t.Helper()

	cookies := map[string]*http.Cookie{}
	for _, c := range w.Result().Cookies() {
		cookies[c.Name] = c
	}

	return cookies
}

func TestSetAuthCookies(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "insecure", true: "secure"}[secure], func(t *testing.T) {
			h := newTestHandler(secure)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

			h.setAccessTokenCookie(c, "access-value")
			h.setRefreshTokenCookie(c, "refresh-value")

			cookies := parseCookies(t, w)

			access := cookies["access_token"]
			if access == nil {
				t.Fatal("access_token cookie not set")
			}
			if access.Value != "access-value" || access.Path != "/" ||
				access.MaxAge != 15*60 || !access.HttpOnly ||
				access.Secure != secure || access.SameSite != http.SameSiteLaxMode {
				t.Errorf("unexpected access cookie: %+v", access)
			}

			refresh := cookies["refresh_token"]
			if refresh == nil {
				t.Fatal("refresh_token cookie not set")
			}
			if refresh.Value != "refresh-value" || refresh.Path != "/api/v1/auth" ||
				refresh.MaxAge != int(testRefreshTTL.Seconds()) || !refresh.HttpOnly ||
				refresh.Secure != secure || refresh.SameSite != http.SameSiteLaxMode {
				t.Errorf("unexpected refresh cookie: %+v", refresh)
			}
		})
	}
}

func TestClearAuthCookies(t *testing.T) {
	h := newTestHandler(true)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

	h.clearAuthCookies(c)

	cookies := parseCookies(t, w)

	for name, path := range map[string]string{
		"access_token":  "/",
		"refresh_token": "/api/v1/auth",
	} {
		cookie := cookies[name]
		if cookie == nil {
			t.Fatalf("%s cookie not set", name)
		}
		if cookie.Value != "" || cookie.MaxAge >= 0 || cookie.Path != path ||
			!cookie.HttpOnly || !cookie.Secure {
			t.Errorf("%s cookie not cleared properly: %+v", name, cookie)
		}
	}
}

func TestQueryInt(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name    string
		query   string
		want    int
		wantErr bool
	}{
		{"missing uses default", "", 20, false},
		{"empty value uses default", "?n=", 20, false},
		{"valid", "?n=5", 5, false},
		{"negative", "?n=-3", -3, false},
		{"not a number", "?n=abc", 0, true},
		{"decimal", "?n=1.5", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodGet, "/"+tt.query, nil)

			got, err := queryInt(c, "n", 20)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("queryInt = %d, want %d", got, tt.want)
			}
		})
	}
}
