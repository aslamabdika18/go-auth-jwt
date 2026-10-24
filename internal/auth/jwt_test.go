package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "unit-test-secret-key"

func signToken(
	t *testing.T,
	secret string,
	method jwt.SigningMethod,
	claims jwt.RegisteredClaims,
) string {
	t.Helper()

	var key any = []byte(secret)
	if method == jwt.SigningMethodNone {
		key = jwt.UnsafeAllowNoneSignatureType
	}

	token, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return token
}

func validClaims() jwt.RegisteredClaims {
	now := time.Now()

	return jwt.RegisteredClaims{
		Subject:   "42",
		ID:        "session-abc",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
	}
}

func TestJWT_MaxAge(t *testing.T) {
	j := NewJWT(testSecret, 15)

	if got, want := j.MaxAge(), 15*60; got != want {
		t.Fatalf("MaxAge() = %d, want %d", got, want)
	}
}

func TestGenerateAccessToken_Success(t *testing.T) {
	j := NewJWT(testSecret, 15)

	token, err := j.GenerateAccessToken(42, "session-abc")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	if strings.Count(token, ".") != 2 {
		t.Fatalf("token should have 3 segments, got %q", token)
	}

	claims, err := j.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}

	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
	if claims.SessionID != "session-abc" {
		t.Errorf("SessionID = %q, want session-abc", claims.SessionID)
	}
}

func TestGenerateAccessToken_ExpiryMatchesTTL(t *testing.T) {
	j := NewJWT(testSecret, 30)

	token, err := j.GenerateAccessToken(1, "s")
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	parsed := &jwt.RegisteredClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, parsed); err != nil {
		t.Fatalf("parse unverified: %v", err)
	}

	got := parsed.ExpiresAt.Sub(parsed.IssuedAt.Time)
	if got != 30*time.Minute {
		t.Fatalf("exp - iat = %v, want 30m", got)
	}
	if parsed.Subject != "1" || parsed.ID != "s" {
		t.Fatalf("unexpected sub/jti: %q / %q", parsed.Subject, parsed.ID)
	}
}

func TestGenerateAccessToken_InvalidInput(t *testing.T) {
	tests := []struct {
		name      string
		jwt       *JWT
		userID    int
		sessionID string
		wantErr   string
	}{
		{"zero user id", NewJWT(testSecret, 15), 0, "s", "invalid user ID"},
		{"negative user id", NewJWT(testSecret, 15), -1, "s", "invalid user ID"},
		{"empty session id", NewJWT(testSecret, 15), 1, "", "session ID is required"},
		{"empty secret", NewJWT("", 15), 1, "s", "JWT secret is required"},
		{"zero ttl", NewJWT(testSecret, 0), 1, "s", "TTL must be positive"},
		{"negative ttl", NewJWT(testSecret, -5), 1, "s", "TTL must be positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := tt.jwt.GenerateAccessToken(tt.userID, tt.sessionID)
			if err == nil {
				t.Fatalf("expected error, got token %q", token)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.wantErr)
			}
			if token != "" {
				t.Fatalf("token should be empty on error, got %q", token)
			}
		})
	}
}

func TestValidateAccessToken_Valid(t *testing.T) {
	j := NewJWT(testSecret, 15)
	token := signToken(t, testSecret, jwt.SigningMethodHS256, validClaims())

	claims, err := j.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}
	if claims.UserID != 42 || claims.SessionID != "session-abc" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestValidateAccessToken_Rejected(t *testing.T) {
	j := NewJWT(testSecret, 15)

	expired := validClaims()
	expired.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))

	noExp := validClaims()
	noExp.ExpiresAt = nil

	noJTI := validClaims()
	noJTI.ID = ""

	badSub := validClaims()
	badSub.Subject = "abc"

	zeroSub := validClaims()
	zeroSub.Subject = "0"

	negSub := validClaims()
	negSub.Subject = "-7"

	emptySub := validClaims()
	emptySub.Subject = ""

	otherSecret := signToken(t, "another-secret", jwt.SigningMethodHS256, validClaims())

	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"garbage", "not-a-jwt"},
		{"two segments", "aaa.bbb"},
		{"wrong secret", otherSecret},
		{"expired", signToken(t, testSecret, jwt.SigningMethodHS256, expired)},
		{"missing exp", signToken(t, testSecret, jwt.SigningMethodHS256, noExp)},
		{"missing jti", signToken(t, testSecret, jwt.SigningMethodHS256, noJTI)},
		{"non numeric subject", signToken(t, testSecret, jwt.SigningMethodHS256, badSub)},
		{"zero subject", signToken(t, testSecret, jwt.SigningMethodHS256, zeroSub)},
		{"negative subject", signToken(t, testSecret, jwt.SigningMethodHS256, negSub)},
		{"empty subject", signToken(t, testSecret, jwt.SigningMethodHS256, emptySub)},
		{"HS512 instead of HS256", signToken(t, testSecret, jwt.SigningMethodHS512, validClaims())},
		{"alg none", signToken(t, "", jwt.SigningMethodNone, validClaims())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := j.ValidateAccessToken(tt.token)
			if err == nil {
				t.Fatalf("expected error, got claims %+v", claims)
			}
			if claims != nil {
				t.Fatalf("claims should be nil on error, got %+v", claims)
			}
		})
	}
}

func TestValidateAccessToken_ExpiredWrapsSentinel(t *testing.T) {
	j := NewJWT(testSecret, 15)

	expired := validClaims()
	expired.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))

	_, err := j.ValidateAccessToken(
		signToken(t, testSecret, jwt.SigningMethodHS256, expired),
	)
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("error = %v, want it to wrap jwt.ErrTokenExpired", err)
	}
}

func TestValidateAccessToken_EmptySecret(t *testing.T) {
	j := NewJWT("", 15)

	if _, err := j.ValidateAccessToken("a.b.c"); err == nil ||
		!strings.Contains(err.Error(), "JWT secret is required") {
		t.Fatalf("error = %v, want JWT secret is required", err)
	}
}

func TestValidateAccessToken_TamperedPayload(t *testing.T) {
	j := NewJWT(testSecret, 15)

	victim := signToken(t, testSecret, jwt.SigningMethodHS256, validClaims())

	adminClaims := validClaims()
	adminClaims.Subject = "1"
	attacker := signToken(t, "attacker-secret", jwt.SigningMethodHS256, adminClaims)

	v := strings.Split(victim, ".")
	a := strings.Split(attacker, ".")

	// Payload milik attacker + signature milik korban harus ditolak.
	forged := strings.Join([]string{v[0], a[1], v[2]}, ".")

	if _, err := j.ValidateAccessToken(forged); err == nil {
		t.Fatal("forged token must be rejected")
	}
}
