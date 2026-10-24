package auth

import (
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWT struct {
	secretKey []byte
	ttl       time.Duration
}

type AccessClaims struct {
	SessionID string
	UserID    int
}

func NewJWT(secret string, ttlMinutes int) *JWT {
	return &JWT{
		secretKey: []byte(secret),
		ttl:       time.Duration(ttlMinutes) * time.Minute,
	}
}

func (j *JWT) GenerateAccessToken(userID int, sessionID string) (string, error) {
	if userID <= 0 {
		return "", fmt.Errorf("invalid user ID")
	}
	if sessionID == "" {
		return "", fmt.Errorf("session ID is required")
	}
	if len(j.secretKey) == 0 {
		return "", fmt.Errorf("JWT secret is required")
	}
	if j.ttl <= 0 {
		return "", fmt.Errorf("access token TTL must be positive")
	}

	now := time.Now()

	claims := jwt.RegisteredClaims{
		Subject:   strconv.Itoa(userID),
		ID:        sessionID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(j.ttl)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(j.secretKey)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}

	return signedToken, nil
}

func (j *JWT) ValidateAccessToken(tokenString string) (*AccessClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("token is required")
	}
	if len(j.secretKey) == 0 {
		return nil, fmt.Errorf("JWT secret is required")
	}

	claims := &jwt.RegisteredClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
			}
			return j.secretKey, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse access token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid access token")
	}

	userID, err := strconv.Atoi(claims.Subject)
	if err != nil || userID <= 0 {
		return nil, fmt.Errorf("invalid user ID in token")
	}
	if claims.ID == "" {
		return nil, fmt.Errorf("session ID missing from token")
	}

	return &AccessClaims{
		UserID:    userID,
		SessionID: claims.ID,
	}, nil
}

func (j *JWT) MaxAge() int {
	return int(j.ttl.Seconds())
}
