package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

type RefreshToken struct {
	Token     string
	TokenHash string
	ExpiresAt time.Time
}

func GenerateRefreshToken(
	ttl time.Duration,
) (*RefreshToken, error) {
	randomBytes := make([]byte, 32)

	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf(
			"generate refresh token: %w",
			err,
		)
	}

	token := base64.RawURLEncoding.EncodeToString(randomBytes)

	tokenHash := sha256.Sum256([]byte(token))

	return &RefreshToken{
		Token:     token,
		TokenHash: fmt.Sprintf("%x", tokenHash),
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}

func HashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))

	return fmt.Sprintf("%x", hash)
}
