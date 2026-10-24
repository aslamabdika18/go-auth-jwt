package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func GenerateSessionID() (string, error) {
	var randomBytes [32]byte

	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes[:]), nil
}
