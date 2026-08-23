package middleware

import (
	"net/http"

	"github.com/aslamabdika18/go-auth-jwt/internal/auth"
	"github.com/gin-gonic/gin"
)

const UserIDKey = "userID"

func Auth(jwtService *auth.JWT) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("access_token")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
			})
			c.Abort()
			return
		}

		userID, err := jwtService.ValidateAccessToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
			})
			c.Abort()
			return
		}

		c.Set(UserIDKey, userID)

		c.Next()
	}
}
