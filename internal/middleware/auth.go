package middleware

import (
	"context"
	"net/http"

	"github.com/aslamabdika18/go-auth-jwt/internal/auth"
	"github.com/aslamabdika18/go-auth-jwt/internal/rbac"
	"github.com/gin-gonic/gin"
)

const (
	UserIDKey    = "userID"
	SessionIDKey = "sessionID"
)

type SessionVerifier interface {
	IsSessionActive(
		ctx context.Context,
		sessionID string,
		userID int,
	) (bool, error)
}

func Auth(
	jwtService *auth.JWT,
	sessionVerifier SessionVerifier,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("access_token")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
			})
			c.Abort()
			return
		}

		claims, err := jwtService.ValidateAccessToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
			})
			c.Abort()
			return
		}

		active, err := sessionVerifier.IsSessionActive(
			c.Request.Context(),
			claims.SessionID,
			claims.UserID,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to verify session",
			})
			c.Abort()
			return
		}

		if !active {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "session expired or revoked",
			})
			c.Abort()
			return
		}

		c.Set(UserIDKey, claims.UserID)
		c.Set(SessionIDKey, claims.SessionID)
		c.Next()
	}
}

func RequireSuperadmin(rbacService *rbac.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		value, exists := c.Get(UserIDKey)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
			})
			c.Abort()
			return
		}

		userID, ok := value.(int)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid user context",
			})
			c.Abort()
			return
		}

		isSuperadmin, err := rbacService.IsSuperadmin(
			c.Request.Context(),
			userID,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to verify authorization",
			})
			c.Abort()
			return
		}

		if !isSuperadmin {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "superadmin access required",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func RequirePermission(
	rbacService *rbac.Service,
	permission string,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		value, exists := c.Get(UserIDKey)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
			})
			c.Abort()
			return
		}

		userID, ok := value.(int)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid user context",
			})
			c.Abort()
			return
		}

		allowed, err := rbacService.HasPermission(
			c.Request.Context(),
			userID,
			permission,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to verify permission",
			})
			c.Abort()
			return
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "permission denied",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
