package router

import (
	"net/http"

	"github.com/aslamabdika18/go-auth-jwt/internal/auth"
	"github.com/aslamabdika18/go-auth-jwt/internal/middleware"
	"github.com/aslamabdika18/go-auth-jwt/internal/user"
	"github.com/gin-gonic/gin"
)

func New(
	userHandler *user.Handler,
	jwtService *auth.JWT,
) *gin.Engine {
	router := gin.Default()

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	api := router.Group("/api/v1")

	authRoutes := api.Group("/auth")
	{
		authRoutes.POST("/register", userHandler.Register)
		authRoutes.POST("/login", userHandler.Login)
		authRoutes.POST("/logout", userHandler.Logout)
		authRoutes.GET(
			"/me",
			middleware.Auth(jwtService),
			userHandler.Me,
		)
	}
	return router
}
