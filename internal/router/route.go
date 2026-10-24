package router

import (
	"net/http"

	"github.com/aslamabdika18/go-auth-jwt/internal/auth"
	"github.com/aslamabdika18/go-auth-jwt/internal/middleware"
	"github.com/aslamabdika18/go-auth-jwt/internal/rbac"
	"github.com/aslamabdika18/go-auth-jwt/internal/user"
	"github.com/gin-gonic/gin"
)

func New(
	userHandler *user.Handler,
	rbacHandler *rbac.Handler,
	jwtService *auth.JWT,
	rbacService *rbac.Service,
	userService *user.Service,
) *gin.Engine {
	router := gin.Default()

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	api := router.Group("/api/v1")

	// Authentication routes
	authRoutes := api.Group("/auth")
	{
		authRoutes.POST(
			"/register",
			userHandler.Register,
		)

		authRoutes.POST(
			"/login",
			userHandler.Login,
		)

		authRoutes.POST(
			"/refresh",
			userHandler.Refresh,
		)

		authRoutes.POST(
			"/logout",
			middleware.Auth(jwtService, userService),
			userHandler.Logout,
		)

		authRoutes.GET(
			"/me",
			middleware.Auth(jwtService, userService),
			userHandler.Me,
		)
	}

	// Read users
	userReadRoutes := api.Group("/users")
	userReadRoutes.Use(
		middleware.Auth(jwtService, userService),
		middleware.RequirePermission(
			rbacService,
			"users.read",
		),
	)
	{
		userReadRoutes.GET("", userHandler.ListUsers)
		userReadRoutes.GET("/:id", userHandler.GetUser)
	}

	// Update users
	userUpdateRoutes := api.Group("/users")
	userUpdateRoutes.Use(
		middleware.Auth(jwtService, userService),
		middleware.RequirePermission(
			rbacService,
			"users.update",
		),
	)
	{
		userUpdateRoutes.PUT("/:id", userHandler.UpdateUser)
	}

	// Delete users
	userDeleteRoutes := api.Group("/users")
	userDeleteRoutes.Use(
		middleware.Auth(jwtService, userService),
		middleware.RequirePermission(
			rbacService,
			"users.delete",
		),
	)
	{
		userDeleteRoutes.DELETE("/:id", userHandler.DeleteUser)
	}

	// Roles: superadmin only
	roleRoutes := api.Group("/roles")
	roleRoutes.Use(
		middleware.Auth(jwtService, userService),
		middleware.RequireSuperadmin(rbacService),
	)
	{
		roleRoutes.GET("", rbacHandler.ListRoles)
		roleRoutes.GET("/:id", rbacHandler.GetRole)
		roleRoutes.POST("", rbacHandler.CreateRole)
		roleRoutes.PUT("/:id", rbacHandler.UpdateRole)
		roleRoutes.DELETE("/:id", rbacHandler.DeleteRole)

		roleRoutes.PUT(
			"/:id/permissions",
			rbacHandler.UpdateRolePermissions,
		)
	}

	// Permissions: superadmin only
	permissionRoutes := api.Group("/permissions")
	permissionRoutes.Use(
		middleware.Auth(jwtService, userService),
		middleware.RequireSuperadmin(rbacService),
	)
	{
		permissionRoutes.GET("", rbacHandler.ListPermissions)
		permissionRoutes.GET("/:id", rbacHandler.GetPermission)
		permissionRoutes.POST("", rbacHandler.CreatePermission)
		permissionRoutes.PUT("/:id", rbacHandler.UpdatePermission)
		permissionRoutes.DELETE("/:id", rbacHandler.DeletePermission)
	}

	// Assign roles: superadmin only
	userRoleRoutes := api.Group("/users")
	userRoleRoutes.Use(
		middleware.Auth(jwtService, userService),
		middleware.RequireSuperadmin(rbacService),
	)
	{
		userRoleRoutes.PUT("/:id/role", rbacHandler.UpdateUserRole)
	}

	return router
}
