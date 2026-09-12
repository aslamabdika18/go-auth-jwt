package main

import (
	"log"
	"time"

	"github.com/aslamabdika18/go-auth-jwt/internal/auth"
	"github.com/aslamabdika18/go-auth-jwt/internal/config"
	"github.com/aslamabdika18/go-auth-jwt/internal/database"
	"github.com/aslamabdika18/go-auth-jwt/internal/router"
	"github.com/aslamabdika18/go-auth-jwt/internal/user"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	if cfg.AppEnv == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	databaseURL := database.ConnectionString(cfg)

	if err := database.Migrate(databaseURL); err != nil {
		log.Fatal(err)
	}

	db, err := database.Connect(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	jwtService := auth.NewJWT(
		cfg.JWTSecret,
		cfg.JWTAccessTokenTTL,
	)

	refreshTokenTTL :=
		time.Duration(
			cfg.JWTRefreshTokenTTL,
		) * time.Minute

	userRepository := user.NewRepository(db)

	userService := user.NewService(
		userRepository,
		jwtService,
		refreshTokenTTL,
	)

	secureCookie := cfg.AppEnv == "production"

	userHandler := user.NewHandler(
		userService,
		jwtService,
		secureCookie,
	)

	app := router.New(
		userHandler,
		jwtService,
	)

	log.Printf(
		"server running on port %s",
		cfg.AppPort,
	)

	if err := app.Run(":" + cfg.AppPort); err != nil {
		log.Fatal(err)
	}
}
