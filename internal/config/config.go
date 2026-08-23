package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	AppName string
	AppEnv  string
	AppPort string

	DBHost     string
	DBPort     string
	DBName     string
	DBUser     string
	DBPassword string
	DBSSLMode  string

	JWTSecret         string
	JWTAccessTokenTTL int
}

func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, fmt.Errorf("load .env: %w", err)
	}

	jwtAccessTokenTTL, err := strconv.Atoi(
		os.Getenv("JWT_ACCESS_TOKEN_TTL"),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"JWT_ACCESS_TOKEN_TTL must be a valid number: %w",
			err,
		)
	}

	cfg := &Config{
		AppName: os.Getenv("APP_NAME"),
		AppEnv:  os.Getenv("APP_ENV"),
		AppPort: os.Getenv("APP_PORT"),

		DBHost:     os.Getenv("DB_HOST"),
		DBPort:     os.Getenv("DB_PORT"),
		DBName:     os.Getenv("DB_NAME"),
		DBUser:     os.Getenv("DB_USER"),
		DBPassword: os.Getenv("DB_PASSWORD"),
		DBSSLMode:  os.Getenv("DB_SSLMODE"),

		JWTSecret:         os.Getenv("JWT_SECRET"),
		JWTAccessTokenTTL: jwtAccessTokenTTL,
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	required := map[string]string{
		"APP_NAME":    c.AppName,
		"APP_ENV":     c.AppEnv,
		"APP_PORT":    c.AppPort,
		"DB_HOST":     c.DBHost,
		"DB_PORT":     c.DBPort,
		"DB_NAME":     c.DBName,
		"DB_USER":     c.DBUser,
		"DB_PASSWORD": c.DBPassword,
		"DB_SSLMODE":  c.DBSSLMode,
		"JWT_SECRET":  c.JWTSecret,
	}

	for key, value := range required {
		if value == "" {
			return fmt.Errorf("environment variable %s is required", key)
		}
	}

	if c.JWTAccessTokenTTL <= 0 {
		return fmt.Errorf(
			"JWT_ACCESS_TOKEN_TTL must be greater than 0",
		)
	}

	return nil
}
