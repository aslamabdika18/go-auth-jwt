package database

import (
	"context"
	"fmt"

	"github.com/aslamabdika18/go-auth-jwt/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func ConnectionString(cfg *config.Config) string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBName,
		cfg.DBSSLMode,
	)
}

func Connect(cfg *config.Config) (*pgxpool.Pool, error) {
	connString := ConnectionString(cfg)

	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()

		return nil, fmt.Errorf("ping database: %w", err)
	}

	return pool, nil
}
