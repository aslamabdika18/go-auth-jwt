package database

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/aslamabdika18/go-auth-jwt/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func ConnectionString(cfg *config.Config) string {
	dbName := strings.TrimPrefix(cfg.DBName, "/")

	query := url.Values{}
	query.Set("sslmode", cfg.DBSSLMode)

	u := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(cfg.DBUser, cfg.DBPassword),
		Host:     net.JoinHostPort(cfg.DBHost, cfg.DBPort),
		Path:     "/" + dbName,
		RawQuery: query.Encode(),
	}

	return u.String()
}

func Connect(cfg *config.Config) (*pgxpool.Pool, error) {
	const connectTimeout = 5 * time.Second

	ctx, cancel := context.WithTimeout(
		context.Background(),
		connectTimeout,
	)
	defer cancel()

	connString := ConnectionString(cfg)

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("create database pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return pool, nil
}
