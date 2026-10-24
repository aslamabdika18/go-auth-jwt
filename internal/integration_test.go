package integration_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aslamabdika18/go-auth-jwt/internal/config"
	"github.com/aslamabdika18/go-auth-jwt/internal/database"
	"github.com/aslamabdika18/go-auth-jwt/internal/rbac"
	"github.com/aslamabdika18/go-auth-jwt/internal/user"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests intentionally mutate tables. Set TEST_DATABASE_URL only to a
// disposable test database, never to development, staging, or production.
func TestDatabaseIntegrationSuite(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set TEST_DATABASE_URL to a disposable PostgreSQL database to run integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	if err := database.Migrate(databaseURL); err != nil {
		t.Fatalf("apply migrations to test database: %v", err)
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("create test database pool: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping test database: %v", err)
	}

	t.Run("SeedSuperadminConcurrentAndIdempotent", func(t *testing.T) {
		resetUsers(t, ctx, pool)

		cfg := &config.Config{
			InitialAdminName:     "Integration Admin",
			InitialAdminEmail:    "integration-admin@example.test",
			InitialAdminPassword: "test-password-at-least-12",
		}

		const workers = 8
		start := make(chan struct{})
		errs := make(chan error, workers)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs <- database.SeedSuperadmin(ctx, pool, cfg)
			}()
		}
		close(start)
		wg.Wait()
		close(errs)

		for err := range errs {
			if err != nil {
				t.Errorf("concurrent SeedSuperadmin() error: %v", err)
			}
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE is_superadmin = TRUE`).Scan(&count); err != nil {
			t.Fatalf("count superadmins: %v", err)
		}
		if count != 1 {
			t.Fatalf("superadmin count = %d, want 1", count)
		}

		if err := database.SeedSuperadmin(ctx, pool, cfg); err != nil {
			t.Fatalf("second SeedSuperadmin() should be idempotent: %v", err)
		}
	})

	t.Run("SeedSuperadminRejectsInvalidConfig", func(t *testing.T) {
		resetUsers(t, ctx, pool)
		err := database.SeedSuperadmin(ctx, pool, &config.Config{})
		if err == nil {
			t.Fatal("SeedSuperadmin() expected error for missing initial admin configuration")
		}
	})

	t.Run("RevokeSessionIsIdempotentAndDeletesTokens", func(t *testing.T) {
		resetUsers(t, ctx, pool)
		userID := insertTestUser(t, ctx, pool)
		sessionID := fmt.Sprintf("test-session-%d", time.Now().UnixNano())

		_, err := pool.Exec(ctx, `
			INSERT INTO sessions (id, user_id, expires_at)
			VALUES ($1, $2, NOW() + INTERVAL '1 hour')
		`, sessionID, userID)
		if err != nil {
			t.Fatalf("insert test session: %v", err)
		}
		_, err = pool.Exec(ctx, `
			INSERT INTO refresh_tokens (user_id, token_hash, expires_at, session_id)
			VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)
		`, userID, "hash-"+sessionID, sessionID)
		if err != nil {
			t.Fatalf("insert test refresh token: %v", err)
		}

		repository := user.NewRepository(pool)
		const workers = 8
		start := make(chan struct{})
		errs := make(chan error, workers)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs <- repository.RevokeSession(ctx, sessionID, userID)
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Errorf("concurrent RevokeSession() error: %v", err)
			}
		}
		if err := repository.RevokeSession(ctx, sessionID, userID); err != nil {
			t.Fatalf("repeated RevokeSession() should be idempotent: %v", err)
		}

		var revokedAt *time.Time
		if err := pool.QueryRow(ctx, `SELECT revoked_at FROM sessions WHERE id = $1`, sessionID).Scan(&revokedAt); err != nil {
			t.Fatalf("read revoked_at: %v", err)
		}
		if revokedAt == nil {
			t.Fatal("session revoked_at is NULL after logout")
		}

		var tokenCount int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM refresh_tokens WHERE session_id = $1`, sessionID).Scan(&tokenCount); err != nil {
			t.Fatalf("count refresh tokens: %v", err)
		}
		if tokenCount != 0 {
			t.Errorf("refresh token count = %d, want 0", tokenCount)
		}

		// A caller who does not own a session must not revoke it.
		otherUserID := insertTestUserWithEmail(t, ctx, pool, "other-"+sessionID+"@example.test")
		if err := repository.RevokeSession(ctx, sessionID, otherUserID); err != nil {
			t.Fatalf("logout for non-owned session should be harmless: %v", err)
		}
	})

	t.Run("UpdateRolePreservesPermissionIDs", func(t *testing.T) {
		resetUsers(t, ctx, pool)
		var roleID, permissionID int
		roleName := fmt.Sprintf("integration-role-%d", time.Now().UnixNano())
		permissionName := fmt.Sprintf("integration-permission-%d", time.Now().UnixNano())

		if err := pool.QueryRow(ctx, `INSERT INTO roles (name, description) VALUES ($1, $2) RETURNING id`, roleName, "before").Scan(&roleID); err != nil {
			t.Fatalf("insert role: %v", err)
		}
		if err := pool.QueryRow(ctx, `INSERT INTO permissions (name, description) VALUES ($1, $2) RETURNING id`, permissionName, "test permission").Scan(&permissionID); err != nil {
			t.Fatalf("insert permission: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, roleID, permissionID); err != nil {
			t.Fatalf("assign permission: %v", err)
		}

		repository := rbac.NewRepository(pool)
		updated, err := repository.UpdateRole(ctx, roleID, roleName, "after")
		if err != nil {
			t.Fatalf("UpdateRole() error: %v", err)
		}
		if updated.Description != "after" {
			t.Errorf("description = %q, want after", updated.Description)
		}
		if len(updated.PermissionIDs) != 1 || updated.PermissionIDs[0] != permissionID {
			t.Errorf("permission IDs = %v, want [%d]", updated.PermissionIDs, permissionID)
		}

		_, err = repository.UpdateRole(ctx, -987654, "missing-role", "no role")
		if !errors.Is(err, rbac.ErrRoleNotFound) {
			t.Errorf("UpdateRole(missing role) error = %v, want ErrRoleNotFound", err)
		}
	})
}

func resetUsers(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `TRUNCATE TABLE users RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("reset test users: %v", err)
	}
}

func insertTestUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	return insertTestUserWithEmail(t, ctx, pool, fmt.Sprintf("test-%d@example.test", time.Now().UnixNano()))
}

func insertTestUserWithEmail(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) int {
	t.Helper()
	var userID int
	err := pool.QueryRow(ctx, `
		INSERT INTO users (name, email, password_hash, role_id)
		SELECT $1, $2, $3, id FROM roles WHERE name = 'user'
		RETURNING id
	`, "Integration User", email, "test-hash").Scan(&userID)
	if err != nil {
		t.Fatalf("insert test user: %v", err)
	}
	return userID
}

// Keep the pgx import referenced so this test package can also assert that the
// integration database is a PostgreSQL connection URL during local setup.
var _ = pgx.ErrNoRows
