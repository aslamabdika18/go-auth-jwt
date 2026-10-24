package database

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aslamabdika18/go-auth-jwt/internal/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func SeedSuperadmin(
	ctx context.Context,
	db *pgxpool.Pool,
	cfg *config.Config,
) error {
	const checkSuperadminQuery = `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE is_superadmin = TRUE
		)
	`

	var superadminExists bool

	if err := db.QueryRow(
		ctx,
		checkSuperadminQuery,
	).Scan(&superadminExists); err != nil {
		return fmt.Errorf("check existing superadmin: %w", err)
	}

	// Jika superadmin sudah tersedia, bootstrap tidak diperlukan.
	if superadminExists {
		return nil
	}

	name := strings.TrimSpace(cfg.InitialAdminName)
	email := strings.ToLower(
		strings.TrimSpace(cfg.InitialAdminEmail),
	)
	password := cfg.InitialAdminPassword

	// Ketiga konfigurasi harus kosong bersama-sama
	// atau diisi bersama-sama.
	if name == "" && email == "" && password == "" {
		return errors.New(
			"initial superadmin is required but not configured",
		)
	}

	if name == "" || email == "" || password == "" {
		return errors.New(
			"initial admin name, email, and password must all be set",
		)
	}

	if len(name) < 3 || len(name) > 100 {
		return errors.New(
			"initial admin name must be between 3 and 100 bytes",
		)
	}

	if len(password) < 12 || len(password) > 72 {
		return errors.New(
			"initial admin password must be between 12 and 72 bytes",
		)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return fmt.Errorf("hash initial admin password: %w", err)
	}

	const insertQuery = `
		INSERT INTO users (
			name,
			email,
			password_hash,
			role_id,
			is_superadmin
		)
		SELECT
			$1,
			$2,
			$3,
			r.id,
			TRUE
		FROM roles r
		WHERE r.name = 'superadmin'
		  AND r.is_superadmin = TRUE
		ON CONFLICT DO NOTHING
		RETURNING id
	`

	var userID int

	err = db.QueryRow(
		ctx,
		insertQuery,
		name,
		email,
		string(hashedPassword),
	).Scan(&userID)

	if err == nil {
		return nil
	}

	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("create initial superadmin: %w", err)
	}

	// INSERT tidak menghasilkan baris. Periksa apakah instance
	// lain sudah berhasil membuat superadmin.
	if err := db.QueryRow(
		ctx,
		checkSuperadminQuery,
	).Scan(&superadminExists); err != nil {
		return fmt.Errorf(
			"verify superadmin after insert conflict: %w",
			err,
		)
	}

	if superadminExists {
		return nil
	}

	// Tidak ada superadmin: kemungkinan email bentrok,
	// role superadmin tidak tersedia, atau konflik lain.
	const checkEmailQuery = `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE email = $1
		)
	`

	var emailExists bool

	if err := db.QueryRow(
		ctx,
		checkEmailQuery,
		email,
	).Scan(&emailExists); err != nil {
		return fmt.Errorf("check initial admin email: %w", err)
	}

	if emailExists {
		return errors.New(
			"initial admin email already belongs to another user",
		)
	}

	const checkRoleQuery = `
		SELECT EXISTS (
			SELECT 1
			FROM roles
			WHERE name = 'superadmin'
			  AND is_superadmin = TRUE
		)
	`

	var roleExists bool

	if err := db.QueryRow(
		ctx,
		checkRoleQuery,
	).Scan(&roleExists); err != nil {
		return fmt.Errorf("check superadmin role: %w", err)
	}

	if !roleExists {
		return errors.New("superadmin role not found")
	}

	return errors.New(
		"could not create initial superadmin due to a database conflict",
	)
}
