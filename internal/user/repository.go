package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrEmailAlreadyExists   = errors.New("email already exists")
	ErrUserNotFound         = errors.New("user not found")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		db: db,
	}
}

// WithTransaction executes a function inside a database transaction.
//
// If fn returns an error, the transaction is rolled back.
// If fn succeeds, the transaction is committed.
func (r *Repository) WithTransaction(
	ctx context.Context,
	fn func(tx pgx.Tx) error,
) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func (r *Repository) Create(
	ctx context.Context,
	name string,
	email string,
	passwordHash string,
) (*User, error) {
	const query = `
		INSERT INTO users (
			name,
			email,
			password_hash
		)
		VALUES ($1, $2, $3)
		RETURNING
			id,
			name,
			email,
			password_hash,
			created_at,
			updated_at
	`

	var user User

	err := r.db.QueryRow(
		ctx,
		query,
		name,
		email,
		passwordHash,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError

		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrEmailAlreadyExists
		}

		return nil, fmt.Errorf("create user: %w", err)
	}

	return &user, nil
}

func (r *Repository) GetByEmail(
	ctx context.Context,
	email string,
) (*User, error) {
	const query = `
		SELECT
			id,
			name,
			email,
			password_hash,
			created_at,
			updated_at
		FROM users
		WHERE email = $1
	`

	var user User

	err := r.db.QueryRow(
		ctx,
		query,
		email,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}

		return nil, fmt.Errorf("get user by email: %w", err)
	}

	return &user, nil
}

func (r *Repository) GetByID(
	ctx context.Context,
	id int,
) (*User, error) {
	const query = `
		SELECT
			id,
			name,
			email,
			password_hash,
			created_at,
			updated_at
		FROM users
		WHERE id = $1
	`

	var user User

	err := r.db.QueryRow(
		ctx,
		query,
		id,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}

		return nil, fmt.Errorf("get user by id: %w", err)
	}

	return &user, nil
}

// CreateRefreshToken stores the refresh-token hash.
//
// The raw refresh token must never be stored in the database.
func (r *Repository) CreateRefreshToken(
	ctx context.Context,
	tx pgx.Tx,
	refreshToken RefreshToken,
) error {
	const query = `
		INSERT INTO refresh_tokens (
			user_id,
			token_hash,
			expires_at
		)
		VALUES ($1, $2, $3)
	`

	_, err := tx.Exec(
		ctx,
		query,
		refreshToken.UserID,
		refreshToken.TokenHash,
		refreshToken.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}

	return nil
}

// ConsumeRefreshToken atomically consumes a valid refresh token.
//
// The token is deleted and returned in one SQL statement.
// Therefore, the same refresh token cannot be consumed successfully
// by two concurrent requests.
func (r *Repository) ConsumeRefreshToken(
	ctx context.Context,
	tx pgx.Tx,
	tokenHash string,
) (*RefreshToken, error) {
	const query = `
		DELETE FROM refresh_tokens
		WHERE token_hash = $1
		  AND expires_at > NOW()
		RETURNING
			id,
			user_id,
			token_hash,
			expires_at,
			created_at
	`

	var refreshToken RefreshToken

	err := tx.QueryRow(
		ctx,
		query,
		tokenHash,
	).Scan(
		&refreshToken.ID,
		&refreshToken.UserID,
		&refreshToken.TokenHash,
		&refreshToken.ExpiresAt,
		&refreshToken.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshTokenNotFound
		}

		return nil, fmt.Errorf("consume refresh token: %w", err)
	}

	return &refreshToken, nil
}

// DeleteRefreshToken removes a refresh token.
//
// This is used during logout.
func (r *Repository) DeleteRefreshToken(
	ctx context.Context,
	tokenHash string,
) error {
	const query = `
		DELETE FROM refresh_tokens
		WHERE token_hash = $1
	`

	_, err := r.db.Exec(
		ctx,
		query,
		tokenHash,
	)
	if err != nil {
		return fmt.Errorf("delete refresh token: %w", err)
	}

	return nil
}
