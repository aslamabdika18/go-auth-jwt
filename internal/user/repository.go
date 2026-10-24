package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrEmailAlreadyExists   = errors.New("email already exists")
	ErrUserNotFound         = errors.New("user not found")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrSuperadminProtected  = errors.New("superadmin account is protected")
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

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
			name, email, password_hash, role_id
		)
		SELECT $1, $2, $3, id
		FROM roles
		WHERE name = 'user'
		RETURNING
			id, name, email, password_hash, role_id,
			is_superadmin, created_at, updated_at
	`

	var u User

	err := r.db.QueryRow(
		ctx, query, name, email, passwordHash,
	).Scan(
		&u.ID, &u.Name, &u.Email, &u.PasswordHash,
		&u.RoleID, &u.IsSuperadmin, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrEmailAlreadyExists
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("default user role not found")
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	u.Role = "user"
	return &u, nil
}

func (r *Repository) GetByEmail(
	ctx context.Context,
	email string,
) (*User, error) {
	const query = `
		SELECT
			u.id, u.name, u.email, u.password_hash,
			u.role_id, r.name, u.is_superadmin,
			u.created_at, u.updated_at
		FROM users u
		JOIN roles r ON r.id = u.role_id
		WHERE u.email = $1
	`

	var u User

	err := r.db.QueryRow(ctx, query, email).Scan(
		&u.ID, &u.Name, &u.Email, &u.PasswordHash,
		&u.RoleID, &u.Role, &u.IsSuperadmin,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	return &u, nil
}

func (r *Repository) GetByID(
	ctx context.Context,
	id int,
) (*User, error) {
	const query = `
		SELECT
			u.id, u.name, u.email, u.password_hash,
			u.role_id, r.name, u.is_superadmin,
			u.created_at, u.updated_at
		FROM users u
		JOIN roles r ON r.id = u.role_id
		WHERE u.id = $1
	`

	var u User

	err := r.db.QueryRow(ctx, query, id).Scan(
		&u.ID, &u.Name, &u.Email, &u.PasswordHash,
		&u.RoleID, &u.Role, &u.IsSuperadmin,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}

	return &u, nil
}

func (r *Repository) List(
	ctx context.Context,
	limit int,
	offset int,
) ([]User, int64, error) {
	const countQuery = `SELECT COUNT(*) FROM users`

	var total int64
	if err := r.db.QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	const query = `
		SELECT
			u.id, u.name, u.email, u.role_id, r.name,
			u.is_superadmin, u.created_at, u.updated_at
		FROM users u
		JOIN roles r ON r.id = u.role_id
		ORDER BY u.id
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	users := make([]User, 0)

	for rows.Next() {
		var u User
		if err := rows.Scan(
			&u.ID, &u.Name, &u.Email, &u.RoleID, &u.Role,
			&u.IsSuperadmin, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate users: %w", err)
	}

	return users, total, nil
}

func (r *Repository) Update(
	ctx context.Context,
	id int,
	name string,
	email string,
) (*User, error) {
	const query = `
		UPDATE users
		SET name = $1, email = $2, updated_at = NOW()
		WHERE id = $3 AND is_superadmin = FALSE
		RETURNING id
	`

	var updatedID int
	err := r.db.QueryRow(ctx, query, name, email, id).Scan(&updatedID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, r.classifyProtectedUser(ctx, id)
		}

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrEmailAlreadyExists
		}
		return nil, fmt.Errorf("update user: %w", err)
	}

	u, err := r.GetByID(ctx, updatedID)
	if err != nil {
		return nil, fmt.Errorf("get updated user: %w", err)
	}
	return u, nil
}

func (r *Repository) Delete(ctx context.Context, id int) error {
	const query = `
		DELETE FROM users
		WHERE id = $1 AND is_superadmin = FALSE
	`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if result.RowsAffected() == 0 {
		return r.classifyProtectedUser(ctx, id)
	}
	return nil
}

func (r *Repository) classifyProtectedUser(
	ctx context.Context,
	id int,
) error {
	const query = `SELECT is_superadmin FROM users WHERE id = $1`

	var isSuperadmin bool
	err := r.db.QueryRow(ctx, query, id).Scan(&isSuperadmin)

	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUserNotFound
	}
	if err != nil {
		return fmt.Errorf("check user before mutation: %w", err)
	}
	if isSuperadmin {
		return ErrSuperadminProtected
	}
	return ErrUserNotFound
}

func (r *Repository) CreateRefreshToken(
	ctx context.Context,
	tx pgx.Tx,
	refreshToken RefreshToken,
) error {
	const query = `
		INSERT INTO refresh_tokens (
			user_id, session_id, token_hash, expires_at
		)
		VALUES ($1, $2, $3, $4)
	`

	_, err := tx.Exec(
		ctx, query,
		refreshToken.UserID,
		refreshToken.SessionID,
		refreshToken.TokenHash,
		refreshToken.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

// FindRefreshToken membaca token tanpa menguncinya.
// Transaksi refresh harus mengunci sesi terlebih dahulu.
func (r *Repository) FindRefreshToken(
	ctx context.Context,
	tx pgx.Tx,
	tokenHash string,
) (*RefreshToken, error) {
	const query = `
		SELECT
			id, user_id, session_id, token_hash,
			expires_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1
		  AND expires_at > NOW()
	`

	var token RefreshToken
	err := tx.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.SessionID,
		&token.TokenHash,
		&token.ExpiresAt,
		&token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("find refresh token: %w", err)
	}
	return &token, nil
}

// ConsumeRefreshToken dipanggil setelah sesi dikunci dan divalidasi.
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
			id, user_id, session_id, token_hash,
			expires_at, created_at
	`

	var token RefreshToken
	err := tx.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.SessionID,
		&token.TokenHash,
		&token.ExpiresAt,
		&token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("consume refresh token: %w", err)
	}
	return &token, nil
}

func (r *Repository) DeleteRefreshToken(
	ctx context.Context,
	tokenHash string,
) error {
	const query = `DELETE FROM refresh_tokens WHERE token_hash = $1`

	if _, err := r.db.Exec(ctx, query, tokenHash); err != nil {
		return fmt.Errorf("delete refresh token: %w", err)
	}
	return nil
}

func (r *Repository) CreateSession(
	ctx context.Context,
	tx pgx.Tx,
	sessionID string,
	userID int,
	expiresAt time.Time,
) error {
	if sessionID == "" || userID <= 0 {
		return fmt.Errorf("invalid session data")
	}

	const query = `
		INSERT INTO sessions (id, user_id, expires_at)
		VALUES ($1, $2, $3)
	`

	if _, err := tx.Exec(ctx, query, sessionID, userID, expiresAt); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// LockSession mengambil lock sesi; gunakan sebelum mengubah token sesi.
func (r *Repository) LockSession(
	ctx context.Context,
	tx pgx.Tx,
	sessionID string,
	userID int,
) (bool, error) {
	const query = `
		SELECT (revoked_at IS NULL AND expires_at > NOW())
		FROM sessions
		WHERE id = $1 AND user_id = $2
		FOR UPDATE
	`

	var active bool
	err := tx.QueryRow(ctx, query, sessionID, userID).Scan(&active)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("lock session: %w", err)
	}
	return active, nil
}

func (r *Repository) IsSessionActiveTx(
	ctx context.Context,
	tx pgx.Tx,
	sessionID string,
	userID int,
) (bool, error) {
	return r.LockSession(ctx, tx, sessionID, userID)
}

func (r *Repository) IsSessionActive(
	ctx context.Context,
	sessionID string,
	userID int,
) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM sessions
			WHERE id = $1
			  AND user_id = $2
			  AND revoked_at IS NULL
			  AND expires_at > NOW()
		)
	`

	var active bool
	if err := r.db.QueryRow(ctx, query, sessionID, userID).Scan(&active); err != nil {
		return false, fmt.Errorf("check session status: %w", err)
	}
	return active, nil
}

func (r *Repository) ExtendSession(
	ctx context.Context,
	tx pgx.Tx,
	sessionID string,
	userID int,
	expiresAt time.Time,
) error {
	const query = `
		UPDATE sessions
		SET expires_at = $3
		WHERE id = $1
		  AND user_id = $2
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
	`

	result, err := tx.Exec(ctx, query, sessionID, userID, expiresAt)
	if err != nil {
		return fmt.Errorf("extend session: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrRefreshTokenNotFound
	}
	return nil
}

// RevokeSession mencabut sesi dan semua refresh token miliknya.
// Semua perubahan dilakukan dalam satu transaksi.

// RevokeSession mencabut sesi dan semua refresh token miliknya.
// Semua perubahan dilakukan dalam satu transaksi.
func (r *Repository) RevokeSession(
	ctx context.Context,
	sessionID string,
	userID int,
) error {
	return r.WithTransaction(ctx, func(tx pgx.Tx) error {
		active, err := r.LockSession(ctx, tx, sessionID, userID)
		if err != nil {
			return err
		}

		// Sesi tidak ditemukan atau bukan milik user ini.
		if !active {
			// Tetap bersihkan token untuk sesi yang cocok dengan
			// sessionID dan userID, jika sesi sudah kedaluwarsa
			// atau sebelumnya sudah dicabut.
			const cleanupQuery = `
				DELETE FROM refresh_tokens
				WHERE session_id = $1
				  AND session_id IN (
					SELECT id
					FROM sessions
					WHERE id = $1 AND user_id = $2
				  )
			`
			if _, err := tx.Exec(
				ctx,
				cleanupQuery,
				sessionID,
				userID,
			); err != nil {
				return fmt.Errorf(
					"delete session refresh tokens: %w",
					err,
				)
			}
			return nil
		}

		const revokeQuery = `
			UPDATE sessions
			SET revoked_at = COALESCE(revoked_at, NOW())
			WHERE id = $1 AND user_id = $2
		`
		if _, err := tx.Exec(
			ctx,
			revokeQuery,
			sessionID,
			userID,
		); err != nil {
			return fmt.Errorf("revoke session: %w", err)
		}

		const deleteTokensQuery = `
			DELETE FROM refresh_tokens
			WHERE session_id = $1
		`
		if _, err := tx.Exec(
			ctx,
			deleteTokensQuery,
			sessionID,
		); err != nil {
			return fmt.Errorf(
				"delete session refresh tokens: %w",
				err,
			)
		}

		return nil
	})
}

// Kompatibilitas untuk logout yang masih menggunakan refresh token.
// Jika token sudah tidak ada, fungsi ini idempoten.
func (r *Repository) RevokeSessionByRefreshToken(
	ctx context.Context,
	tokenHash string,
) error {
	return r.WithTransaction(ctx, func(tx pgx.Tx) error {
		token, err := r.FindRefreshToken(ctx, tx, tokenHash)
		if err != nil {
			if errors.Is(err, ErrRefreshTokenNotFound) {
				return nil
			}
			return err
		}

		_, err = r.LockSession(
			ctx, tx, token.SessionID, token.UserID,
		)
		if err != nil {
			return err
		}

		const revokeQuery = `
			UPDATE sessions
			SET revoked_at = COALESCE(revoked_at, NOW())
			WHERE id = $1 AND user_id = $2
		`
		if _, err := tx.Exec(
			ctx, revokeQuery, token.SessionID, token.UserID,
		); err != nil {
			return fmt.Errorf("revoke session: %w", err)
		}

		if _, err := tx.Exec(
			ctx,
			`DELETE FROM refresh_tokens WHERE session_id = $1`,
			token.SessionID,
		); err != nil {
			return fmt.Errorf("delete session refresh tokens: %w", err)
		}
		return nil
	})
}
