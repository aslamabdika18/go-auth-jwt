package rbac

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrRoleNotFound            = errors.New("role not found")
	ErrPermissionNotFound      = errors.New("permission not found")
	ErrUserNotFound            = errors.New("user not found")
	ErrRoleNameAlreadyExists   = errors.New("role name already exists")
	ErrPermissionNameExists    = errors.New("permission name already exists")
	ErrRoleInUse               = errors.New("role is still assigned to users")
	ErrPermissionInUse         = errors.New("permission is still assigned to roles")
	ErrSuperadminProtected     = errors.New("superadmin is protected")
	ErrSuperadminRoleProtected = errors.New("superadmin role cannot be assigned")
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{
		db: db,
	}
}

func (r *Repository) ListRoles(
	ctx context.Context,
) ([]Role, error) {
	const query = `
		SELECT
			r.id,
			r.name,
			r.description,
			r.is_superadmin,
			COALESCE(
				array_agg(rp.permission_id ORDER BY rp.permission_id)
				FILTER (WHERE rp.permission_id IS NOT NULL),
				ARRAY[]::INTEGER[]
			) AS permission_ids,
			r.created_at,
			r.updated_at
		FROM roles r
		LEFT JOIN role_permissions rp
			ON rp.role_id = r.id
		GROUP BY
			r.id,
			r.name,
			r.description,
			r.is_superadmin,
			r.created_at,
			r.updated_at
		ORDER BY r.id
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()

	roles := make([]Role, 0)

	for rows.Next() {
		var role Role
		var permissionIDs []int32

		if err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&role.IsSuperadmin,
			&permissionIDs,
			&role.CreatedAt,
			&role.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}

		role.PermissionIDs = int32ToInt(permissionIDs)

		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate roles: %w", err)
	}

	return roles, nil
}

func (r *Repository) GetRoleByID(
	ctx context.Context,
	id int,
) (*Role, error) {
	const query = `
		SELECT
			r.id,
			r.name,
			r.description,
			r.is_superadmin,
			COALESCE(
				array_agg(rp.permission_id ORDER BY rp.permission_id)
				FILTER (WHERE rp.permission_id IS NOT NULL),
				ARRAY[]::INTEGER[]
			) AS permission_ids,
			r.created_at,
			r.updated_at
		FROM roles r
		LEFT JOIN role_permissions rp
			ON rp.role_id = r.id
		WHERE r.id = $1
		GROUP BY
			r.id,
			r.name,
			r.description,
			r.is_superadmin,
			r.created_at,
			r.updated_at
	`

	var role Role
	var permissionIDs []int32

	err := r.db.QueryRow(
		ctx,
		query,
		id,
	).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.IsSuperadmin,
		&permissionIDs,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRoleNotFound
		}

		return nil, fmt.Errorf("get role: %w", err)
	}

	role.PermissionIDs = int32ToInt(permissionIDs)

	return &role, nil
}

func (r *Repository) CreateRole(
	ctx context.Context,
	name string,
	description string,
) (*Role, error) {
	const query = `
		INSERT INTO roles (
			name,
			description
		)
		VALUES ($1, $2)
		RETURNING
			id,
			name,
			description,
			is_superadmin,
			created_at,
			updated_at
	`

	var role Role

	err := r.db.QueryRow(
		ctx,
		query,
		name,
		description,
	).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.IsSuperadmin,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err != nil {
		var pgErr *pgconn.PgError

		if errors.As(err, &pgErr) &&
			pgErr.Code == "23505" {
			return nil, ErrRoleNameAlreadyExists
		}

		return nil, fmt.Errorf("create role: %w", err)
	}

	role.PermissionIDs = []int{}

	return &role, nil
}

func (r *Repository) UpdateRole(
	ctx context.Context,
	id int,
	name string,
	description string,
) (*Role, error) {
	const query = `
		UPDATE roles
		SET
			name = $1,
			description = $2,
			updated_at = NOW()
		WHERE id = $3
		RETURNING id
	`

	var updatedID int

	err := r.db.QueryRow(
		ctx,
		query,
		name,
		description,
		id,
	).Scan(&updatedID)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRoleNotFound
		}

		var pgErr *pgconn.PgError

		if errors.As(err, &pgErr) &&
			pgErr.Code == "23505" {
			return nil, ErrRoleNameAlreadyExists
		}

		return nil, fmt.Errorf("update role: %w", err)
	}

	updatedRole, err := r.GetRoleByID(
		ctx,
		updatedID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"get updated role: %w",
			err,
		)
	}

	return updatedRole, nil
}

func (r *Repository) DeleteRole(
	ctx context.Context,
	id int,
) error {
	const query = `
		DELETE FROM roles
		WHERE id = $1
	`

	result, err := r.db.Exec(
		ctx,
		query,
		id,
	)
	if err != nil {
		var pgErr *pgconn.PgError

		if errors.As(err, &pgErr) &&
			pgErr.Code == "23503" &&
			pgErr.ConstraintName == "fk_users_role" {
			return ErrRoleInUse
		}

		return fmt.Errorf("delete role: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrRoleNotFound
	}

	return nil
}

func (r *Repository) ListPermissions(
	ctx context.Context,
) ([]Permission, error) {
	const query = `
		SELECT
			id,
			name,
			description,
			created_at,
			updated_at
		FROM permissions
		ORDER BY id
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	defer rows.Close()

	permissions := make([]Permission, 0)

	for rows.Next() {
		var permission Permission

		if err := rows.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf(
				"scan permission: %w",
				err,
			)
		}

		permissions = append(
			permissions,
			permission,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate permissions: %w",
			err,
		)
	}

	return permissions, nil
}

func (r *Repository) GetPermissionByID(
	ctx context.Context,
	id int,
) (*Permission, error) {
	const query = `
		SELECT
			id,
			name,
			description,
			created_at,
			updated_at
		FROM permissions
		WHERE id = $1
	`

	var permission Permission

	err := r.db.QueryRow(
		ctx,
		query,
		id,
	).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPermissionNotFound
		}

		return nil, fmt.Errorf(
			"get permission: %w",
			err,
		)
	}

	return &permission, nil
}

func (r *Repository) CreatePermission(
	ctx context.Context,
	name string,
	description string,
) (*Permission, error) {
	const query = `
		INSERT INTO permissions (
			name,
			description
		)
		VALUES ($1, $2)
		RETURNING
			id,
			name,
			description,
			created_at,
			updated_at
	`

	var permission Permission

	err := r.db.QueryRow(
		ctx,
		query,
		name,
		description,
	).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)

	if err != nil {
		var pgErr *pgconn.PgError

		if errors.As(err, &pgErr) &&
			pgErr.Code == "23505" {
			return nil, ErrPermissionNameExists
		}

		return nil, fmt.Errorf(
			"create permission: %w",
			err,
		)
	}

	return &permission, nil
}

func (r *Repository) UpdatePermission(
	ctx context.Context,
	id int,
	name string,
	description string,
) (*Permission, error) {
	const query = `
		UPDATE permissions
		SET
			name = $1,
			description = $2,
			updated_at = NOW()
		WHERE id = $3
		RETURNING
			id,
			name,
			description,
			created_at,
			updated_at
	`

	var permission Permission

	err := r.db.QueryRow(
		ctx,
		query,
		name,
		description,
		id,
	).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPermissionNotFound
		}

		var pgErr *pgconn.PgError

		if errors.As(err, &pgErr) &&
			pgErr.Code == "23505" {
			return nil, ErrPermissionNameExists
		}

		return nil, fmt.Errorf(
			"update permission: %w",
			err,
		)
	}

	return &permission, nil
}

func (r *Repository) DeletePermission(
	ctx context.Context,
	id int,
) error {
	const query = `
		DELETE FROM permissions
		WHERE id = $1
	`

	result, err := r.db.Exec(
		ctx,
		query,
		id,
	)
	if err != nil {
		var pgErr *pgconn.PgError

		if errors.As(err, &pgErr) &&
			pgErr.Code == "23503" &&
			pgErr.ConstraintName ==
				"fk_role_permissions_permission" {
			return ErrPermissionInUse
		}

		return fmt.Errorf(
			"delete permission: %w",
			err,
		)
	}

	if result.RowsAffected() == 0 {
		return ErrPermissionNotFound
	}

	return nil
}

func (r *Repository) SetRolePermissions(
	ctx context.Context,
	roleID int,
	permissionIDs []int,
) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"begin role permissions transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const lockRoleQuery = `
		SELECT id
		FROM roles
		WHERE id = $1
		FOR UPDATE
	`

	var lockedRoleID int

	err = tx.QueryRow(
		ctx,
		lockRoleQuery,
		roleID,
	).Scan(&lockedRoleID)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRoleNotFound
		}

		return fmt.Errorf(
			"lock role: %w",
			err,
		)
	}

	const deleteQuery = `
		DELETE FROM role_permissions
		WHERE role_id = $1
	`

	if _, err := tx.Exec(
		ctx,
		deleteQuery,
		roleID,
	); err != nil {
		return fmt.Errorf(
			"clear role permissions: %w",
			err,
		)
	}

	const insertQuery = `
		INSERT INTO role_permissions (
			role_id,
			permission_id
		)
		VALUES ($1, $2)
	`

	for _, permissionID := range permissionIDs {
		if _, err := tx.Exec(
			ctx,
			insertQuery,
			roleID,
			permissionID,
		); err != nil {
			var pgErr *pgconn.PgError

			if errors.As(err, &pgErr) &&
				pgErr.Code == "23503" &&
				pgErr.ConstraintName ==
					"fk_role_permissions_permission" {
				return ErrPermissionNotFound
			}

			return fmt.Errorf(
				"assign permission: %w",
				err,
			)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit role permissions transaction: %w",
			err,
		)
	}

	return nil
}

func (r *Repository) SetUserRole(
	ctx context.Context,
	userID int,
	roleID int,
) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf(
			"begin user role transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const userQuery = `
		SELECT is_superadmin
		FROM users
		WHERE id = $1
		FOR UPDATE
	`

	var isSuperadmin bool

	err = tx.QueryRow(
		ctx,
		userQuery,
		userID,
	).Scan(&isSuperadmin)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}

		return fmt.Errorf(
			"get user for role update: %w",
			err,
		)
	}

	if isSuperadmin {
		return ErrSuperadminProtected
	}

	const roleQuery = `
		SELECT is_superadmin
		FROM roles
		WHERE id = $1
	`

	var isSuperadminRole bool

	err = tx.QueryRow(
		ctx,
		roleQuery,
		roleID,
	).Scan(&isSuperadminRole)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRoleNotFound
		}

		return fmt.Errorf(
			"get target role: %w",
			err,
		)
	}

	if isSuperadminRole {
		return ErrSuperadminRoleProtected
	}

	const updateQuery = `
		UPDATE users
		SET
			role_id = $1,
			updated_at = NOW()
		WHERE id = $2
	`

	if _, err := tx.Exec(
		ctx,
		updateQuery,
		roleID,
		userID,
	); err != nil {
		return fmt.Errorf(
			"update user role: %w",
			err,
		)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit user role transaction: %w",
			err,
		)
	}

	return nil
}

func (r *Repository) IsSuperadmin(
	ctx context.Context,
	userID int,
) (bool, error) {
	const query = `
		SELECT is_superadmin
		FROM users
		WHERE id = $1
	`

	var isSuperadmin bool

	err := r.db.QueryRow(
		ctx,
		query,
		userID,
	).Scan(&isSuperadmin)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrUserNotFound
		}

		return false, fmt.Errorf(
			"check superadmin: %w",
			err,
		)
	}

	return isSuperadmin, nil
}

func (r *Repository) HasPermission(
	ctx context.Context,
	userID int,
	permissionName string,
) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM users u
			LEFT JOIN roles r
				ON r.id = u.role_id
			LEFT JOIN role_permissions rp
				ON rp.role_id = r.id
			LEFT JOIN permissions p
				ON p.id = rp.permission_id
			WHERE u.id = $1
			  AND (
					u.is_superadmin = TRUE
					OR p.name = $2
			  )
		)
	`

	var allowed bool

	if err := r.db.QueryRow(
		ctx,
		query,
		userID,
		permissionName,
	).Scan(&allowed); err != nil {
		return false, fmt.Errorf(
			"check permission: %w",
			err,
		)
	}

	return allowed, nil
}

func int32ToInt(values []int32) []int {
	result := make([]int, len(values))

	for i, value := range values {
		result[i] = int(value)
	}

	return result
}
