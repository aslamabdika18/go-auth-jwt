package rbac

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

var (
	ErrInvalidRoleName       = errors.New("invalid role name")
	ErrInvalidPermissionName = errors.New("invalid permission name")
	ErrInvalidDescription    = errors.New("invalid description")
	ErrSystemRole            = errors.New("system role is protected")
	ErrInvalidPermissionID   = errors.New("permission id must be greater than 0")
)

var (
	roleNamePattern = regexp.MustCompile(
		`^[a-z0-9][a-z0-9_-]{0,49}$`,
	)

	permissionNamePattern = regexp.MustCompile(
		`^[a-z0-9_]+(\.[a-z0-9_]+)+$`,
	)
)

type Service struct {
	repository *Repository
}

func NewService(
	repository *Repository,
) *Service {
	return &Service{
		repository: repository,
	}
}

func (s *Service) ListRoles(
	ctx context.Context,
) ([]Role, error) {
	return s.repository.ListRoles(ctx)
}

func (s *Service) GetRole(
	ctx context.Context,
	id int,
) (*Role, error) {
	if id <= 0 {
		return nil, ErrRoleNotFound
	}

	return s.repository.GetRoleByID(ctx, id)
}

func (s *Service) CreateRole(
	ctx context.Context,
	name string,
	description string,
) (*Role, error) {
	name = normalize(name)
	description = normalizeDescription(description)

	if err := validateRoleName(name); err != nil {
		return nil, err
	}

	if err := validateDescription(description); err != nil {
		return nil, err
	}

	if isSystemRole(name) {
		return nil, ErrSystemRole
	}

	return s.repository.CreateRole(
		ctx,
		name,
		description,
	)
}

func (s *Service) UpdateRole(
	ctx context.Context,
	id int,
	name string,
	description string,
) (*Role, error) {
	name = normalize(name)
	description = normalizeDescription(description)

	if err := validateRoleName(name); err != nil {
		return nil, err
	}

	if err := validateDescription(description); err != nil {
		return nil, err
	}

	currentRole, err := s.repository.GetRoleByID(
		ctx,
		id,
	)
	if err != nil {
		return nil, err
	}

	if isSystemRole(currentRole.Name) {
		return nil, ErrSystemRole
	}

	if isSystemRole(name) {
		return nil, ErrSystemRole
	}

	return s.repository.UpdateRole(
		ctx,
		id,
		name,
		description,
	)
}

func (s *Service) DeleteRole(
	ctx context.Context,
	id int,
) error {
	role, err := s.repository.GetRoleByID(
		ctx,
		id,
	)
	if err != nil {
		return err
	}

	if isSystemRole(role.Name) {
		return ErrSystemRole
	}

	return s.repository.DeleteRole(
		ctx,
		id,
	)
}

func (s *Service) ListPermissions(
	ctx context.Context,
) ([]Permission, error) {
	return s.repository.ListPermissions(ctx)
}

func (s *Service) GetPermission(
	ctx context.Context,
	id int,
) (*Permission, error) {
	if id <= 0 {
		return nil, ErrPermissionNotFound
	}

	return s.repository.GetPermissionByID(
		ctx,
		id,
	)
}

func (s *Service) CreatePermission(
	ctx context.Context,
	name string,
	description string,
) (*Permission, error) {
	name = normalize(name)
	description = normalizeDescription(description)

	if err := validatePermissionName(name); err != nil {
		return nil, err
	}

	if err := validateDescription(description); err != nil {
		return nil, err
	}

	return s.repository.CreatePermission(
		ctx,
		name,
		description,
	)
}

func (s *Service) UpdatePermission(
	ctx context.Context,
	id int,
	name string,
	description string,
) (*Permission, error) {
	name = normalize(name)
	description = normalizeDescription(description)

	if err := validatePermissionName(name); err != nil {
		return nil, err
	}

	if err := validateDescription(description); err != nil {
		return nil, err
	}

	return s.repository.UpdatePermission(
		ctx,
		id,
		name,
		description,
	)
}

func (s *Service) DeletePermission(
	ctx context.Context,
	id int,
) error {
	return s.repository.DeletePermission(
		ctx,
		id,
	)
}

func (s *Service) SetRolePermissions(
	ctx context.Context,
	roleID int,
	permissionIDs []int,
) error {
	if roleID <= 0 {
		return ErrRoleNotFound
	}

	uniqueIDs := make([]int, 0, len(permissionIDs))
	seen := make(map[int]struct{})

	for _, permissionID := range permissionIDs {
		if permissionID <= 0 {
			return ErrInvalidPermissionID
		}

		if _, exists := seen[permissionID]; exists {
			continue
		}

		seen[permissionID] = struct{}{}
		uniqueIDs = append(
			uniqueIDs,
			permissionID,
		)
	}

	return s.repository.SetRolePermissions(
		ctx,
		roleID,
		uniqueIDs,
	)
}

func (s *Service) SetUserRole(
	ctx context.Context,
	userID int,
	roleID int,
) error {
	if userID <= 0 {
		return errors.New("invalid user id")
	}

	if roleID <= 0 {
		return ErrRoleNotFound
	}

	return s.repository.SetUserRole(
		ctx,
		userID,
		roleID,
	)
}

func (s *Service) IsSuperadmin(
	ctx context.Context,
	userID int,
) (bool, error) {
	return s.repository.IsSuperadmin(
		ctx,
		userID,
	)
}

func (s *Service) HasPermission(
	ctx context.Context,
	userID int,
	permission string,
) (bool, error) {
	permission = normalize(permission)

	if permission == "" {
		return false, nil
	}

	return s.repository.HasPermission(
		ctx,
		userID,
		permission,
	)
}

func normalize(value string) string {
	return strings.ToLower(
		strings.TrimSpace(value),
	)
}

func normalizeDescription(value string) string {
	return strings.TrimSpace(value)
}

func validateRoleName(name string) error {
	if !roleNamePattern.MatchString(name) {
		return ErrInvalidRoleName
	}

	return nil
}

func validatePermissionName(name string) error {
	if !permissionNamePattern.MatchString(name) {
		return ErrInvalidPermissionName
	}

	if len(name) > 100 {
		return ErrInvalidPermissionName
	}

	return nil
}

func validateDescription(description string) error {
	if len(description) > 500 {
		return ErrInvalidDescription
	}

	return nil
}

func isSystemRole(name string) bool {
	return name == "user" ||
		name == "superadmin"
}
