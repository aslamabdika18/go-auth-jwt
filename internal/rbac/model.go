package rbac

import "time"

type Role struct {
	ID            int
	Name          string
	Description   string
	IsSuperadmin  bool
	PermissionIDs []int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Permission struct {
	ID          int
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type CreateRoleRequest struct {
	Name        string `json:"name" binding:"required,min=1,max=50"`
	Description string `json:"description" binding:"max=500"`
}

type UpdateRoleRequest struct {
	Name        string `json:"name" binding:"required,min=1,max=50"`
	Description string `json:"description" binding:"max=500"`
}

type CreatePermissionRequest struct {
	Name        string `json:"name" binding:"required,min=1,max=100"`
	Description string `json:"description" binding:"max=500"`
}

type UpdatePermissionRequest struct {
	Name        string `json:"name" binding:"required,min=1,max=100"`
	Description string `json:"description" binding:"max=500"`
}

type UpdateRolePermissionsRequest struct {
	PermissionIDs *[]int `json:"permission_ids" binding:"required"`
}

type UpdateUserRoleRequest struct {
	RoleID int `json:"role_id" binding:"required,gt=0"`
}

type RoleResponse struct {
	ID            int       `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	IsSuperadmin  bool      `json:"is_superadmin"`
	PermissionIDs []int     `json:"permission_ids"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type PermissionResponse struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
