package rbac

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(
	service *Service,
) *Handler {
	return &Handler{
		service: service,
	}
}

func (h *Handler) ListRoles(c *gin.Context) {
	roles, err := h.service.ListRoles(
		c.Request.Context(),
	)
	if err != nil {
		handleError(c, err)
		return
	}

	response := make(
		[]RoleResponse,
		0,
		len(roles),
	)

	for i := range roles {
		response = append(
			response,
			toRoleResponse(&roles[i]),
		)
	}

	c.JSON(http.StatusOK, response)
}

func (h *Handler) GetRole(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}

	role, err := h.service.GetRole(
		c.Request.Context(),
		id,
	)
	if err != nil {
		handleError(c, err)
		return
	}

	c.JSON(
		http.StatusOK,
		toRoleResponse(role),
	)
}

func (h *Handler) CreateRole(c *gin.Context) {
	var request CreateRoleRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	role, err := h.service.CreateRole(
		c.Request.Context(),
		request.Name,
		request.Description,
	)
	if err != nil {
		handleError(c, err)
		return
	}

	c.JSON(
		http.StatusCreated,
		toRoleResponse(role),
	)
}

func (h *Handler) UpdateRole(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}

	var request UpdateRoleRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	role, err := h.service.UpdateRole(
		c.Request.Context(),
		id,
		request.Name,
		request.Description,
	)
	if err != nil {
		handleError(c, err)
		return
	}

	c.JSON(
		http.StatusOK,
		toRoleResponse(role),
	)
}

func (h *Handler) DeleteRole(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}

	if err := h.service.DeleteRole(
		c.Request.Context(),
		id,
	); err != nil {
		handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "role deleted",
	})
}

func (h *Handler) UpdateRolePermissions(
	c *gin.Context,
) {
	id, ok := parseID(c)
	if !ok {
		return
	}

	var request UpdateRolePermissionsRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "permission_ids is required",
		})
		return
	}

	if err := h.service.SetRolePermissions(
		c.Request.Context(),
		id,
		*request.PermissionIDs,
	); err != nil {
		handleError(c, err)
		return
	}

	role, err := h.service.GetRole(
		c.Request.Context(),
		id,
	)
	if err != nil {
		handleError(c, err)
		return
	}

	c.JSON(
		http.StatusOK,
		toRoleResponse(role),
	)
}

func (h *Handler) ListPermissions(c *gin.Context) {
	permissions, err := h.service.ListPermissions(
		c.Request.Context(),
	)
	if err != nil {
		handleError(c, err)
		return
	}

	response := make(
		[]PermissionResponse,
		0,
		len(permissions),
	)

	for i := range permissions {
		response = append(
			response,
			toPermissionResponse(&permissions[i]),
		)
	}

	c.JSON(http.StatusOK, response)
}

func (h *Handler) GetPermission(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}

	permission, err := h.service.GetPermission(
		c.Request.Context(),
		id,
	)
	if err != nil {
		handleError(c, err)
		return
	}

	c.JSON(
		http.StatusOK,
		toPermissionResponse(permission),
	)
}

func (h *Handler) CreatePermission(c *gin.Context) {
	var request CreatePermissionRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	permission, err := h.service.CreatePermission(
		c.Request.Context(),
		request.Name,
		request.Description,
	)
	if err != nil {
		handleError(c, err)
		return
	}

	c.JSON(
		http.StatusCreated,
		toPermissionResponse(permission),
	)
}

func (h *Handler) UpdatePermission(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}

	var request UpdatePermissionRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	permission, err := h.service.UpdatePermission(
		c.Request.Context(),
		id,
		request.Name,
		request.Description,
	)
	if err != nil {
		handleError(c, err)
		return
	}

	c.JSON(
		http.StatusOK,
		toPermissionResponse(permission),
	)
}

func (h *Handler) DeletePermission(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}

	if err := h.service.DeletePermission(
		c.Request.Context(),
		id,
	); err != nil {
		handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "permission deleted",
	})
}

func (h *Handler) UpdateUserRole(c *gin.Context) {
	userID, ok := parseID(c)
	if !ok {
		return
	}

	var request UpdateUserRoleRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	if err := h.service.SetUserRole(
		c.Request.Context(),
		userID,
		request.RoleID,
	); err != nil {
		handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "user role updated",
	})
}

func parseID(c *gin.Context) (int, bool) {
	id, err := strconv.Atoi(
		c.Param("id"),
	)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid id",
		})
		return 0, false
	}

	return id, true
}

func handleError(
	c *gin.Context,
	err error,
) {
	switch {
	case errors.Is(err, ErrRoleNotFound),
		errors.Is(err, ErrPermissionNotFound),
		errors.Is(err, ErrUserNotFound):

		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})

	case errors.Is(err, ErrRoleNameAlreadyExists),
		errors.Is(err, ErrPermissionNameExists),
		errors.Is(err, ErrRoleInUse),
		errors.Is(err, ErrPermissionInUse),
		errors.Is(err, ErrSystemRole),
		errors.Is(err, ErrSuperadminProtected),
		errors.Is(err, ErrSuperadminRoleProtected):

		c.JSON(http.StatusConflict, gin.H{
			"error": err.Error(),
		})

	case errors.Is(err, ErrInvalidRoleName),
		errors.Is(err, ErrInvalidPermissionName),
		errors.Is(err, ErrInvalidDescription),
		errors.Is(err, ErrInvalidPermissionID):

		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})

	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
	}
}

func toRoleResponse(role *Role) RoleResponse {
	permissionIDs := role.PermissionIDs

	if permissionIDs == nil {
		permissionIDs = []int{}
	}

	return RoleResponse{
		ID:            role.ID,
		Name:          role.Name,
		Description:   role.Description,
		IsSuperadmin:  role.IsSuperadmin,
		PermissionIDs: permissionIDs,
		CreatedAt:     role.CreatedAt,
		UpdatedAt:     role.UpdatedAt,
	}
}

func toPermissionResponse(
	permission *Permission,
) PermissionResponse {
	return PermissionResponse{
		ID:          permission.ID,
		Name:        permission.Name,
		Description: permission.Description,
		CreatedAt:   permission.CreatedAt,
		UpdatedAt:   permission.UpdatedAt,
	}
}
