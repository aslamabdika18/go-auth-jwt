package user

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/aslamabdika18/go-auth-jwt/internal/auth"
	"github.com/aslamabdika18/go-auth-jwt/internal/middleware"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

const (
	accessTokenCookie  = "access_token"
	refreshTokenCookie = "refresh_token"
)

type Handler struct {
	service      *Service
	jwt          *auth.JWT
	secureCookie bool
}

func NewHandler(
	service *Service,
	jwt *auth.JWT,
	secureCookie bool,
) *Handler {
	return &Handler{
		service:      service,
		jwt:          jwt,
		secureCookie: secureCookie,
	}
}

func (h *Handler) Register(c *gin.Context) {
	var request RegisterRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		h.handleValidationError(c, err)
		return
	}

	response, err := h.service.Register(
		c.Request.Context(),
		request,
	)
	if err != nil {
		if errors.Is(err, ErrEmailAlreadyExists) {
			c.JSON(http.StatusConflict, gin.H{
				"error": "email already exists",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	c.JSON(http.StatusCreated, response)
}

func (h *Handler) Login(c *gin.Context) {
	var request LoginRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		h.handleValidationError(c, err)
		return
	}

	result, err := h.service.Login(
		c.Request.Context(),
		request,
	)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid email or password",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	h.setAccessTokenCookie(c, result.AccessToken)
	h.setRefreshTokenCookie(c, result.RefreshToken)

	c.JSON(http.StatusOK, result.User)
}

func (h *Handler) Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie(refreshTokenCookie)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "refresh token required",
		})
		return
	}

	result, err := h.service.Refresh(
		c.Request.Context(),
		refreshToken,
	)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenNotFound) {
			h.clearAuthCookies(c)

			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired refresh token",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	h.setAccessTokenCookie(c, result.AccessToken)
	h.setRefreshTokenCookie(c, result.RefreshToken)

	c.JSON(http.StatusOK, gin.H{
		"message": "token refreshed successfully",
	})
}

func (h *Handler) Me(c *gin.Context) {
	userID := c.GetInt(middleware.UserIDKey)

	response, err := h.service.Me(
		c.Request.Context(),
		userID,
	)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "user not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *Handler) Logout(c *gin.Context) {
	userID := c.GetInt(middleware.UserIDKey)
	sessionID := c.GetString(middleware.SessionIDKey)

	if userID <= 0 || sessionID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
		})
		return
	}

	if err := h.service.Logout(
		c.Request.Context(),
		sessionID,
		userID,
	); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to logout",
		})
		return
	}

	h.clearAuthCookies(c)

	c.JSON(http.StatusOK, gin.H{
		"message": "logged out successfully",
	})
}

func (h *Handler) ListUsers(c *gin.Context) {
	page, err := queryInt(c, "page", 1)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "page must be a positive integer",
		})
		return
	}

	pageSize, err := queryInt(c, "page_size", 20)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "page_size must be an integer",
		})
		return
	}

	response, err := h.service.ListUsers(
		c.Request.Context(),
		page,
		pageSize,
	)
	if err != nil {
		if errors.Is(err, ErrInvalidPagination) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "page must be at least 1 and page_size must be between 1 and 100",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *Handler) GetUser(c *gin.Context) {
	userID, ok := parseUserID(c)
	if !ok {
		return
	}

	response, err := h.service.GetUser(
		c.Request.Context(),
		userID,
	)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "user not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *Handler) UpdateUser(c *gin.Context) {
	userID, ok := parseUserID(c)
	if !ok {
		return
	}

	var request UpdateUserRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		h.handleValidationError(c, err)
		return
	}

	response, err := h.service.UpdateUser(
		c.Request.Context(),
		userID,
		request,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			c.JSON(http.StatusNotFound, gin.H{
				"error": "user not found",
			})

		case errors.Is(err, ErrEmailAlreadyExists):
			c.JSON(http.StatusConflict, gin.H{
				"error": "email already exists",
			})

		case errors.Is(err, ErrSuperadminProtected):
			c.JSON(http.StatusConflict, gin.H{
				"error": "superadmin account is protected",
			})

		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "internal server error",
			})
		}
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *Handler) DeleteUser(c *gin.Context) {
	userID, ok := parseUserID(c)
	if !ok {
		return
	}

	if err := h.service.DeleteUser(
		c.Request.Context(),
		userID,
	); err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			c.JSON(http.StatusNotFound, gin.H{
				"error": "user not found",
			})

		case errors.Is(err, ErrSuperadminProtected):
			c.JSON(http.StatusConflict, gin.H{
				"error": "superadmin account is protected",
			})

		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "internal server error",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "user deleted successfully",
	})
}

func (h *Handler) setAccessTokenCookie(
	c *gin.Context,
	token string,
) {
	c.SetSameSite(http.SameSiteLaxMode)

	c.SetCookie(
		accessTokenCookie,
		token,
		h.jwt.MaxAge(),
		"/",
		"",
		h.secureCookie,
		true,
	)
}

func (h *Handler) setRefreshTokenCookie(
	c *gin.Context,
	token string,
) {
	c.SetSameSite(http.SameSiteLaxMode)

	c.SetCookie(
		refreshTokenCookie,
		token,
		int(h.service.refreshTokenTTL.Seconds()),
		"/api/v1/auth",
		"",
		h.secureCookie,
		true,
	)
}

func (h *Handler) clearAuthCookies(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)

	c.SetCookie(
		accessTokenCookie,
		"",
		-1,
		"/",
		"",
		h.secureCookie,
		true,
	)

	c.SetCookie(
		refreshTokenCookie,
		"",
		-1,
		"/api/v1/auth",
		"",
		h.secureCookie,
		true,
	)
}

func (h *Handler) handleValidationError(
	c *gin.Context,
	err error,
) {
	var validationErrors validator.ValidationErrors

	if errors.As(err, &validationErrors) {
		fields := make(map[string]string)

		for _, fieldError := range validationErrors {
			switch fieldError.Field() {
			case "Name":
				fields["name"] = validationMessage(fieldError)

			case "Email":
				fields["email"] = validationMessage(fieldError)

			case "Password":
				fields["password"] = validationMessage(fieldError)
			}
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"error":  "validation failed",
			"fields": fields,
		})
		return
	}

	c.JSON(http.StatusBadRequest, gin.H{
		"error": "invalid request body",
	})
}

func validationMessage(
	fieldError validator.FieldError,
) string {
	switch fieldError.Tag() {
	case "required":
		return "this field is required"

	case "min":
		return "must be at least " +
			fieldError.Param() +
			" characters"

	case "max":
		return "must not exceed " +
			fieldError.Param() +
			" characters"

	case "email":
		return "must be a valid email address"

	default:
		return "invalid value"
	}
}

func parseUserID(c *gin.Context) (int, bool) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil || userID < 1 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid user id",
		})
		return 0, false
	}

	return userID, true
}

func queryInt(
	c *gin.Context,
	key string,
	defaultValue int,
) (int, error) {
	value := c.Query(key)
	if value == "" {
		return defaultValue, nil
	}

	return strconv.Atoi(value)
}
