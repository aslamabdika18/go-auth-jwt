package user

import (
	"errors"
	"net/http"

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

	h.setAccessTokenCookie(
		c,
		result.AccessToken,
	)

	h.setRefreshTokenCookie(
		c,
		result.RefreshToken,
	)

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

	h.setAccessTokenCookie(
		c,
		result.AccessToken,
	)

	h.setRefreshTokenCookie(
		c,
		result.RefreshToken,
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "token refreshed successfully",
	})
}

func (h *Handler) Me(c *gin.Context) {
	userID := c.GetInt(
		middleware.UserIDKey,
	)

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
	refreshToken, _ := c.Cookie(
		refreshTokenCookie,
	)

	if err := h.service.Logout(
		c.Request.Context(),
		refreshToken,
	); err != nil {
		h.clearAuthCookies(c)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	h.clearAuthCookies(c)

	c.JSON(http.StatusOK, gin.H{
		"message": "logged out successfully",
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

func (h *Handler) clearAuthCookies(
	c *gin.Context,
) {
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
				fields["name"] = validationMessage(
					fieldError,
				)

			case "Email":
				fields["email"] = validationMessage(
					fieldError,
				)

			case "Password":
				fields["password"] = validationMessage(
					fieldError,
				)
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
