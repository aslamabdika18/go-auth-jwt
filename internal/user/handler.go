package user

import (
	"errors"
	"net/http"

	"github.com/aslamabdika18/go-auth-jwt/internal/auth"
	"github.com/aslamabdika18/go-auth-jwt/internal/middleware"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
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

	response, err := h.service.Login(
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

	c.SetSameSite(http.SameSiteLaxMode)

	c.SetCookie(
		"access_token",
		response.AccessToken,
		h.jwt.MaxAge(),
		"/",
		"",
		h.secureCookie,
		true,
	)

	c.JSON(http.StatusOK, response.User)
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
	c.SetCookie(
		"access_token",
		"",
		-1,
		"/",
		"",
		h.secureCookie,
		true,
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "logged out successfully",
	})
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

func validationMessage(fieldError validator.FieldError) string {
	switch fieldError.Tag() {
	case "required":
		return "this field is required"

	case "min":
		return "must be at least " + fieldError.Param() + " characters"

	case "max":
		return "must not exceed " + fieldError.Param() + " characters"

	case "email":
		return "must be a valid email address"

	default:
		return "invalid value"
	}
}
