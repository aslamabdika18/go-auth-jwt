package user

import "time"

type User struct {
	ID           int
	Name         string
	Email        string
	PasswordHash string
	RoleID       int
	Role         string
	IsSuperadmin bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type RefreshToken struct {
	ID        int64
	UserID    int
	SessionID string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type RegisterRequest struct {
	Name     string `json:"name" binding:"required,min=3,max=100"`
	Email    string `json:"email" binding:"required,email,max=255"`
	Password string `json:"password" binding:"required,min=8,max=72"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email,max=255"`
	Password string `json:"password" binding:"required"`
}

type UpdateUserRequest struct {
	Name  string `json:"name" binding:"required,min=3,max=100"`
	Email string `json:"email" binding:"required,email,max=255"`
}

type Response struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type UserListResponse struct {
	Data     []Response `json:"data"`
	Page     int        `json:"page"`
	PageSize int        `json:"page_size"`
	Total    int64      `json:"total"`
}

type LoginResult struct {
	User         Response
	AccessToken  string
	RefreshToken string
}

type RefreshResult struct {
	AccessToken  string
	RefreshToken string
}
