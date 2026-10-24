package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aslamabdika18/go-auth-jwt/internal/auth"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidPagination  = errors.New("invalid pagination parameters")
)

type Service struct {
	repository      *Repository
	jwt             *auth.JWT
	refreshTokenTTL time.Duration
}

func NewService(
	repository *Repository,
	jwt *auth.JWT,
	refreshTokenTTL time.Duration,
) *Service {
	return &Service{
		repository:      repository,
		jwt:             jwt,
		refreshTokenTTL: refreshTokenTTL,
	}
}

func (s *Service) Register(
	ctx context.Context,
	request RegisterRequest,
) (*Response, error) {
	name := strings.TrimSpace(request.Name)
	email := strings.ToLower(strings.TrimSpace(request.Email))

	passwordHash, err := auth.HashPassword(request.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	createdUser, err := s.repository.Create(
		ctx,
		name,
		email,
		passwordHash,
	)
	if err != nil {
		return nil, err
	}

	return toResponse(createdUser), nil
}

func (s *Service) Login(
	ctx context.Context,
	request LoginRequest,
) (*LoginResult, error) {
	email := strings.ToLower(strings.TrimSpace(request.Email))

	user, err := s.repository.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	if err := auth.ComparePassword(user.PasswordHash, request.Password); err != nil {
		return nil, ErrInvalidCredentials
	}

	sessionID, err := auth.GenerateSessionID()
	if err != nil {
		return nil, fmt.Errorf("generate session ID: %w", err)
	}

	refreshToken, err := auth.GenerateRefreshToken(s.refreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	accessToken, err := s.jwt.GenerateAccessToken(user.ID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	refreshTokenModel := RefreshToken{
		UserID:    user.ID,
		SessionID: sessionID,
		TokenHash: refreshToken.TokenHash,
		ExpiresAt: refreshToken.ExpiresAt,
	}

	err = s.repository.WithTransaction(ctx, func(tx pgx.Tx) error {
		if err := s.repository.CreateSession(
			ctx,
			tx,
			sessionID,
			user.ID,
			refreshToken.ExpiresAt,
		); err != nil {
			return err
		}

		if err := s.repository.CreateRefreshToken(
			ctx,
			tx,
			refreshTokenModel,
		); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("create login session: %w", err)
	}

	return &LoginResult{
		User:         *toResponse(user),
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
	}, nil
}

func (s *Service) Refresh(
	ctx context.Context,
	refreshTokenString string,
) (*RefreshResult, error) {
	if strings.TrimSpace(refreshTokenString) == "" {
		return nil, ErrRefreshTokenNotFound
	}

	newRefreshToken, err := auth.GenerateRefreshToken(s.refreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	tokenHash := auth.HashRefreshToken(refreshTokenString)
	var accessToken string

	err = s.repository.WithTransaction(ctx, func(tx pgx.Tx) error {
		// 1. Baca token tanpa menguncinya.
		oldToken, err := s.repository.FindRefreshToken(
			ctx, tx, tokenHash,
		)
		if err != nil {
			return err
		}

		// 2. Kunci sesi terlebih dahulu.
		active, err := s.repository.IsSessionActiveTx(
			ctx, tx, oldToken.SessionID, oldToken.UserID,
		)
		if err != nil {
			return err
		}
		if !active {
			return ErrRefreshTokenNotFound
		}

		// 3. Konsumsi token lama setelah sesi terkunci.
		consumedToken, err := s.repository.ConsumeRefreshToken(
			ctx, tx, tokenHash,
		)
		if err != nil {
			return err
		}

		// Pastikan token yang dikonsumsi sesuai dengan sesi awal.
		if consumedToken.SessionID != oldToken.SessionID ||
			consumedToken.UserID != oldToken.UserID {
			return ErrRefreshTokenNotFound
		}

		// 4. Perpanjang sesi.
		if err := s.repository.ExtendSession(
			ctx,
			tx,
			oldToken.SessionID,
			oldToken.UserID,
			newRefreshToken.ExpiresAt,
		); err != nil {
			return err
		}

		// 5. Terbitkan access token untuk sesi yang sama.
		accessToken, err = s.jwt.GenerateAccessToken(
			oldToken.UserID,
			oldToken.SessionID,
		)
		if err != nil {
			return fmt.Errorf("generate access token: %w", err)
		}

		// 6. Simpan refresh token baru.
		return s.repository.CreateRefreshToken(ctx, tx, RefreshToken{
			UserID:    oldToken.UserID,
			SessionID: oldToken.SessionID,
			TokenHash: newRefreshToken.TokenHash,
			ExpiresAt: newRefreshToken.ExpiresAt,
		})
	})
	if err != nil {
		if errors.Is(err, ErrRefreshTokenNotFound) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("refresh token rotation: %w", err)
	}

	return &RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken.Token,
	}, nil
}

func (s *Service) Logout(
	ctx context.Context,
	sessionID string,
	userID int,
) error {
	if strings.TrimSpace(sessionID) == "" || userID <= 0 {
		return fmt.Errorf("invalid session identity")
	}

	if err := s.repository.RevokeSession(
		ctx,
		sessionID,
		userID,
	); err != nil {
		return fmt.Errorf("revoke login session: %w", err)
	}

	return nil
}

func (s *Service) Me(
	ctx context.Context,
	userID int,
) (*Response, error) {
	user, err := s.repository.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrUserNotFound
		}

		return nil, fmt.Errorf("get current user: %w", err)
	}

	return toResponse(user), nil
}

func (s *Service) ListUsers(
	ctx context.Context,
	page int,
	pageSize int,
) (*UserListResponse, error) {
	if page < 1 || pageSize < 1 || pageSize > 100 {
		return nil, ErrInvalidPagination
	}

	// Prevent integer overflow when calculating OFFSET.
	if page-1 > int(^uint(0)>>1)/pageSize {
		return nil, ErrInvalidPagination
	}

	offset := (page - 1) * pageSize

	users, total, err := s.repository.List(
		ctx,
		pageSize,
		offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	data := make([]Response, 0, len(users))

	for i := range users {
		data = append(data, *toResponse(&users[i]))
	}

	return &UserListResponse{
		Data:     data,
		Page:     page,
		PageSize: pageSize,
		Total:    total,
	}, nil
}

func (s *Service) GetUser(
	ctx context.Context,
	userID int,
) (*Response, error) {
	user, err := s.repository.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrUserNotFound
		}

		return nil, fmt.Errorf("get user: %w", err)
	}

	return toResponse(user), nil
}

func (s *Service) UpdateUser(
	ctx context.Context,
	userID int,
	request UpdateUserRequest,
) (*Response, error) {
	name := strings.TrimSpace(request.Name)
	email := strings.ToLower(strings.TrimSpace(request.Email))

	updatedUser, err := s.repository.Update(
		ctx,
		userID,
		name,
		email,
	)
	if err != nil {
		return nil, err
	}

	return toResponse(updatedUser), nil
}

func (s *Service) DeleteUser(
	ctx context.Context,
	userID int,
) error {
	return s.repository.Delete(ctx, userID)
}

func toResponse(user *User) *Response {
	return &Response{
		ID:        user.ID,
		Name:      user.Name,
		Email:     user.Email,
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
	}
}

func (s *Service) IsSessionActive(
	ctx context.Context,
	sessionID string,
	userID int,
) (bool, error) {
	return s.repository.IsSessionActive(ctx, sessionID, userID)
}
