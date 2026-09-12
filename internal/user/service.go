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

var ErrInvalidCredentials = errors.New("invalid credentials")

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

		return nil, fmt.Errorf(
			"get user by email: %w",
			err,
		)
	}

	if err := auth.ComparePassword(
		user.PasswordHash,
		request.Password,
	); err != nil {
		return nil, ErrInvalidCredentials
	}

	accessToken, err := s.jwt.GenerateAccessToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf(
			"generate access token: %w",
			err,
		)
	}

	refreshToken, err := auth.GenerateRefreshToken(
		s.refreshTokenTTL,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"generate refresh token: %w",
			err,
		)
	}

	refreshTokenModel := RefreshToken{
		UserID:    user.ID,
		TokenHash: refreshToken.TokenHash,
		ExpiresAt: refreshToken.ExpiresAt,
	}

	if err := s.repository.WithTransaction(
		ctx,
		func(tx pgx.Tx) error {
			return s.repository.CreateRefreshToken(
				ctx,
				tx,
				refreshTokenModel,
			)
		},
	); err != nil {
		return nil, fmt.Errorf(
			"store refresh token: %w",
			err,
		)
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

	tokenHash := auth.HashRefreshToken(
		refreshTokenString,
	)

	newRefreshToken, err := auth.GenerateRefreshToken(
		s.refreshTokenTTL,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"generate refresh token: %w",
			err,
		)
	}

	var accessToken string

	if err := s.repository.WithTransaction(
		ctx,
		func(tx pgx.Tx) error {
			oldRefreshToken, err := s.repository.ConsumeRefreshToken(
				ctx,
				tx,
				tokenHash,
			)
			if err != nil {
				return err
			}

			accessToken, err = s.jwt.GenerateAccessToken(
				oldRefreshToken.UserID,
			)
			if err != nil {
				return fmt.Errorf(
					"generate access token: %w",
					err,
				)
			}

			newRefreshTokenModel := RefreshToken{
				UserID:    oldRefreshToken.UserID,
				TokenHash: newRefreshToken.TokenHash,
				ExpiresAt: newRefreshToken.ExpiresAt,
			}

			if err := s.repository.CreateRefreshToken(
				ctx,
				tx,
				newRefreshTokenModel,
			); err != nil {
				return fmt.Errorf(
					"store new refresh token: %w",
					err,
				)
			}

			return nil
		},
	); err != nil {
		if errors.Is(err, ErrRefreshTokenNotFound) {
			return nil, ErrRefreshTokenNotFound
		}

		return nil, fmt.Errorf(
			"refresh token rotation: %w",
			err,
		)
	}

	return &RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken.Token,
	}, nil
}

func (s *Service) Logout(
	ctx context.Context,
	refreshTokenString string,
) error {
	if strings.TrimSpace(refreshTokenString) == "" {
		return nil
	}

	tokenHash := auth.HashRefreshToken(
		refreshTokenString,
	)

	if err := s.repository.DeleteRefreshToken(
		ctx,
		tokenHash,
	); err != nil {
		return fmt.Errorf(
			"delete refresh token: %w",
			err,
		)
	}

	return nil
}

func (s *Service) Me(
	ctx context.Context,
	userID int,
) (*Response, error) {
	user, err := s.repository.GetByID(
		ctx,
		userID,
	)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrUserNotFound
		}

		return nil, fmt.Errorf(
			"get current user: %w",
			err,
		)
	}

	return toResponse(user), nil
}

func toResponse(user *User) *Response {
	return &Response{
		ID:        user.ID,
		Name:      user.Name,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}
}
