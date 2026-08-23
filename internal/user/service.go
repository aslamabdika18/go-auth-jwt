package user

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aslamabdika18/go-auth-jwt/internal/auth"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type Service struct {
	repository *Repository
	jwt        *auth.JWT
}

func NewService(
	repository *Repository,
	jwt *auth.JWT,
) *Service {
	return &Service{
		repository: repository,
		jwt:        jwt,
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

	return &Response{
		ID:        createdUser.ID,
		Name:      createdUser.Name,
		Email:     createdUser.Email,
		CreatedAt: createdUser.CreatedAt,
	}, nil
}

func (s *Service) Login(
	ctx context.Context,
	request LoginRequest,
) (*LoginResponse, error) {
	email := strings.ToLower(strings.TrimSpace(request.Email))

	user, err := s.repository.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}

		return nil, fmt.Errorf("get user by email: %w", err)
	}

	if err := auth.ComparePassword(
		user.PasswordHash,
		request.Password,
	); err != nil {
		return nil, ErrInvalidCredentials
	}

	accessToken, err := s.jwt.GenerateAccessToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	return &LoginResponse{
		User: Response{
			ID:        user.ID,
			Name:      user.Name,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
		},
		AccessToken: accessToken,
	}, nil
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

	return &Response{
		ID:        user.ID,
		Name:      user.Name,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}, nil
}
