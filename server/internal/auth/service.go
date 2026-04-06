package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/adamgeorgiou/mcp_auth/server/internal/store"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthorized       = errors.New("unauthorized")
)

type Service struct {
	store      *store.Store
	sessionTTL time.Duration
}

func New(store *store.Store, sessionTTL time.Duration) *Service {
	return &Service{store: store, sessionTTL: sessionTTL}
}

func (s *Service) EnsureBootstrapUser(
	ctx context.Context,
	email string,
	password string,
) (*store.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash bootstrap password: %w", err)
	}
	return s.store.EnsureBootstrapUser(ctx, strings.ToLower(strings.TrimSpace(email)), string(hash))
}

func (s *Service) Login(
	ctx context.Context,
	email string,
	password string,
) (*store.Session, *store.User, error) {
	record, err := s.store.GetUserAuthRecordByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(record.PasswordHash), []byte(password)); err != nil {
		return nil, nil, ErrInvalidCredentials
	}
	session, err := s.store.CreateSession(ctx, record.ID, s.sessionTTL)
	if err != nil {
		return nil, nil, err
	}
	return session, &record.User, nil
}

func (s *Service) Authenticate(ctx context.Context, token string) (*store.User, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, ErrUnauthorized
	}
	user, err := s.store.GetUserBySessionToken(ctx, token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	return user, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	return s.store.DeleteSession(ctx, token)
}
