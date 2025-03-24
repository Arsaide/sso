package auth

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/services/storage"
	"time"
)

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	tokenTTL     time.Duration
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userId int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appId int) (models.App, error)
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppId       = errors.New("invalid app id")
	ErrUserExists         = errors.New("user already exists")
)

// New returns a new instance of Auth service.
func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		userSaver:    userSaver,
		userProvider: userProvider,
		log:          log,
		appProvider:  appProvider,
		tokenTTL:     tokenTTL,
	}
}

// Login checks if user with given credentials exists in the system.
//
// If user exist, but password is incorrect, func return error.
// If user doesn't exist, returns error.
func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appId int,
) (string, error) {
	const op = "auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("username", email),
	)

	log.Info("attempting to login user")

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", "error", err)

			return "", fmt.Errorf("%s, %w", op, ErrInvalidCredentials)
		}

		a.log.Error("failed to get user", "error", err)

		return "", fmt.Errorf("%s, %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid password", "error", err)

		return "", fmt.Errorf("%s, %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appId)
	if err != nil {
		return "", fmt.Errorf("%s, %w", op, err)
	}

	log.Info("user logged in successfully")

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", "error", err)

		return "", fmt.Errorf("%s, %w", op, err)
	}

	return token, nil
}

// RegisterNewUser registers new users in the system and returns user ID.
// If user with given username already exist, returns error.
func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	pass string,
) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registration new user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)

	if err != nil {
		log.Error("failed to generate password hash", "error", err)

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", "error", err)

			return 0, fmt.Errorf("%s, %w", op, ErrUserExists)
		}

		log.Error("failed to save user", "error", err)

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("New user registrations successfully", "email", email)

	return id, nil
}

// IsAdmin checks if user is admin.
func (a *Auth) IsAdmin(
	ctx context.Context,
	userId int64,
) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userId),
	)

	log.Info("checking if user is admin")

	isAdmin, err := a.userProvider.IsAdmin(ctx, userId)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("user not found", "error", err)

			return false, fmt.Errorf("%s, %w", op, ErrInvalidAppId)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checking if user is admin", slog.Bool("isAdmin", isAdmin))

	return isAdmin, nil
}
