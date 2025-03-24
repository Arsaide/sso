package auth

import (
	"context"
	ssov1 "github.com/Arsaide/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"regexp"
)

type IAuth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appId int,
	) (token string, err error)
	Register(
		ctx context.Context,
		email string,
		password string,
	) (userId int, err error)
	IsAdmin(
		ctx context.Context,
		userId int,
	) (bool, error)
}

type serverApi struct {
	ssov1.UnimplementedAuthServer

	auth IAuth
}

func Register(gRPC *grpc.Server, auth IAuth) {
	ssov1.RegisterAuthServer(gRPC, &serverApi{auth: auth})
}

const (
	emptyValue = 0
)

func (s *serverApi) Login(
	ctx context.Context,
	req *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {
	email := req.GetEmail()
	password := req.GetPassword()
	appId := req.GetAppId()

	if err := validateLogin(req); err != nil {
		return nil, err
	}

	token, authErr := s.auth.Login(ctx, email, password, int(appId))
	if authErr != nil {
		// TODO...
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func (s *serverApi) Register(
	ctx context.Context,
	req *ssov1.RegisterRequest,
) (*ssov1.RegisterResponse, error) {
	if err := validateRegister(req); err != nil {
		return nil, err
	}

	userId, registerErr := s.auth.Register(ctx, req.GetEmail(), req.GetPassword())

	if registerErr != nil {
		// TODO...
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &ssov1.RegisterResponse{
		UserId: int64(userId),
	}, nil
}

func (s *serverApi) IsAdmin(
	ctx context.Context,
	req *ssov1.IsAdminRequest,
) (*ssov1.IsAdminResponse, error) {
	if err := validateIsAdmin(req); err != nil {
		return nil, err
	}

	idAdmin, isAdminError := s.auth.IsAdmin(ctx, int(req.GetUserId()))

	if isAdminError != nil {
		// TODO...
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &ssov1.IsAdminResponse{
		IsAdmin: idAdmin,
	}, nil
}

func validateLogin(req *ssov1.LoginRequest) error {
	email := req.GetEmail()
	password := req.GetPassword()
	appId := req.GetAppId()
	emailValidation, _ := regexp.MatchString("^[\\w.-]+@[\\w.-]+\\.\\w{2,}$", email)
	passwordValidation, _ := regexp.MatchString("^(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*])[A-Za-z\\d!@#$%^&*]{8,}$", password)

	if password == "" || !passwordValidation || len(password) < 6 {
		return status.Error(
			codes.InvalidArgument,
			"Password is required. Password must contain more than 6 characters, special symbols and one capital letter",
		)
	}

	if email == "" || !emailValidation {
		return status.Error(
			codes.InvalidArgument,
			"Email is required",
		)
	}

	if appId == emptyValue {
		return status.Error(codes.InvalidArgument, "AppId is required")
	}

	return nil
}

func validateRegister(req *ssov1.RegisterRequest) error {
	email := req.GetEmail()
	password := req.GetPassword()
	emailValidation, _ := regexp.MatchString("^[\\w.-]+@[\\w.-]+\\.\\w{2,}$", email)
	passwordValidation, _ := regexp.MatchString("^(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*])[A-Za-z\\d!@#$%^&*]{8,}$", password)

	if password == "" || !passwordValidation || len(password) < 6 {
		return status.Error(
			codes.InvalidArgument,
			"Password is required. Password must contain more than 6 characters, special symbols and one capital letter",
		)
	}

	if email == "" || !emailValidation {
		return status.Error(
			codes.InvalidArgument,
			"Email is required",
		)
	}

	return nil
}

func validateIsAdmin(req *ssov1.IsAdminRequest) error {
	userId := req.GetUserId()

	if userId == emptyValue {
		return status.Error(codes.InvalidArgument, "UserId is required")
	}

	return nil
}
