package handlers

import (
	pb "auth_gRPC/gen"
	"auth_gRPC/internal/models"
	"auth_gRPC/internal/schemas"
	"auth_gRPC/internal/services"
	"context"
	"strconv"
	"strings"

	"google.golang.org/grpc/metadata"
)

type AuthHandler struct {
	pb.UnimplementedAuthServiceServer
	service services.AuthService
}

func NewAuthHandler(s services.AuthService) *AuthHandler {
	return &AuthHandler{service: s}
}

func (h *AuthHandler) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.MessageResponse, error) {
	user := &models.User{
		Name:     req.Name,
		Surname:  req.Surname,
		Phone:    req.Phone,
		Email:    req.Email,
		Password: req.Password,
	}

	if err := h.service.Register(user); err != nil {
		return nil, err
	}

	return &pb.MessageResponse{
		Message: "user successfully registered",
	}, nil
}

func (h *AuthHandler) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse, error) {
	accessToken, refreshToken, err := h.service.Login(
		req.Email,
		req.Password,
	)

	if err != nil {
		return nil, err
	}

	return &pb.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (h *AuthHandler) RefreshToken(ctx context.Context, req *pb.RefreshRequest) (*pb.RefreshResponse, error) {
	accessToken, err := h.service.RefreshAccessToken(
		req.RefreshToken,
	)

	if err != nil {
		return nil, err
	}

	return &pb.RefreshResponse{
		AccessToken: accessToken,
	}, nil
}

func (h *AuthHandler) MyProfile(ctx context.Context, req *pb.MyProfileRequest) (*pb.UserResponse, error) {
	userID := ctx.Value("user_id").(uint)

	user, err := h.service.MyProfile(userID)
	if err != nil {
		return nil, err
	}

	return &pb.UserResponse{
		Id:       strconv.Itoa(int(user.ID)),
		Name:     user.Name,
		Surname:  user.Surname,
		Phone:    user.Phone,
		Email:    user.Email,
		IsActive: user.IsActive,
	}, nil
}

func (h *AuthHandler) UpdateProfile(ctx context.Context, req *pb.UpdateProfileRequest) (*pb.MessageResponse, error) {
	userID := ctx.Value("user_id").(uint)

	data := schemas.AuthUpdate{
		Name:     &req.Name,
		Surname:  &req.Surname,
		Phone:    &req.Phone,
		Email:    &req.Email,
		Password: &req.Password,
	}

	if err := h.service.EditeProfile(userID, &data); err != nil {
		return nil, err
	}

	return &pb.MessageResponse{
		Message: "profile updated successfully",
	}, nil
}

func (h *AuthHandler) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.MessageResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	authHeader := md["authorization"][0]

	accessToken := strings.TrimPrefix(authHeader, "Bearer ")

	err := h.service.EndSession(req.RefreshToken, accessToken)
	if err != nil {
		return nil, err
	}

	return &pb.MessageResponse{
		Message: "logout successful",
	}, nil
}
