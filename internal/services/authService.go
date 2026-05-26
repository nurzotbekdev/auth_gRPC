package services

import (
	"auth_gRPC/config"
	"auth_gRPC/internal/models"
	"auth_gRPC/internal/schemas"
	"auth_gRPC/internal/security"
	"errors"
	"time"
)

type AuthService interface {
	Register(user *models.User) error
	Login(email, password string) (string, string, error)
	RefreshAccessToken(refreshToken string) (string, error)
	MyProfile(userID uint) (*models.User, error)
	EditeProfile(userID uint, data *schemas.AuthUpdate) error
	EndSession(refreshToken, accessToken string) error
}

type authService struct{}

func NewAuthService() AuthService {
	return &authService{}
}

var (
	ErrEmailAlreadyExists = errors.New("Email already exists")
	ErrPhoneAlreadyExists = errors.New("Phone already exists")
	ErrEmailOrPassword    = errors.New("Invalid email or password")
	ErrRedis              = errors.New("Failed to save refresh token to Redis")
	ErrTokenInvalid       = errors.New("Failed to create token")
	ErrUserNotFound       = errors.New("User not found")
)

func (s *authService) Register(user *models.User) error {
	var existingUser models.User
	if err := config.DB.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		return ErrEmailAlreadyExists
	}

	if err := config.DB.Where("phone = ?", user.Phone).First(&existingUser).Error; err == nil {
		return ErrPhoneAlreadyExists
	}

	hashed, err := security.HashPassword(user.Password)
	if err != nil {
		return err
	}

	user.Password = hashed

	if err := config.DB.Create(user).Error; err != nil {
		return err
	}

	return nil
}

func (s *authService) Login(email, password string) (string, string, error) {
	var user models.User
	if err := config.DB.Where("email = ?", email).First(&user).Error; err != nil {
		return "", "", ErrEmailOrPassword
	}

	if !security.CheckPassword(user.Password, password) {
		return "", "", ErrEmailOrPassword
	}

	accessToken, err := security.GenerateAccessToken(user.ID)
	if err != nil {
		return "", "", ErrTokenInvalid
	}
	refreshToken, err := security.GenerateRefreshToken(user.ID)
	if err != nil {
		return "", "", ErrTokenInvalid
	}
	err = config.RedisClient.Set(config.Ctx, refreshToken, user.ID, 14*24*time.Hour).Err()
	if err != nil {
		return "", "", ErrRedis
	}

	return accessToken, refreshToken, nil
}

func (s *authService) RefreshAccessToken(refreshToken string) (string, error) {
	_, err := config.RedisClient.Get(config.Ctx, refreshToken).Result()
	if err != nil {
		return "", ErrTokenInvalid
	}

	userID, err := security.ParseRefreshToken(refreshToken)
	if err != nil {
		return "", ErrTokenInvalid
	}

	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		return "", ErrUserNotFound
	}

	accessToken, err := security.GenerateAccessToken(user.ID)
	if err != nil {
		return "", ErrTokenInvalid
	}

	return accessToken, nil
}

func (s *authService) MyProfile(userID uint) (*models.User, error) {
	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		return nil, ErrUserNotFound
	}

	return &user, nil
}

func (s *authService) EditeProfile(userID uint, data *schemas.AuthUpdate) error {
	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		return ErrUserNotFound
	}

	if data.Name != nil {
		user.Name = *data.Name
	}

	if data.Surname != nil {
		user.Surname = *data.Surname
	}

	if data.Phone != nil {
		var existingUser models.User
		if err := config.DB.
			Where("phone = ? AND id != ?", *data.Phone, userID).
			First(&existingUser).Error; err == nil {
			return ErrPhoneAlreadyExists
		}

		user.Phone = *data.Phone
	}

	if data.Email != nil {
		var existingUser models.User
		if err := config.DB.
			Where("email = ? AND id != ?", *data.Email, userID).
			First(&existingUser).Error; err == nil {
			return ErrEmailAlreadyExists
		}

		user.Email = *data.Email
	}

	if data.Password != nil {
		hashedPassword, err := security.HashPassword(*data.Password)
		if err != nil {
			return err
		}

		user.Password = hashedPassword
	}

	if err := config.DB.Save(&user).Error; err != nil {
		return err
	}

	return nil
}

func (s *authService) EndSession(refreshToken, accessToken string) error {
	_ = config.RedisClient.Del(config.Ctx, refreshToken).Err()

	return config.RedisClient.Set(config.Ctx, "blacklist:"+accessToken, "1", 30*time.Minute).Err()
}
