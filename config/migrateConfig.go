package config

import "auth_gRPC/internal/models"

func MigrateConfig() {
	DB.AutoMigrate(&models.User{})
}
