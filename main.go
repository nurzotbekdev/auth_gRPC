package main

import (
	"log"
	"net"

	"auth_gRPC/config"
	pb "auth_gRPC/gen"
	"auth_gRPC/internal/handlers"
	"auth_gRPC/internal/middleware"
	"auth_gRPC/internal/services"

	"google.golang.org/grpc"
)

func main() {
	config.EnvConfig()
	config.DatabaseConfig()
	config.RedisConfig()
	config.MigrateConfig()

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	authService := services.NewAuthService()
	authHandler := handlers.NewAuthHandler(authService)

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(
			middleware.AuthInterceptor(),
		),
	)

	pb.RegisterAuthServiceServer(
		grpcServer,
		authHandler,
	)

	log.Println("gRPC server running on :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
