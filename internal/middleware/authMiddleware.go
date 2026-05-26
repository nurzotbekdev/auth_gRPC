package middleware

import (
	"context"
	"strings"

	"auth_gRPC/config"
	"auth_gRPC/internal/security"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func AuthInterceptor() grpc.UnaryServerInterceptor {

	protectedMethods := map[string]bool{
		"/auth.AuthService/MyProfile":     true,
		"/auth.AuthService/UpdateProfile": true,
		"/auth.AuthService/Logout":        true,
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if !protectedMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "metadata missing")
		}

		authHeader := md["authorization"]
		if len(authHeader) == 0 {
			return nil, status.Error(codes.Unauthenticated, "authorization required")
		}

		token := authHeader[0]

		if !strings.HasPrefix(token, "Bearer ") {
			return nil, status.Error(codes.Unauthenticated, "invalid token format")
		}

		token = strings.TrimPrefix(token, "Bearer ")

		blacklisted, err := config.RedisClient.Get(
			config.Ctx,
			"blacklist:"+token,
		).Result()

		if err == nil && blacklisted != "" {
			return nil, status.Error(
				codes.Unauthenticated,
				"token revoked (logout)",
			)
		}

		userID, err := security.ParseAccessToken(token)
		if err != nil {
			return nil, status.Error(
				codes.Unauthenticated,
				"invalid or expired token",
			)
		}

		ctx = context.WithValue(ctx, "user_id", userID)

		return handler(ctx, req)
	}
}
