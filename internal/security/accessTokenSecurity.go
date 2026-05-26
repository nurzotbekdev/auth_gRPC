package security

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func ParseAccessToken(tokenString string) (uint, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("invalid signing method")
		}

		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil || !token.Valid {
		return 0, errors.New("invalid access token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, errors.New("invalid claims")
	}

	if typ, ok := claims["type"].(string); !ok || typ != "access" {
		return 0, errors.New("not access token")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return 0, errors.New("invalid expiration")
	}

	if time.Now().Unix() > int64(exp) {
		return 0, errors.New("access token expired")
	}

	sub, ok := claims["sub"].(float64)
	if !ok {
		return 0, errors.New("invalid sub")
	}

	return uint(sub), nil
}
