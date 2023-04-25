package utils

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
)

func SetCookie(c *fiber.Ctx, name string, value string, expiration time.Time) {
	c.Cookie(buildCookie(name, value, expiration))
}

func ClearCookie(c *fiber.Ctx, name string) {
	c.Cookie(buildCookie(name, "", time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)))
}

func CreateJWTToken(issuer string, secretKey string, expiresAt int64) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    issuer,
		ExpiresAt: expiresAt,
	})

	token, err := claims.SignedString([]byte(secretKey))

	return token, err
}

func ParseJWTToken(c *fiber.Ctx, name string, secretKey string) (*jwt.Token, error) {
	cookie := c.Cookies(name)
	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	return token, err
}

func buildCookie(name string, value string, expires time.Time) *fiber.Cookie {
	cookie := new(fiber.Cookie)
	cookie.Name = name
	cookie.Value = value
	cookie.HTTPOnly = true
	cookie.Expires = expires

	return cookie
}
