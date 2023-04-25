package controllers

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/rekib0023/go-jwt-auth/database"
	"github.com/rekib0023/go-jwt-auth/models"
	"github.com/rekib0023/go-jwt-auth/utils"
	"golang.org/x/crypto/bcrypt"
)

const SecretKey = "secret"

func Register(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return c.Status(400).SendString(err.Error())
	}

	password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)
	user := models.User{
		Name:     data["name"],
		Email:    data["email"],
		Password: password,
	}

	database.DB.Create(&user)

	token, err := utils.CreateJWTToken(user.Email, SecretKey, time.Now().Add(time.Hour*24).Unix())

	if err != nil {
		database.DB.Delete(&user)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Could not register",
		})
	}

	utils.SetCookie(c, "jwt", token, time.Now().Add(time.Hour*24))

	return c.JSON(user)
}

func Login(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return c.Status(400).SendString(err.Error())
	}

	var user models.User

	database.DB.Where("email = ?", data["email"]).First(&user)

	if user.Id == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"message": "user not found",
		})
	}

	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(data["password"])); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid credentials",
		})
	}

	token, err := utils.CreateJWTToken(user.Email, SecretKey, time.Now().Add(time.Hour*24).Unix())

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Could not login",
		})
	}

	utils.SetCookie(c, "jwt", token, time.Now().Add(time.Hour*24))

	return c.Status(201).JSON(fiber.Map{
		"message": "Logged in successfully",
	})
}

func User(c *fiber.Ctx) error {
	token, err := utils.ParseJWTToken(c, "jwt", SecretKey)

	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "unauthenticated",
		})
	}

	claims := token.Claims.(*jwt.StandardClaims)

	var user models.User

	database.DB.Where("email = ?", claims.Issuer).First(&user)

	return c.JSON(user)
}

func Logout(c *fiber.Ctx) error {

	utils.ClearCookie(c, "jwt")

	return c.JSON(fiber.Map{
		"message": "success",
	})
}
