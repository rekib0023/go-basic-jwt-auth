package database

import (
	"github.com/rekib0023/go-jwt-auth/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect() {

	conn, err := gorm.Open(mysql.Open("root:password@tcp(172.17.0.2:3306)/go_jwt_auth"), &gorm.Config{})

	if err != nil {
		panic("failed to connect database")
	}

	DB = conn

	conn.AutoMigrate(&models.User{})

}
