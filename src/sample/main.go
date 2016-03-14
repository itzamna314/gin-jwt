package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	jwtauth "github.com/itzamna314/gin-jwt"
	"time"
)

const superSecretKey = "CAFEBEEF"

type claimsObject struct {
	auth bool
}

func main() {
	r := gin.New()

	r.POST("/tokens", makeToken)
	r.GET("/private", jwtauth.Validator([]byte(superSecretKey), jwt.SigningMethodHS256), privateHandler)

	r.Run()
}

func privateHandler(c *gin.Context) {
	claims := c.MustGet("claims").(map[string]interface{})
	auth, ok := claims["auth"].(bool)
	if !ok || !auth {
		c.AbortWithError(401, fmt.Errorf("Request Unauthorized"))
	}

	c.JSON(200, gin.H{
		"request status": "authorized",
	})
}

func makeToken(c *gin.Context) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["auth"] = true
	token.Claims["exp"] = time.Now().Add(time.Hour).Unix()

	tokenString, err := token.SignedString([]byte(superSecretKey))

	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}

	c.JSON(200, gin.H{
		"token": tokenString,
	})
}
