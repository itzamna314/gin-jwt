# gin-jwt
JWT Middleware for Gin http framework.  Validates the token, and adds the claims payload into the request context.

# Usage
```go
package main

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/itzamna314/gin-jwt/jwtauth"
)

const superSecretKey = "CAFEBEEF"

func main() {
	validator := jwtauth.Validator{
		Key:      []byte(superSecretKey),
		Method:   jwt.SigningMethodHS256,
		Location: new(string),
	}
	*validator.Location = realm
	r := gin.New()

	r.POST("/tokens", makeToken)
	r.GET("/private", validator.Middleware(), privateHandler)

	r.Run()
}

func privateHandler(c *gin.Context) {
	claims := c.MustGet("claims").(map[string]interface{})
	
	// Verify that the claims grant access to this endpoint...

	c.JSON(200, gin.H{
		"secretData": "Illuminati!",
	})
}
```
## Get
* `go get github.com/itzamna314/gin-jwt`
* `gb vendor fetch github.com/itzamna314/gin-jwt`

## Build
Use [gb](https://getgb.io/).

## Based On:
* https://github.com/gin-gonic/gin
* https://github.com/dgrijalva/jwt-go
