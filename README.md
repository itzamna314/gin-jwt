# gin-jwt
JWT Middleware for Gin http framework.  Validates the token, and adds the claims payload into the request context.

# Usage
```
package main

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/itzamna314/gin-jwt/jwtauth"
)

const superSecretKey = "CAFEBEEF"

func main() {
	r := gin.New()

	r.GET("/private", jwtauth.Validator([]byte(superSecretKey), jwt.SigningMethodHS256), privateHandler)

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

## Build
Use [gb](https://getgb.io/).

## Based On:
* https://github.com/gin-gonic/gin
* https://github.com/dgrijalva/jwt-go
