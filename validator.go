package jwtauth

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func Validator(key []byte, method jwt.SigningMethod) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := jwt.ParseFromRequest(c.Request, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if method.Alg() != token.Method.Alg() {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return key, nil
		})

		if err != nil {
			c.AbortWithError(401, err)
			return
		}

		if !token.Valid {
			c.AbortWithError(401, err)
		}

		c.Set("claims", token.Claims)
	}
}
