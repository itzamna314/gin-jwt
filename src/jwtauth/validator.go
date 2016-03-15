package jwtauth

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type Validator struct {
	Key      interface{}
	Method   jwt.SigningMethod
	Location *string
}

func (v *Validator) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := jwt.ParseFromRequest(c.Request, func(token *jwt.Token) (interface{}, error) {
			if v.Method.Alg() != token.Method.Alg() {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return v.Key, nil
		})

		if err != nil {
			v.unauthorized(c)
			return
		}

		if !token.Valid {
			v.unauthorized(c)
			return
		}

		c.Set("claims", token.Claims)
	}
}

func (v *Validator) unauthorized(c *gin.Context) {
	if v.Location != nil {
		c.Writer.Header().Set("Location", *v.Location)
	}
	c.AbortWithError(401, fmt.Errorf("Request unauthorized"))
}
