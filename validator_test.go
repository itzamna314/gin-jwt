package jwtauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

const (
	secretKey = "MyTestSigningKey"
	realm     = "http://foo.bar.com"
)

func TestNoToken(t *testing.T) {
	router := createRouter()
	response := makeRequest(router, "GET", "/private", "")

	if response.Code != 401 {
		t.Errorf("No token.  Expected 401, got %d", response.Code)
	}

	if realm != response.Header().Get("Location") {
		t.Errorf("Realm was not set in the location header")
	}
}

func TestEmptyToken(t *testing.T) {
	router := createRouter()
	response := makeRequest(router, "GET", "/private", "Authorization: Bearer ")
	if response.Code != 401 {
		t.Errorf("Empty token: Expected 401, got %d", response.Code)
	}

}

func TestWrongKey(t *testing.T) {
	router := createRouter()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"auth": true,
	})
	tokenString, _ := token.SignedString([]byte("WrongKey"))
	response := makeRequest(router, "GET", "/private", fmt.Sprintf("Bearer %s", tokenString))
	if response.Code != 401 {
		t.Errorf("Empty token: Expected 401, got %d", response.Code)
	}
}

func TestValidKey(t *testing.T) {
	router := createRouter()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"auth": true,
	})
	tokenString, _ := token.SignedString([]byte("MyTestSigningKey"))
	response := makeRequest(router, "GET", "/private", fmt.Sprintf("Bearer %s", tokenString))
	if response.Code != 200 {
		t.Errorf("Correct token: Expected 200, got %d", response.Code)
	}
	response.Flush()

	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Errorf("Failed to unmarshal response: %s", err)
		return
	}

	claims, ok := body["claims"].(map[string]interface{})
	if !ok {
		t.Errorf("Claims missing from body")
		return
	}

	auth, ok := claims["auth"].(bool)
	if !ok {
		t.Errorf("Missing auth claim")
		return
	}

	if !auth {
		t.Errorf("Auth was somehow valid but false")
	}
}

func createRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	validator := Validator{
		Key:      []byte(secretKey),
		Method:   jwt.SigningMethodHS256,
		Location: new(string),
	}
	*validator.Location = realm

	router := gin.New()
	router.GET("/private", validator.Middleware(), privateHandler)
	return router
}

func privateHandler(c *gin.Context) {
	var claims map[string]interface{}
	if cl, exists := c.Get("claims"); exists {
		var ok bool
		// gin-jwt uses jwt.MapClaims from dgijalva/jwt-go.
		claims, ok = cl.(jwt.MapClaims)
		if !ok {
			fmt.Printf("Error from privateHandler: Failed to parse claims\n")
			c.AbortWithError(401, fmt.Errorf("missing claims"))
		}
	}

	// Write out the plaintext claims in the response for the purposes of this
	// test.  Note that the jwt.MapClaims will be serialized into a plain
	// map[string]interface{}.  Also, never do this in a real api.
	c.JSON(200, gin.H{
		"claims": claims,
	})
}

func makeRequest(r http.Handler, method, path, authHeader string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, nil)
	if authHeader != "" {
		req.Header.Add("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
