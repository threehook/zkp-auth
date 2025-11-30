package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"zkp-auth/app"
)

// AuthMiddleware (capitalized to export it)
func AuthMiddleware(jwtSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
			c.Abort()
			return
		}

		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Extract username from Subject claim
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if subject, exists := claims["sub"]; exists {
				if username, ok := subject.(string); ok {
					c.Set("username", username)
					c.Next()
					return
				}
			}
		}

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		c.Abort()
	}
}

func SecurityMiddleware(deps *app.Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		ipAddress := c.ClientIP()
		userAgent := c.Request.UserAgent()
		path := c.Request.URL.Path

		c.Next()

		// Log security events for certain status codes
		status := c.Writer.Status()
		if status >= 400 {
			username, _ := c.Get("username")
			deps.SecurityMonitor.LogEvent("HTTP_ERROR", username.(string), ipAddress, userAgent, "", "",
				fmt.Sprintf("path=%s status=%d", path, status), "WARN")
		}
	}
}
