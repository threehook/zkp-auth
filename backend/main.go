package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type LoginRequest struct {
	Username string `json:"username"`
	Proof    string `json:"proof"` // Serialized ZKP proof
}

type User struct {
	Username string `json:"username"`
	Salt     string `json:"salt"`
	// Add password hash for verification
	PasswordHash int `json:"passwordHash"`
}

var (
	users = map[string]User{
		"alice": {
			Username:     "alice",
			Salt:         "12345",
			PasswordHash: 1518435, // 123 * 12345 = 1518435
		},
	}
	jwtSecret = []byte("your-secret-key")
	verifier  *ZKPVerifier
)

func main() {
	// Initialize ZKP verifier
	var err error
	verifier, err = NewZKPVerifier()
	if err != nil {
		log.Fatalf("Failed to initialize ZKP verifier: %v", err)
	}

	r := gin.Default()

	// Add CORS middleware for React frontend
	r.Use(corsMiddleware())

	r.POST("/api/register", handleRegister)
	r.POST("/api/login", handleLogin)
	r.GET("/api/protected", authMiddleware(), handleProtected)

	log.Println("Server running on :8080")
	r.Run(":8080")
}

// CORS middleware
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func handleRegister(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Generate salt and compute password hash
	salt := "12345" // In production, use crypto/rand
	passwordInt := simpleHash(req.Password)
	passwordHash := passwordInt * saltToInt(salt)

	// Store user
	users[req.Username] = User{
		Username:     req.Username,
		Salt:         salt,
		PasswordHash: passwordHash,
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User registered successfully",
		"salt":    salt, // Frontend needs this for proof generation
	})
}

func handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Verify user exists
	user, exists := users[req.Username]
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Verify ZKP proof
	if verifyZKProof(req.Proof, user) {
		token := generateJWT(req.Username)
		c.JSON(http.StatusOK, gin.H{
			"token": token,
			"user":  req.Username,
		})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid proof"})
	}
}

func verifyZKProof(proof string, user User) bool {
	var proofData map[string]interface{}
	if err := json.Unmarshal([]byte(proof), &proofData); err != nil {
		log.Printf("Failed to parse proof: %v", err)
		return false
	}

	// Verify the proof structure and content
	return verifier.VerifyProof(proofData) // Only one argument!
}

func generateJWT(username string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		log.Printf("Error generating JWT: %v", err)
		return ""
	}
	return tokenString
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
			c.Abort()
			return
		}

		// Remove "Bearer " prefix if present
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			c.Set("username", claims["username"])
		}

		c.Next()
	}
}

func handleProtected(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "This is protected data!",
		"user":    username,
		"secret":  "Very sensitive information that requires ZKP auth",
	})
}

// Helper functions for demo
func simpleHash(password string) int {
	hash := 0
	for i := 0; i < len(password); i++ {
		hash = ((hash << 5) - hash) + int(password[i])
		hash |= 0
	}
	return hash
}

func saltToInt(salt string) int {
	result := 0
	for i := 0; i < len(salt); i++ {
		result = result*10 + int(salt[i]-'0')
	}
	return result
}
