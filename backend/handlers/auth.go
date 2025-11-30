package handlers

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"zkp-auth/app"
	"zkp-auth/proof"
	"zkp-auth/repository"
	"zkp-auth/validation"
)

type AuthHandler struct {
	deps *app.Dependencies
}

func NewAuthHandler(deps *app.Dependencies) *AuthHandler {
	return &AuthHandler{
		deps: deps,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BindJSON(&req); err != nil {
		log.Printf("❌ BindJSON error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	// Validation
	if req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
		return
	}

	if len(req.Username) < 3 || len(req.Username) > 50 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username must be 3-50 characters"})
		return
	}

	// Create user
	user, err := h.deps.UserRepo.CreateUser(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		return
	}

	log.Printf("🔐 User registered - Username: %s, Salt: %s", user.Username, user.Salt)

	c.JSON(http.StatusOK, gin.H{
		"message": "User registered successfully",
		"salt":    user.Salt,
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Username string        `json:"username"`
		Proof    proof.Request `json:"proof"`
	}

	if err := c.BindJSON(&req); err != nil {
		h.deps.SecurityMonitor.LogEvent("INVALID_JSON", "", c.ClientIP(), c.Request.UserAgent(), "", "",
			"Invalid JSON in login", "WARN")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	// Set proof type if not set
	if req.Proof.ProofType == "" {
		req.Proof.ProofType = proof.ProofTypeLogin
	}

	// Input validation
	validator := validation.New()
	validator.ValidateUsername(req.Username)

	if req.Proof.Proof == nil {
		validator.AddError("proof", "proof object is required")
	} else {
		validator.ValidateProofStructure(req.Proof.Proof)
	}

	validator.ValidatePublicSignals(req.Proof.PublicSignals)
	validator.ValidateNonce(req.Proof.Nonce)
	validator.ValidateTimestamp(req.Proof.Timestamp)

	if !validator.Valid() {
		h.deps.SecurityMonitor.LogEvent("VALIDATION_FAILED", req.Username, c.ClientIP(), c.Request.UserAgent(), "", req.Proof.Nonce,
			fmt.Sprintf("Validation errors: %v", validator.Errors), "WARN")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Validation failed", "details": validator.Errors})
		return
	}

	// Verify user exists
	user, exists := h.deps.UserRepo.GetUser(req.Username)
	if !exists {
		h.deps.SecurityMonitor.LogEvent("USER_NOT_FOUND", req.Username, c.ClientIP(), c.Request.UserAgent(), "", req.Proof.Nonce,
			"User not found during login", "WARN")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Get security context
	ipAddress := c.ClientIP()
	userAgent := c.Request.UserAgent()

	// Security logging - login attempt
	h.deps.SecurityMonitor.LogEvent("LOGIN_ATTEMPT", req.Username, ipAddress, userAgent, "", req.Proof.Nonce,
		"Login attempt initiated", "INFO")

	// Validate proof request with replay protection
	if err := h.deps.ProofValidator.ValidateProofRequest(req.Proof, ipAddress, userAgent); err != nil {
		h.deps.SecurityMonitor.LogEvent("LOGIN_FAILED", req.Username, ipAddress, userAgent, "", req.Proof.Nonce,
			fmt.Sprintf("Proof validation failed: %s", err.Error()), "WARN")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Proof validation failed: " + err.Error()})
		return
	}

	// Verify ZKP proof
	if !h.verifyZKProof(req.Proof, user) {
		h.deps.SecurityMonitor.LogEvent("PROOF_VERIFICATION_FAILED", req.Username, ipAddress, userAgent, "", req.Proof.Nonce,
			"ZKP proof verification failed", "ERROR")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "ZKP proof verification failed"})
		return
	}

	// Generate JWT token
	token := h.generateJWT(req.Username)

	// Security logging - successful login
	h.deps.SecurityMonitor.LogEvent("LOGIN_SUCCESS", req.Username, ipAddress, userAgent, "", req.Proof.Nonce,
		"User authenticated successfully with ZKP", "INFO")

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  req.Username,
	})
}

func (h *AuthHandler) verifyZKProof(proofReq proof.Request, user interface{}) bool {
	// Type assertion to get the actual user
	authUser, ok := user.(repository.User) // Use auth.User type instead of anonymous struct
	if !ok {
		return false
	}

	proofData := map[string]interface{}{
		"proof":         proofReq.Proof,
		"publicSignals": proofReq.PublicSignals,
		"username":      authUser.Username,
		"salt":          authUser.Salt,
		"storedHash":    authUser.PasswordHash,
		"nonce":         proofReq.Nonce,
		"timestamp":     proofReq.Timestamp,
	}

	return h.deps.ZKPVerifier.VerifyProof(proofData)
}

func (h *AuthHandler) generateJWT(username string) string {
	expirationTime := time.Now().Add(h.deps.Config.JWTExpiry)

	claims := &jwt.RegisteredClaims{
		Subject:   username,
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "zkp-auth",
		ID:        h.generateRandomID(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(h.deps.Config.JWTSecret)
	if err != nil {
		return ""
	}
	return tokenString
}

func (h *AuthHandler) generateRandomID() string {
	return fmt.Sprintf("jti-%d-%d", time.Now().UnixNano(), rand.Intn(1000000))
}

func (h *AuthHandler) Logout(c *gin.Context) {
	username, _ := c.Get("username")

	// Security logging
	h.deps.SecurityMonitor.LogEvent("LOGOUT", username.(string), c.ClientIP(), c.Request.UserAgent(), "", "",
		"User logged out successfully", "INFO")

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func (h *AuthHandler) Protected(c *gin.Context) {
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
