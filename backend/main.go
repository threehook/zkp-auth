package main

import (
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"zkp-auth/app"
	"zkp-auth/handlers"
	"zkp-auth/middleware"
	"zkp-auth/proof"
	"zkp-auth/repository"
	"zkp-auth/security"
	"zkp-auth/verifier"
)

func main() {
	// Load environment variables
	godotenv.Load("backend/.env")

	// Initialize dependencies
	deps := initDependencies()

	// Create and setup router
	router := setupRouter(deps)

	// Start server
	log.Printf("Server running on :%s", deps.Config.ServerPort)
	router.Run(":" + deps.Config.ServerPort)
}

func initDependencies() *app.Dependencies {
	cfg := app.Config{
		JWTSecret:  getJWTSecret(),
		ServerPort: getEnv("SERVER_PORT", "8080"),
		CorsOrigin: getEnv("CORS_ORIGIN", "http://localhost:5173"),
		ProofTTL:   5 * time.Minute,
		JWTExpiry:  24 * time.Hour,
	}

	// Initialize dependencies
	userRepository := repository.NewMemoryUserRepo()
	proofStore := proof.NewStore(cfg.ProofTTL)
	proofValidator := proof.NewValidator(proofStore, cfg.ProofTTL, 2*time.Minute)
	zkpVerifier := verifier.NewGroth16Verifier()
	securityMonitor := security.GlobalMonitor

	return &app.Dependencies{
		Config:          cfg,
		UserRepo:        userRepository,
		ProofValidator:  proofValidator,
		ZKPVerifier:     zkpVerifier,
		SecurityMonitor: securityMonitor,
	}
}

func setupRouter(deps *app.Dependencies) *gin.Engine {
	router := gin.Default()

	// Global middleware
	router.Use(middleware.CORS(deps.Config.CorsOrigin))
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RequestSizeLimit(100 * 1024))
	router.Use(middleware.RateLimit())
	router.Use(handlers.SecurityMiddleware(deps))

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(deps)
	adminHandler := handlers.NewAdminHandler(deps.SecurityMonitor)

	// Routes
	router.GET("/health", handlers.HealthCheck)
	router.POST("/api/register", authHandler.Register)
	router.POST("/api/login", authHandler.Login)

	// Protected routes
	protected := router.Group("/api")
	protected.Use(handlers.AuthMiddleware(deps.Config.JWTSecret))
	{
		protected.POST("/logout", authHandler.Logout)
		protected.GET("/protected", authHandler.Protected)
		protected.GET("/admin/security-events", adminHandler.SecurityEvents)
	}

	return router
}

func getJWTSecret() []byte {
	jwtSecretStr := os.Getenv("JWT_SECRET")
	if jwtSecretStr == "" {
		log.Fatal("JWT_SECRET environment variable must be set in production!")
	}
	return []byte(jwtSecretStr)
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
