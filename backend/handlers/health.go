package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func HealthCheck(c *gin.Context) {
	healthInfo := gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
		"services": gin.H{
			"authentication":      "operational",
			"proof_verification":  "operational",
			"security_monitoring": "operational",
		},
	}

	c.JSON(http.StatusOK, healthInfo)
}
