package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"zkp-auth/security"
)

type AdminHandler struct {
	securityMonitor *security.SecurityMonitor
}

func NewAdminHandler(securityMonitor *security.SecurityMonitor) *AdminHandler {
	return &AdminHandler{
		securityMonitor: securityMonitor,
	}
}

func (h *AdminHandler) SecurityEvents(c *gin.Context) {
	// Only allow admin users in production
	username, _ := c.Get("username")

	// Simple admin check - enhance this in production
	if username != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	sinceStr := c.Query("since")
	var since time.Time
	if sinceStr != "" {
		parsed, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			since = time.Now().Add(-1 * time.Hour) // Default to last hour
		} else {
			since = parsed
		}
	} else {
		since = time.Now().Add(-1 * time.Hour)
	}

	events := h.securityMonitor.GetEvents(since)
	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"count":  len(events),
		"since":  since,
	})
}
