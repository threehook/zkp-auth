package security

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

type SecurityEvent struct {
	Type      string    `json:"type"`
	Username  string    `json:"username,omitempty"`
	IPAddress string    `json:"ipAddress"`
	UserAgent string    `json:"userAgent,omitempty"`
	SessionID string    `json:"sessionId,omitempty"`
	Nonce     string    `json:"nonce,omitempty"`
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"` // INFO, WARN, ERROR, CRITICAL
}

type SecurityMonitor struct {
	mu        sync.RWMutex
	events    []SecurityEvent
	maxEvents int
}

func NewSecurityMonitor(maxEvents int) *SecurityMonitor {
	return &SecurityMonitor{
		events:    make([]SecurityEvent, 0, maxEvents),
		maxEvents: maxEvents,
	}
}

func (sm *SecurityMonitor) LogEvent(eventType, username, ipAddress, userAgent, sessionID, nonce, details, severity string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	event := SecurityEvent{
		Type:      eventType,
		Username:  username,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		SessionID: sessionID,
		Nonce:     nonce,
		Details:   details,
		Timestamp: time.Now(),
		Severity:  severity,
	}

	// Add event to buffer
	sm.events = append(sm.events, event)

	// Maintain buffer size
	if len(sm.events) > sm.maxEvents {
		sm.events = sm.events[1:]
	}

	// Log to console with emojis for visibility
	emoji := getSeverityEmoji(severity)
	log.Printf("%s SECURITY: %s - user=%s ip=%s details=%s",
		emoji, eventType, username, ipAddress, details)
}

func (sm *SecurityMonitor) GetEvents(since time.Time) []SecurityEvent {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var filtered []SecurityEvent
	for _, event := range sm.events {
		if event.Timestamp.After(since) {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func (sm *SecurityMonitor) GetEventsJSON(since time.Time) (string, error) {
	events := sm.GetEvents(since)
	jsonData, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func getSeverityEmoji(severity string) string {
	switch severity {
	case "CRITICAL":
		return "🚨"
	case "ERROR":
		return "❌"
	case "WARN":
		return "⚠️"
	default:
		return "🔍"
	}
}

// Global security monitor instance
var GlobalMonitor = NewSecurityMonitor(10000) // Keep last 10,000 events
