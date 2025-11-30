package config

import "time"

type SecurityConfig struct {
	JWTSecret        string
	SessionDuration  time.Duration
	ProofTTL         time.Duration
	RateLimitWindow  time.Duration
	MaxLoginAttempts int
	MaxProofAttempts int
}

func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		SessionDuration:  24 * time.Hour,
		ProofTTL:         5 * time.Minute,
		RateLimitWindow:  1 * time.Minute,
		MaxLoginAttempts: 5,
		MaxProofAttempts: 10,
	}
}
