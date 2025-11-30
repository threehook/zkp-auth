package security

import (
	"sync"
	"time"
)

type RateLimitConfig struct {
	Requests      int
	Window        time.Duration
	BlockDuration time.Duration
}

type RateLimiter struct {
	mu       sync.RWMutex
	attempts map[string][]time.Time
	blocked  map[string]time.Time
	config   RateLimitConfig
}

func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		attempts: make(map[string][]time.Time),
		blocked:  make(map[string]time.Time),
		config:   config,
	}
}

// CheckRateLimit checks if request is allowed and records the attempt
func (rl *RateLimiter) CheckRateLimit(identifier string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Check if blocked
	if blockUntil, blocked := rl.blocked[identifier]; blocked {
		if now.Before(blockUntil) {
			return false, blockUntil.Sub(now)
		}
		// Block expired
		delete(rl.blocked, identifier)
	}

	// Clean old attempts
	windowStart := now.Add(-rl.config.Window)
	validAttempts := make([]time.Time, 0)
	for _, attempt := range rl.attempts[identifier] {
		if attempt.After(windowStart) {
			validAttempts = append(validAttempts, attempt)
		}
	}

	// Check if over limit
	if len(validAttempts) >= rl.config.Requests {
		blockUntil := now.Add(rl.config.BlockDuration)
		rl.blocked[identifier] = blockUntil
		rl.attempts[identifier] = validAttempts // Keep current attempts
		return false, blockUntil.Sub(now)
	}

	// Record new attempt
	validAttempts = append(validAttempts, now)
	rl.attempts[identifier] = validAttempts

	return true, 0
}

// GetAttemptCount returns current attempt count for identifier
func (rl *RateLimiter) GetAttemptCount(identifier string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock() // Fixed: changed 'sm' to 'rl'

	windowStart := time.Now().Add(-rl.config.Window)
	count := 0
	for _, attempt := range rl.attempts[identifier] {
		if attempt.After(windowStart) {
			count++
		}
	}
	return count
}
