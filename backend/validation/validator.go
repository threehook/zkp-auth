package validation

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

type Validator struct {
	Errors map[string]string
}

func New() *Validator {
	return &Validator{Errors: make(map[string]string)}
}

func (v *Validator) Valid() bool {
	return len(v.Errors) == 0
}

func (v *Validator) AddError(key, message string) {
	if _, exists := v.Errors[key]; !exists {
		v.Errors[key] = message
	}
}

// ValidateUsername checks username format
func (v *Validator) ValidateUsername(username string) {
	username = strings.TrimSpace(username)

	if username == "" {
		v.AddError("username", "username is required")
		return
	}

	if utf8.RuneCountInString(username) < 3 || utf8.RuneCountInString(username) > 50 {
		v.AddError("username", "username must be between 3 and 50 characters")
		return
	}

	// Alphanumeric, underscores, hyphens only
	validUsername := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validUsername.MatchString(username) {
		v.AddError("username", "username can only contain letters, numbers, underscores, and hyphens")
	}
}

// ValidatePassword checks password strength
func (v *Validator) ValidatePassword(password string) {
	password = strings.TrimSpace(password)

	if password == "" {
		v.AddError("password", "password is required")
		return
	}

	if utf8.RuneCountInString(password) < 8 {
		v.AddError("password", "password must be at least 8 characters")
		return
	}

	if utf8.RuneCountInString(password) > 100 {
		v.AddError("password", "password must be less than 100 characters")
		return
	}
}

// ValidateProofStructure validates ZKP proof format
func (v *Validator) ValidateProofStructure(proof map[string]interface{}) {
	if proof == nil {
		v.AddError("proof", "proof is required")
		return
	}

	// Check required proof components
	required := []string{"pi_a", "pi_b", "pi_c", "protocol", "curve"}
	for _, field := range required {
		if proof[field] == nil {
			v.AddError("proof", fmt.Sprintf("proof missing required field: %s", field))
		}
	}

	// Validate protocol and curve
	if protocol, ok := proof["protocol"].(string); ok && protocol != "groth16" {
		v.AddError("proof", "only groth16 protocol is supported")
	}

	if curve, ok := proof["curve"].(string); ok && curve != "bn128" {
		v.AddError("proof", "only bn128 curve is supported")
	}
}

// ValidatePublicSignals validates public signals format
func (v *Validator) ValidatePublicSignals(publicSignals []interface{}) {
	if publicSignals == nil || len(publicSignals) == 0 {
		v.AddError("publicSignals", "public signals are required")
		return
	}

	if len(publicSignals) != 4 {
		v.AddError("publicSignals", "expected exactly 4 public signals")
		return
	}

	// All signals should be strings
	for i, signal := range publicSignals {
		if _, ok := signal.(string); !ok {
			v.AddError("publicSignals", fmt.Sprintf("public signal %d must be a string", i))
		}
	}
}

// ValidateNonce validates proof nonce format
func (v *Validator) ValidateNonce(nonce string) {
	nonce = strings.TrimSpace(nonce)

	if nonce == "" {
		v.AddError("nonce", "nonce is required")
		return
	}

	if len(nonce) < 16 {
		v.AddError("nonce", "nonce must be at least 16 characters")
		return
	}

	if len(nonce) > 100 {
		v.AddError("nonce", "nonce must be less than 100 characters")
		return
	}
}

// ValidateTimestamp validates proof timestamp
func (v *Validator) ValidateTimestamp(timestamp int64) {
	if timestamp == 0 {
		v.AddError("timestamp", "timestamp is required")
		return
	}

	// Basic timestamp validation (not in future, not too old)
	// More specific validation happens in proof package
}
