package proof

import (
	"fmt"
	"log"
	"time"
)

type Validator struct {
	store           *Store
	maxAge          time.Duration
	futureAllowance time.Duration
}

func NewValidator(store *Store, maxAge, futureAllowance time.Duration) *Validator {
	return &Validator{
		store:           store,
		maxAge:          maxAge,
		futureAllowance: futureAllowance,
	}
}

func (v *Validator) GetStore() *Store {
	return v.store
}

// ValidateProofRequest with security context
func (v *Validator) ValidateProofRequest(proofReq Request, ipAddress string, userAgent string) error {
	// Basic validation
	if err := v.validateBasicFields(proofReq); err != nil {
		return err
	}

	// Timestamp validation
	if err := v.validateTimestamp(proofReq); err != nil {
		return err
	}

	// Nonce validation
	if err := v.validateNonce(proofReq.Nonce); err != nil {
		return err
	}

	// Check for replay attack with security context
	if !v.store.AddProof(
		proofReq.Nonce,
		proofReq.Username,
		proofReq.ProofType,
		ipAddress,
		userAgent,
	) {
		return fmt.Errorf("proof replay detected - nonce already used")
	}

	return nil
}

func (v *Validator) validateBasicFields(proofReq Request) error {
	if proofReq.Username == "" {
		return fmt.Errorf("username is required")
	}
	if proofReq.Nonce == "" {
		return fmt.Errorf("nonce is required")
	}
	if proofReq.Timestamp == 0 {
		return fmt.Errorf("timestamp is required")
	}
	if proofReq.Proof == nil {
		return fmt.Errorf("proof is required")
	}
	if proofReq.ProofType == "" {
		return fmt.Errorf("proofType is required")
	}
	return nil
}

func (v *Validator) validateTimestamp(proofReq Request) error {
	proofTime := time.Unix(proofReq.Timestamp, 0)
	now := time.Now()

	if proofTime.After(now.Add(v.futureAllowance)) {
		return fmt.Errorf("proof timestamp is too far in the future")
	}

	if now.Sub(proofTime) > v.maxAge {
		return fmt.Errorf("proof has expired")
	}

	return nil
}

func (v *Validator) validateNonce(nonce string) error {
	if len(nonce) < 16 {
		return fmt.Errorf("nonce too short - minimum 16 characters required")
	}
	if len(nonce) > 256 {
		return fmt.Errorf("nonce too long")
	}
	// Additional nonce format validation can be added here
	return nil
}

// Security logging helper
func (v *Validator) LogSecurityEvent(eventType string, proofReq Request, ipAddress string, details string) {
	// Enhanced security logging
	log.Printf("🔒 SECURITY_EVENT: type=%s user=%s nonce=%s ip=%s details=%s",
		eventType, proofReq.Username, proofReq.Nonce, ipAddress, details)
}
