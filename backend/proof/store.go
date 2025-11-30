package proof

import (
	"sync"
	"time"
)

type ProofRecord struct {
	Nonce     string
	Timestamp time.Time
	Username  string
	ProofType ProofType
	IPAddress string
	UserAgent string
	CreatedAt time.Time
}

type Store struct {
	mu         sync.RWMutex
	usedProofs map[string]ProofRecord
	proofTTL   time.Duration
}

func NewStore(ttl time.Duration) *Store {
	return &Store{
		usedProofs: make(map[string]ProofRecord),
		proofTTL:   ttl,
	}
}

// AddProof adds a proof with enhanced metadata and returns true if it was new
func (ps *Store) AddProof(nonce string, username string, proofType ProofType, ipAddress string, userAgent string) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Clean expired proofs first
	ps.cleanExpired()

	// Check if proof already exists
	if _, exists := ps.usedProofs[nonce]; exists {
		return false
	}

	// Add new proof with enhanced metadata
	ps.usedProofs[nonce] = ProofRecord{
		Nonce:     nonce,
		Timestamp: time.Now(),
		Username:  username,
		ProofType: proofType,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
	}
	return true
}

// HasProof checks if a proof has been used
func (ps *Store) HasProof(proofID string) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	_, exists := ps.usedProofs[proofID]
	return exists
}

// GetProofMetadata retrieves proof metadata for auditing
func (ps *Store) GetProofMetadata(proofID string) (ProofRecord, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	record, exists := ps.usedProofs[proofID]
	return record, exists
}

// GetProofsByUsername for security monitoring
func (ps *Store) GetProofsByUsername(username string) []ProofRecord {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	var records []ProofRecord
	for _, record := range ps.usedProofs {
		if record.Username == username {
			records = append(records, record)
		}
	}
	return records
}

// Cleanup explicitly cleans expired proofs
func (ps *Store) Cleanup() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.cleanExpired()
}

func (ps *Store) cleanExpired() {
	now := time.Now()
	for nonce, record := range ps.usedProofs {
		if now.Sub(record.CreatedAt) > ps.proofTTL {
			delete(ps.usedProofs, nonce)
		}
	}
}
