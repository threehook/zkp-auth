package proof

import "time"

type ProofType string

const (
	ProofTypeLogin ProofType = "login"
	ProofTypeAuth  ProofType = "auth"
)

type Request struct {
	Username      string                 `json:"username"`
	Proof         map[string]interface{} `json:"proof"`
	PublicSignals []interface{}          `json:"publicSignals"`
	Nonce         string                 `json:"nonce"`
	Timestamp     int64                  `json:"timestamp"`
	SessionID     string                 `json:"sessionId,omitempty"` // NEW: Session binding
	ProofType     ProofType              `json:"proofType"`           // NEW: Proof categorization
}

type ProofMetadata struct {
	Nonce     string
	Timestamp time.Time
	Username  string
	SessionID string
	ProofType ProofType
	IPAddress string // NEW: Client IP tracking
	UserAgent string // NEW: Client fingerprinting
	CreatedAt time.Time
}
