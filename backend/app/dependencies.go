package app

import (
	"time"

	"zkp-auth/proof"
	"zkp-auth/repository"
	"zkp-auth/security"
	"zkp-auth/verifier"
)

type Config struct {
	JWTSecret  []byte
	ServerPort string
	CorsOrigin string
	ProofTTL   time.Duration
	JWTExpiry  time.Duration
}

type Dependencies struct {
	Config          Config
	UserRepo        repository.UserRepo
	ProofValidator  *proof.Validator
	ZKPVerifier     *verifier.Groth16Verifier
	SecurityMonitor *security.SecurityMonitor
}
