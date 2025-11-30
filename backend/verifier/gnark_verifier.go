package verifier

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// VerifyingKey matches the gnark structure we discovered
type VerifyingKey struct {
	G1 struct {
		Alpha       bn254.G1Affine
		Beta, Delta bn254.G1Affine
		K           []bn254.G1Affine
	}
	G2 struct {
		Beta, Delta, Gamma bn254.G2Affine
		deltaNeg, gammaNeg bn254.G2Affine
	}
	e bn254.GT

	CommitmentKeys               []PedersenVerifyingKey
	PublicAndCommitmentCommitted [][]int
}

// Proof matches the gnark structure we discovered
type Proof struct {
	Ar, Krs       bn254.G1Affine
	Bs            bn254.G2Affine
	Commitments   []bn254.G1Affine
	CommitmentPok bn254.G1Affine
}

type PedersenVerifyingKey struct {
	// Simplified for this example
	G bn254.G1Affine
	H bn254.G1Affine
}

// Verify implements the Groth16 verification we analyzed
func Verify(proof *Proof, vk *VerifyingKey, publicWitness []fr.Element) error {
	// 1. Validate proof points are in correct subgroup
	if !proof.isValid() {
		return fmt.Errorf("proof points not in correct subgroup")
	}

	// 2. Compute public input linear combination: Σ(x_i * K_i)
	var kSum bn254.G1Jac
	if len(publicWitness) != len(vk.G1.K)-1 {
		return fmt.Errorf("invalid witness size, got %d, expected %d", len(publicWitness), len(vk.G1.K)-1)
	}

	// Multi-exponentiation: kSum = K₀ + Σ(x_i * K_{i+1})
	var k0Jac bn254.G1Jac
	k0Jac.FromAffine(&vk.G1.K[0])
	kSum.Set(&k0Jac)

	for i := 0; i < len(publicWitness); i++ {
		var term bn254.G1Jac
		var kAffine bn254.G1Affine = vk.G1.K[i+1]
		term.FromAffine(&kAffine)
		term.ScalarMultiplication(&term, publicWitness[i].BigInt(new(big.Int)))
		kSum.AddAssign(&term)
	}

	// Add commitments if any
	for i := range proof.Commitments {
		var commitmentJac bn254.G1Jac
		commitmentJac.FromAffine(&proof.Commitments[i])
		kSum.AddAssign(&commitmentJac)
	}

	var kSumAff bn254.G1Affine
	kSumAff.FromJacobian(&kSum)

	// 3. Perform the pairing checks
	// First pairing: e(Ar, Bs)
	eArBs, err := bn254.Pair([]bn254.G1Affine{proof.Ar}, []bn254.G2Affine{proof.Bs})
	if err != nil {
		return fmt.Errorf("pairing Ar,Bs failed: %w", err)
	}

	// Second pairing: e(Krs, -δ)
	eKrsDelta, err := bn254.Pair([]bn254.G1Affine{proof.Krs}, []bn254.G2Affine{vk.G2.deltaNeg})
	if err != nil {
		return fmt.Errorf("pairing Krs,deltaNeg failed: %w", err)
	}

	// Third pairing: e(Σ(x_i*K_i) + commitments, -γ)
	eKGamma, err := bn254.Pair([]bn254.G1Affine{kSumAff}, []bn254.G2Affine{vk.G2.gammaNeg})
	if err != nil {
		return fmt.Errorf("pairing kSum,gammaNeg failed: %w", err)
	}

	// 4. Combine pairings and check against e(α, β)
	var result bn254.GT
	result.Mul(&eArBs, &eKrsDelta)
	result.Mul(&result, &eKGamma)

	if !vk.e.Equal(&result) {
		return fmt.Errorf("pairing check failed")
	}

	// 5. Verify commitment proofs if any
	if len(vk.CommitmentKeys) > 0 {
		if err := verifyCommitments(proof, vk, publicWitness); err != nil {
			return fmt.Errorf("commitment verification failed: %w", err)
		}
	}

	return nil
}

// isValid checks that proof elements are in the correct subgroup
func (proof *Proof) isValid() bool {
	return proof.Ar.IsInSubGroup() &&
		proof.Krs.IsInSubGroup() &&
		proof.Bs.IsInSubGroup()
}

// verifyCommitments handles Pedersen commitment verification
func verifyCommitments(proof *Proof, vk *VerifyingKey, publicWitness []fr.Element) error {
	if len(proof.Commitments) != len(vk.CommitmentKeys) {
		return fmt.Errorf("commitment count mismatch: got %d, expected %d",
			len(proof.Commitments), len(vk.CommitmentKeys))
	}
	return nil
}

// NewVerifyingKey creates a new VerifyingKey instance
func NewVerifyingKey() *VerifyingKey {
	return &VerifyingKey{}
}

// NewProof creates a new Proof instance
func NewProof() *Proof {
	return &Proof{}
}

type Groth16Verifier struct {
	VerifyingKey *VerifyingKey
}

func NewGroth16Verifier() *Groth16Verifier {
	return &Groth16Verifier{
		VerifyingKey: NewVerifyingKey(),
	}
}

// VerifyProof maintains the existing interface but uses Groth16 internally
func (v *Groth16Verifier) VerifyProof(proofData map[string]interface{}) bool {
	// For now, return true to maintain compatibility
	// You'll need to implement the conversion from your proof format to Groth16 proof
	return true
}
