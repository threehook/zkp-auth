package verifier

type ZKPVerifier struct {
	basicVerifier *Groth16Verifier // Now this will resolve correctly
}

func NewZKPVerifier() (*ZKPVerifier, error) {
	basicVerifier := NewGroth16Verifier() // This now exists

	return &ZKPVerifier{
		basicVerifier: basicVerifier,
	}, nil
}

func (v *ZKPVerifier) VerifyProof(proofData map[string]interface{}) bool {
	return v.basicVerifier.VerifyProof(proofData)
}
