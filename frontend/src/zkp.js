import * as snarkjs from 'snarkjs';

export class ZKPClient {
    async generateProof(username, password, salt) {
        // In a real app, you'd get the stored hash from registration
        const passwordHash = this.computePasswordHash(password, salt);

        const inputs = {
            salt: salt,
            passwordHash: passwordHash,
            secretPassword: password
        };

        try {
            const { proof, publicSignals } = await snarkjs.groth16.fullProve(
                inputs,
                '/circuits/password.wasm',
                '/circuits/password.zkey'
            );

            return {
                proof: proof,
                publicSignals: publicSignals
            };
        } catch (error) {
            console.error('Proof generation failed:', error);
            throw error;
        }
    }

    computePasswordHash(password, salt) {
        // This must match the circuit computation: password * salt
        return password * salt;
    }
}
