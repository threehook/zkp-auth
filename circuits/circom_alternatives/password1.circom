pragma circom 2.0.0;

template PasswordProof() {
    signal input salt;
    signal input passwordHash;
    signal input secretPassword;

    // Simulate password verification - simple multiplication
    // In production, you'd use a proper hash function from circomlib
    signal computedHash;
    computedHash <== secretPassword * salt;

    // Constraint: computedHash must equal passwordHash for valid proof
    computedHash === passwordHash;

    // Output 1 if constraint passes (circuit will only generate proof if this constraint holds)
    signal output verified <== 1;
}

component main = PasswordProof();
