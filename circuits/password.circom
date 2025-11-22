// circuits/password.circom
pragma circom 2.0.0;

template PasswordProof() {
    signal input salt;
    signal input passwordHash;
    signal input secretPassword;

    signal output verified;

    // Simple hash simulation
    signal computedHash;
    computedHash <== secretPassword * salt;

    // Check if computedHash equals passwordHash
    // If they are equal, the proof is valid
    computedHash === passwordHash;

    // Output 1 to indicate success (only reaches here if constraint passes)
    verified <== 1;
}

component main = PasswordProof();
