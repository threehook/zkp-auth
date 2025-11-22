pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

template SimplePassword() {
    signal input salt;
    signal input storedHash;
    signal input password;

    signal output verified;

    // Simple hash: we'll use a combination of multiplication and addition
    // In production, use a proper hash function like Poseidon from circomlib
    signal computedHash;
    computedHash <== password * salt + 12345; // Simple transformation

    // Check if computed hash matches stored hash
    signal isEqual;
    component eq = IsEqual();
    eq.in[0] <== computedHash;
    eq.in[1] <== storedHash;

    verified <== eq.out;
}

component main = SimplePassword();
