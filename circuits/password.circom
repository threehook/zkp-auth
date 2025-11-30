template SecurePassword() {
    signal input salt;
    signal input storedHash;
    signal input password;

    signal output verified;

    // Use the same simple transform as frontend/backend
    signal computedHash;
    computedHash <== password * salt + 12345;

    // The proof is only valid if computed hash matches stored hash
    computedHash === storedHash;

    // Output 1 when constraint is satisfied
    verified <== 1;
}

component main = SecurePassword();
