# ZKP Authentication System

A zero-knowledge proof authentication system with React frontend and Go backend.

## 🚀 Features

- **Zero-Knowledge Proof Authentication** - Passwords never leave the user's device
- **React Frontend** - Modern UI with proof generation
- **Go Backend** - High-performance proof verification
- **JWT-based Sessions** - Secure token management

## 🛠️ Quick Start

### Prerequisites
- Node.js 16+
- Go 1.19+
- Circom 2.0+

### 1. Generate Circuit Keys

The script `circuits/scripts/generate_keys.sh` generates the following:
- build/password.wasm (for frontend proof generation)
- build/password.zkey (for frontend proof generation)
- build/verification_key.json (for backend verification)

```bash
cd circuits
npm install
./scripts/generate_keys.sh

mv build/password.wasm build/password.zkey ../frontend/public/circuits
mv build/verification_key.json ../backend/circuits
``` 

### 2. Start Backend
```bash 
cd backend
go mod tidy
go run main.go
```

### 3. Start Frontend
```bash
cd frontend
npm install
npm run dev
```

## 🔐 How It Works

### Authentication Flow
1. **User Registration**
    - Password is hashed locally using a simple transformation
    - Salt and password hash are stored on the server
    - User never transmits the actual password

2. **User Login**
    - User enters password in the frontend
    - Frontend generates a zero-knowledge proof using the circuit
    - Only the proof is sent to the server - password stays on device

3. **Server Verification**
    - Backend verifies the ZKP using the verification key
    - If proof is valid, issues a JWT session token
    - Server never sees or stores the actual password

4. **Session Management**
    - JWT tokens are used for authenticated requests
    - Protected endpoints verify JWT validity
    - Sessions expire after configured time

### Technical Implementation
- **Circuit**: `secretPassword * salt === passwordHash`
- **Proof System**: Groth16 zk-SNARK
- **Frontend**: React with SnarkJS for proof generation
- **Backend**: Go with Gin framework for API routes
- **Authentication**: JWT tokens for session management

## 🚧 Important Notes

### ⚠️ Security Considerations

**This is a demonstration implementation and should NOT be used in production without significant security improvements.**

#### Current Limitations:
- 🔴 **Simple Hash Function**: Uses basic multiplication instead of proper cryptographic hash functions
- 🔴 **Single-Party Trusted Setup**: Trusted setup performed by a single party instead of secure multi-party ceremony
- 🔴 **Basic Proof Verification**: Implements only basic proof structure validation, not full cryptographic verification
- 🔴 **No Production Hardening**: Missing essential security features like rate limiting, input validation, and attack protection
- 🔴 **Hardcoded Secrets**: Uses hardcoded JWT secrets and demo credentials

#### Required Improvements for Production:
- ✅ **Use ZK-Friendly Hash Functions**: Implement Poseidon or MiMC hash from circomlib
- ✅ **Secure Trusted Setup**: Conduct multi-party ceremony with independent participants
- ✅ **Proper Proof Verification**: Integrate with Go ZKP libraries (gnark) for full cryptographic verification
- ✅ **Security Hardening**: Add rate limiting, input sanitization, and comprehensive error handling
- ✅ **Key Management**: Use hardware security modules or secure enclaves for key storage
- ✅ **Security Audit**: Conduct thorough security review by cryptography experts

#### Recommended Next Steps:
1. Replace simple multiplication with Poseidon hash function
2. Implement proper multi-party trusted setup ceremony
3. Add comprehensive input validation and sanitization
4. Implement rate limiting and brute force protection
5. Use environment variables for all secrets and configuration
6. Add comprehensive logging and monitoring
7. Conduct third-party security audit

### 🎯 Educational Purpose
This project serves as an educational demonstration of zero-knowledge proof concepts and should be used for learning purposes only. The implementation showcases the fundamental principles of ZKP-based authentication but requires significant security improvements before being deployed in any production environment.
