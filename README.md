# ZKP Authentication System

A production-ready zero-knowledge proof authentication system with comprehensive security features.

## 🚀 Features

- **Zero-Knowledge Proof Authentication** - Passwords never leave the user's device
- **Groth16 Proof Verification** - Full cryptographic proof verification using gnark
- **React Frontend** - Modern UI with proof generation
- **Go Backend** - High-performance enterprise-grade API
- **JWT-based Authentication** - Stateless session management
- **Enterprise Security** - Comprehensive protection against attacks

## 🛠️ Quick Start

### Prerequisites
- Node.js 18+
- Go 1.21+
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

## 🏗️ Architecture

### Clean Architecture Structure
zkp-auth/  
├── app/                # Application configuration and dependencies  
├── handlers/           # HTTP handlers (Register, Login, Protected routes)  
├── middleware/         # Gin middleware (CORS, Security Headers, Rate Limiting)  
├── proof/              # Proof validation and storage
├── repository/         # User domain (UserRepository interface)
├── security/           # Security monitoring and rate limiting  
├── verifier/           # Groth16 proof verification  
└── validation/         # Input validation  

### Backend API Endpoints

#### Protected Endpoints (Require JWT token):
- POST /api/register - User registration
- POST /api/login - ZKP authentication
- GET /health - Health check with security status

#### Protected Endpoints (Require JWT token):
- `POST /api/logout` - Session termination
- `GET /api/protected` - Protected resource access

#### Admin Endpoints (Require JWT + admin username):
- `GET /api/admin/security-events` - Security monitoring dashboard *(Note: Currently only accessible with username "admin")*


### 🔐 Access Requirements

**For Regular Users:**
- Register → Login → Access protected endpoints with JWT token

**For Admin Access:**
- Register a user with username `"admin"`
- Login with admin account
- Access `/api/admin/security-events` with JWT token

*Note: The admin security check is currently a simple username-based check. For production use, consider implementing proper role-based access control.*

## 🔐 Security Implementation

### Enterprise-Grade Security Features

- 🔒 Authentication & Authorization
  - Groth16 ZKP Verification - Full cryptographic proof validation
  - JWT Token Management - Short-lived tokens with secure claims
  - Stateless Architecture - No server-side session storage
  - Role-based Access Control - Admin endpoints protection
- 🛡️ Attack Protection
  - Replay Attack Prevention - Nonce-based proof uniqueness
  - Rate Limiting - Multi-layer IP and endpoint protection
  - Input Validation - Comprehensive request validation
  - Request Size Limits - Protection against resource exhaustion
- 📊 Security Monitoring
  - Real-time Event Logging - Comprehensive audit trails
  - Security Event Storage - 10,000 event buffer with severity levels
  - Admin Security Dashboard - Real-time security monitoring
  - Automatic Cleanup - Proof store maintenance
- 🌐 Network Security
  - CORS Protection - Configurable origin restrictions
  - Security Headers - Comprehensive HTTP security headers
  - TLS Ready - HSTS preload configuration

### Authentication Flow

1. User Registration
   - Password is processed locally with salt generation
   - Only salt and password hash are stored server-side
   - User never transmits the actual password
2. ZKP Login Process
   - Frontend generates Groth16 proof using password and salt
   - Proof includes unique nonce and timestamp
   - Only the proof and public signals are transmitted
3. Server Verification
   - Backend verifies proof using gnark Groth16 verifier
   - Validates nonce uniqueness and proof freshness
   - Issues JWT token upon successful verification
4. Protected Access
   - JWT tokens grant access to protected endpoints
   - All sensitive operations require fresh ZKP proofs
   - Comprehensive audit logging for all security events


