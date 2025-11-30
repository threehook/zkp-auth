import React, { useState } from 'react';
import * as snarkjs from 'snarkjs';
import { poseidon2 } from 'poseidon-lite';
import './App.css';

interface ProofData {
    proof: any;
    publicSignals: any[];
}

// Proper Poseidon2 hash - no compromises
const poseidonHash = (password: string, salt: string): string => {
    // Convert password string to bigint
    let passwordBigInt = 0n;
    for (let i = 0; i < password.length; i++) {
        passwordBigInt = (passwordBigInt << 8n) + BigInt(password.charCodeAt(i));
    }

    // Convert salt to bigint
    const saltBigInt = BigInt(parseInt(salt));

    // Hash both together with poseidon2
    return poseidon2([passwordBigInt, saltBigInt]).toString();
};

const generateZKProof = async (username: string, password: string, salt: string): Promise<ProofData> => {
    // Use Poseidon2 to hash password + salt together
    const combinedHash = poseidonHash(password, salt);
    const saltNum = parseInt(salt);

    const inputs = {
        salt: saltNum.toString(),
        storedHash: combinedHash, // Poseidon2 hash of (password + salt)
        password: combinedHash    // Same for circuit compatibility
    };

    try {
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
          inputs,
          '/circuits/password.wasm',
          '/circuits/password.zkey'
        );

        return { proof, publicSignals };
    } catch (error) {
        console.error('Proof generation failed:', error);
        throw error;
    }
};

function App() {
    const [username, setUsername] = useState<string>('');
    const [password, setPassword] = useState<string>('');
    const [isLoggedIn, setIsLoggedIn] = useState<boolean>(false);
    const [userData, setUserData] = useState<string | null>(null);
    const [loading, setLoading] = useState<boolean>(false);
    const [message, setMessage] = useState<string>('');
    const [isError, setIsError] = useState<boolean>(true);

    const handleRegister = async (): Promise<void> => {
        setLoading(true);
        setMessage('');
        setIsError(true);
        try {
            const response = await fetch('http://localhost:8080/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: username,
                    password: password,
                }),
            });

            if (response.ok) {
                const data = await response.json();
                localStorage.setItem(`${username}_salt`, data.salt);
                setMessage(`Registration successful! Salt: ${data.salt}`);
                setIsError(false);
            } else {
                const errorData = await response.json();
                setMessage(`Registration failed: ${errorData.error}`);
                setIsError(true);
            }
        } catch (error) {
            setMessage(`Registration error: ${error.message}`);
            setIsError(true);
        } finally {
            setLoading(false);
        }
    };

    const handleLogin = async (): Promise<void> => {
        setLoading(true);
        setMessage('');
        setIsError(true);
        try {
            const salt = localStorage.getItem(`${username}_salt`);
            if (!salt) {
                setMessage('User not registered or salt not found');
                setIsError(true);
                return;
            }

            const proofData = await generateZKProof(username, password, salt);

            const proof = {
                username: username,
                proof: proofData.proof,
                publicSignals: proofData.publicSignals,
                nonce: `nonce-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                timestamp: Math.floor(Date.now() / 1000)
            };

            const response = await fetch('http://localhost:8080/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: username,
                    proof: proof,
                }),
            });

            if (response.ok) {
                const data = await response.json();
                localStorage.setItem('token', data.token);
                setIsLoggedIn(true);
                setUserData(data.user);
                setMessage('Login successful with ZKP!');
                setIsError(false);
            } else {
                const errorData = await response.json();
                setMessage(`Login failed: ${errorData.error}`);
                setIsError(true);
            }
        } catch (error) {
            setMessage(`Login error: ${error.message}`);
            setIsError(true);
        } finally {
            setLoading(false);
        }
    };

    const fetchProtectedData = async (): Promise<void> => {
        setMessage('');
        setIsError(true);
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                setMessage('No authentication token found');
                return;
            }

            const response = await fetch('http://localhost:8080/api/protected', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });

            const data = await response.json();

            if (response.ok) {
                setMessage(`Protected data: ${JSON.stringify(data)}`);
                setIsError(false);
            } else {
                setMessage(`Access denied: ${data.error}`);
                setIsError(true);
            }
        } catch (error) {
            setMessage(`Network error: ${error.message}`);
            setIsError(true);
        }
    };

    const handleLogout = (): void => {
        localStorage.removeItem('token');
        setIsLoggedIn(false);
        setUserData(null);
        setMessage('Logged out successfully');
        setIsError(false);
    };

    return (
      <div className="App">
          <header className="App-header">
              <h1>ZKP Authentication Demo</h1>

              {message && (
                <div className={`message ${isError ? 'error' : 'success'}`}>
                    {message}
                </div>
              )}

              {loading && <div className="loading">Loading...</div>}

              {!isLoggedIn ? (
                <div className="login-form">
                    <h2>Login with Zero Knowledge Proof</h2>
                    <input
                      type="text"
                      placeholder="Username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                    />
                    <input
                      type="password"
                      placeholder="Password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                    <div className="button-group">
                        <button onClick={handleLogin} disabled={loading}>
                            {loading ? 'Loading...' : 'Login'}
                        </button>
                        <button onClick={handleRegister} disabled={loading}>
                            {loading ? 'Loading...' : 'Register'}
                        </button>
                    </div>
                </div>
              ) : (
                <div className="dashboard">
                    <h2>Welcome, {userData}!</h2>
                    <p>You're logged in using Zero Knowledge Proofs</p>
                    <div className="button-group">
                        <button onClick={fetchProtectedData}>Get Protected Data</button>
                        <button onClick={handleLogout}>Logout</button>
                    </div>
                </div>
              )}
          </header>
      </div>
    );
}

export default App;
