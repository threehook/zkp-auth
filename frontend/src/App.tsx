import React, { useState } from 'react';
import * as snarkjs from 'snarkjs';
import './App.css';
import poseidon from 'poseidon-lite';

interface ProofData {
    proof: any;
    publicSignals: any[];
}

const generateZKProof = async (username: string, password: string, salt: string): Promise<ProofData> => {
    console.log('=== ZKP Proof Generation ===');

    // Use the same computation as backend
    const passwordInt = simpleHash(password);
    const saltInt = simpleHash(salt);

    // Simple hash that matches backend computePoseidonHash
    const expectedHash = (passwordInt * saltInt) + 12345;

    console.log('Inputs:', {
        password: passwordInt,
        salt: saltInt,
        expectedHash: expectedHash
    });

    const inputs = {
        salt: saltInt,
        storedHash: expectedHash,
        password: passwordInt
    };

    try {
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
          inputs,
          '/circuits/password.wasm',
          '/circuits/password.zkey'
        );

        console.log('Proof generated successfully!');
        return { proof, publicSignals };
    } catch (error) {
        console.error('Proof generation failed:', error);
        throw error;
    }
};

// Keep this for converting strings to numbers, but now we use bigint
const simpleHash = (str: string): number => {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash |= 0;
    }
    return hash;
};

// Add the missing React component
function App() {
    const [username, setUsername] = useState<string>('');
    const [password, setPassword] = useState<string>('');
    const [isLoggedIn, setIsLoggedIn] = useState<boolean>(false);
    const [userData, setUserData] = useState<string | null>(null);
    const [loading, setLoading] = useState<boolean>(false);
    const [message, setMessage] = useState<string>('');

    const handleRegister = async (): Promise<void> => {
        setLoading(true);
        setMessage('');
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
                setMessage(`Registration successful! Salt: ${data.salt}`);
            } else {
                const errorData = await response.json();
                setMessage(`Registration failed: ${errorData.error}`);
            }
        } catch (error) {
            setMessage(`Registration error: ${error.message}`);
        } finally {
            setLoading(false);
        }
    };

    const handleLogin = async (): Promise<void> => {
        setLoading(true);
        setMessage('');
        try {
            const salt = '12345';
            const proof = await generateZKProof(username, password, salt);

            const response = await fetch('http://localhost:8080/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: username,
                    proof: JSON.stringify(proof),
                }),
            });

            if (response.ok) {
                const data = await response.json();
                localStorage.setItem('token', data.token);
                setIsLoggedIn(true);
                setUserData(data.user);
                setMessage('Login successful with ZKP!');
            } else {
                const errorData = await response.json();
                setMessage(`Login failed: ${errorData.error}`);
            }
        } catch (error) {
            setMessage(`Login error: ${error.message}`);
        } finally {
            setLoading(false);
        }
    };

    const fetchProtectedData = async (): Promise<void> => {
        try {
            const token = localStorage.getItem('token');
            const response = await fetch('http://localhost:8080/api/protected', {
                headers: {
                    'Authorization': token || '',
                },
            });

            const data = await response.json();
            if (response.ok) {
                setMessage(`Protected data: ${JSON.stringify(data)}`);
            } else {
                setMessage(`Failed to fetch protected data: ${data.error}`);
            }
        } catch (error) {
            setMessage(`Error fetching protected data: ${error.message}`);
        }
    };

    const handleLogout = (): void => {
        localStorage.removeItem('token');
        setIsLoggedIn(false);
        setUserData(null);
        setMessage('Logged out successfully');
    };

    return (
      <div className="App">
          <header className="App-header">
              <h1>ZKP Authentication Demo</h1>

              {message && (
                <div className={`message ${message.includes('successful') ? 'success' : 'error'}`}>
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
