import React, { useState } from 'react';
import * as snarkjs from 'snarkjs';
import './App.css';

function App() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [isLoggedIn, setIsLoggedIn] = useState(false);
    const [userData, setUserData] = useState(null);
    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState('');

    const handleRegister = async () => {
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

    const handleLogin = async () => {
        setLoading(true);
        setMessage('');
        try {
            // For demo, use the hardcoded salt - in real app, get from registration
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

    const generateZKProof = async (username, password, salt) => {
        console.log('=== ZKP Proof Generation ===');

        // Use the EXACT same computation as Go backend
        const passwordInt = simpleHash(password);
        const saltInt = saltToInt(salt);
        const passwordHash = passwordInt * saltInt;

        console.log('Inputs:', { username, password, passwordInt, salt, saltInt, passwordHash });

        const inputs = {
            salt: saltInt,
            passwordHash: passwordHash,
            secretPassword: passwordInt
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

    // Helper functions that must match Go backend
    const simpleHash = (password) => {
        let hash = 0;
        for (let i = 0; i < password.length; i++) {
            hash = ((hash << 5) - hash) + password.charCodeAt(i);
            hash |= 0;
        }
        return hash;
    };

    const saltToInt = (salt) => {
        let result = 0;
        for (let i = 0; i < salt.length; i++) {
            result = result * 10 + (salt.charCodeAt(i) - '0'.charCodeAt(0));
        }
        return result;
    };

    const fetchProtectedData = async () => {
        try {
            const token = localStorage.getItem('token');
            const response = await fetch('http://localhost:8080/api/protected', {
                headers: {
                    'Authorization': token,
                },
            });

            if (response.ok) {
                const data = await response.json();
                alert(`Protected data: ${data.message}`);
            } else {
                alert('Failed to fetch protected data');
            }
        } catch (error) {
            console.error('Error fetching protected data:', error);
        }
    };

    const handleLogout = () => {
        localStorage.removeItem('token');
        setIsLoggedIn(false);
        setUserData(null);
    };

    return (
        <div className="App">
            <header className="App-header">
                <h1>ZKP Authentication Demo</h1>

                {/* Add feedback messages here */}
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
                        <p className="info">
                            Your password never leaves your device. Only a zero-knowledge proof is sent to the server.
                        </p>
                    </div>
                ) : (
                    <div className="dashboard">
                        <h2>Welcome, {userData}!</h2>
                        <p>You're logged in using Zero Knowledge Proofs</p>
                        <div className="button-group">
                            <button onClick={fetchProtectedData}>Get Protected Data</button>
                            <button onClick={handleLogout}>Logout</button>
                        </div>

                        {/* Show message in dashboard too */}
                        {message && (
                            <div className="message success">
                                {message}
                            </div>
                        )}
                    </div>
                )}
            </header>
        </div>
    );
}

export default App;
