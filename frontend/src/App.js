// frontend/src/App.js
import React, { useState } from 'react';
import axios from 'axios';
import { BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import './App.css';

function App() {
  const [code, setCode] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (!code.trim()) {
      setError('Please paste some Solidity code.');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await axios.post('http://localhost:3001/api/scan', { code });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to scan contract.');
    } finally {
      setLoading(false);
    }
  };

  const severityColors = {
    Critical: '#ef4444',
    High: '#f59e0b',
    Medium: '#3b82f6',
    Low: '#10b981',
  };

  const severityData = result?.severity_counts
    ? Object.entries(result.severity_counts)
        .filter(([_, count]) => count > 0)
        .map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="App">
      <header className="app-header">
        <h1>🛡️ VulnGuard AI</h1>
        <p>AI-Powered Smart Contract Security Scanner</p>
      </header>

      <main className="app-main">
        <section className="input-section">
          <h2>Paste your Solidity contract</h2>
          <textarea
            className="code-input"
            rows="12"
            placeholder="pragma solidity ^0.8.0; contract MyContract { ... }"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
          <button className="scan-button" onClick={handleScan} disabled={loading}>
            {loading ? 'Scanning...' : '🔍 Scan Contract'}
          </button>
          {error && <div className="error-message">{error}</div>}
        </section>

        {result && (
          <section className="results-section">
            <h2>Scan Results</h2>

            <div className="stats-grid">
              <div className="stat-card">
                <span className="stat-label">Risk Score</span>
                <span className={`stat-value ${result.risk_score > 60 ? 'high-risk' : result.risk_score > 30 ? 'medium-risk' : 'low-risk'}`}>
                  {result.risk_score}%
                </span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Vulnerabilities Found</span>
                <span className="stat-value">{result.rule_count}</span>
              </div>
            </div>

            {severityData.length > 0 && (
              <div className="chart-container">
                <h3>Vulnerability Severity</h3>
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={severityColors[entry.name] || '#8884d8'} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            )}

            <div className="vulnerabilities-list">
              <h3>Detected Vulnerabilities</h3>
              {result.rule_vulnerabilities.length > 0 ? (
                <ul>
                  {result.rule_vulnerabilities.map((vuln, idx) => (
                    <li key={idx} className="vuln-item">
                      <span className="vuln-type">⚠️ {vuln.type}</span>
                      <span className="vuln-line">Line {vuln.line}</span>
                      <p className="vuln-description">{vuln.description}</p>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="success-message">✅ No vulnerabilities found!</p>
              )}
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;