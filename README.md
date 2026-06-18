🛡️ VulnGuard AI

A smart contract security scanner I built to learn Web3 security and full-stack development.

---
 What it does

Paste any Solidity contract → get a risk score + list of vulnerabilities.

✅ Working now:
- Detects 7 vulnerability patterns
- Severity breakdown (Critical → Low)
- Clean dark UI dashboard

**🚧 Work in progress:**
- ML model (placeholder for now)
- Live mempool monitoring (code ready, not integrated yet)

---

## Tech stack

| Layer | What I used |
|-------|-------------|
| Frontend | React + Recharts |
| Backend | Node.js + Express |
| Scanner | Python + regex |
| Blockchain | viem |

---

## Quick start

```bash
git clone https://github.com/Khushuuu009/vulnguard-ai.git
cd vulnguard-ai

# Backend
cd backend
npm install
npm start

# Frontend (new terminal)
cd frontend
npm install
npm start
