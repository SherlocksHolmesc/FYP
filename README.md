# 🛡️ GuardChain

### *Your AI-Powered Guardian Against Web3 Scams*

> **Protecting users from $2B+ in annual crypto fraud through real-time ML detection, runtime simulation, and behavioral analysis**

[![Ethereum](https://img.shields.io/badge/Ethereum-3C3C3D?style=for-the-badge&logo=ethereum&logoColor=white)](https://ethereum.org/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org/)
[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://reactjs.org/)
[![ML](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)

---

## 🎯 The Problem

Every day, thousands of crypto users lose millions to:
- **🎣 Phishing sites** - Typosquatting attacks mimicking Uniswap, MetaMask, OpenSea
- **🍯 Honeypot tokens** - Contracts you can buy but never sell
- **💸 Crypto drainers** - Malicious dApps stealing wallet funds through unlimited approvals
- **🎭 IDN homograph attacks** - Unicode domains that look identical to legitimate sites

> **Our mission**: Make Web3 safe for everyone, from beginners to DeFi veterans.

---

## 💡 Our Solution

**Web3 Risk Guard** is a **multi-layered security ecosystem** that analyzes threats from three angles:

### 🧠 1. Machine Learning Engine
- Trained on **667 verified fraud cases** using Random Forest classifier
- **93% accuracy** on legitimate contracts, **85-99% confidence** on scams
- Real-time behavioral analysis with **17 advanced features** (gas patterns, holder distribution, liquidity metrics)

### 🎮 2. Runtime dApp Simulator
- **Playwright-based** browser automation simulating real user interactions
- Detects honeypots by attempting **actual buy/sell transactions** on-chain (Ganache fork)
- **Typosquatting detection** using Levenshtein distance fuzzy matching for 8+ major DeFi brands
- **100% punycode attack detection** (xn-- domains decoded)

### 🔍 3. Source Code Analyzer
- Scans **30+ malicious patterns** from known drainer kits (Inferno, Pink, Angel/Venom)
- Smart contract analysis via **Etherscan API** for verified Solidity code
- **Context-aware filtering** - trusted domains + safe simulation = ZERO false positives

---

## ✨ Features

### 🌐 Browser Extension (Chrome)
- **Real-time wallet transaction monitoring** via `window.ethereum` interception
- Popup showing **hybrid risk score** (35% ML + 30% darklist + 35% heuristics)
- Instant alerts for **3,580+ known malicious addresses** from curated darklist
- Animated UI inspired by Uniswap's design system

### 🖥️ Web Scanner (React)
- Public scanner at `localhost:5173` for analyzing any token/website
- **dApp behavior simulation** with visual threat breakdown
- Smart contract source code viewer with syntax highlighting
- **Three.js animated background** with responsive design

### ⚡ Flask API Backend
- **9 REST endpoints** for ML inference, GoPlus integration, Etherscan data
- Browser-based analysis with **Playwright** for anti-scraping sites
- Feature engineering pipeline computing **30 website features** and **17 token features**
- Response caching for 5-minute TTL optimization

---

## 🏗️ Tech Stack

### Frontend
- **React 19** + **Vite 7** - Lightning-fast dev experience
- **Three.js** + **Framer Motion** - Stunning 3D animations
- **React Router** - SPA navigation
- **Axios** - API communication

### Backend
- **Flask 3.0** - RESTful API server
- **scikit-learn 1.4** - ML model training/inference
- **Web3.py** - Ethereum blockchain interaction
- **Playwright** - Headless browser automation
- **BeautifulSoup4** - HTML parsing

### Browser Extension
- **Manifest V3** - Latest Chrome extension standards
- **Vanilla JavaScript** - Zero dependencies for performance
- **Chrome Extensions API** - `chrome.runtime`, `chrome.storage`

### Machine Learning
- **Random Forest Classifier** - Ensemble learning
- **StandardScaler** - Feature normalization
- **667 labeled fraud cases** - Real-world training data
- **30 engineered features** - Domain patterns, ML predictions, code analysis

### Blockchain
- **Ganache** - Local Ethereum testnet for honeypot simulation
- **GoPlus Security API** - Real-time threat intelligence
- **Etherscan API** - Smart contract source code retrieval

---

## 🚀 How We Built It

### 1. **Data Collection Pipeline**
Aggregated fraud cases from:
- GoPlus Security API flagged contracts
- Community-reported scam addresses
- Known drainer wallet addresses
- Manual verification of 667 confirmed malicious contracts

### 2. **Feature Engineering**
Designed **17 blockchain-specific features**:
- Transaction patterns (frequency, timing, gas usage)
- Holder distribution (concentration ratios, whale presence)
- Liquidity metrics (DEX liquidity, pool depth)
- Contract code patterns (approval mechanisms, transfer restrictions)

### 3. **Context-Aware Architecture**
Revolutionary approach to eliminate false positives:
```python
if trusted_domain AND safe_simulation_score >= 85%:
    skip_code_analysis()  # Don't flag Uniswap's permit() as malicious!
```

### 4. **Hybrid Scoring System**
```
Final Score = (35% ML Model) + (30% Darklist) + (35% Heuristics)
```
- ML catches novel patterns
- Darklist blocks known scammers
- Heuristics detect unlimited approvals, honeypots


## 🛠️ Installation & Setup

### Prerequisites
```bash
Python 3.8+
Node.js 16+
Google Chrome
```

### Quick Start
```bash
# Clone repository
git clone https://github.com/SherlocksHolmesc/FYP.git

# One-command startup (Windows)
./start.bat
./start_ganache.bat

# Load extension
1. Open chrome://extensions
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the /extension folder
```

**Full setup guide**: See [SETUP.md](SETUP.md)

---


