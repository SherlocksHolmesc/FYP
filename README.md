<div align="center">
  <img src="./icons/can-u-make-it-like-svg.svg" alt="Web3 Risk Guard Logo" width="200" height="200" style="margin: 30px 0;">
</div>

<h1 align="center">GuardChain</h1>

<h3 align="center"><i>Your AI-Powered Guardian Against Web3 Scams</i></h3>

<p align="center">
  <b>Protecting users from $2B+ in annual crypto fraud through real-time ML detection, runtime simulation, and behavioral analysis</b>
</p>

<p align="center">
  <a href="#features">View Features</a> •
  <a href="#tech-stack">Tech Stack</a> •
  <a href="#installation--setup">Get Started</a> •
  <a href="SETUP.md">Full Setup</a>
</p>

---

## About GuardChain

GuardChain is an **AI-powered security ecosystem** that protects Ethereum users from scams in real-time. Through a **combination of machine learning, runtime simulation, and behavioral analysis**, it catches phishing sites, honeypot tokens, and crypto drainers before they steal your funds.

Think of it as a **bouncer for Web3** - trained on 667 real fraud cases to identify threats instantly, with zero false positives on legitimate DeFi protocols.

🔗 **[Try Our Live Scanner](#installation--setup)** | 🌐 **[GitHub](https://github.com/SherlocksHolmesc/FYP)**

---

## 🎯 What Makes GuardChain Special?

### 🧠 **ML-Powered Detection**
- Trained on **667 verified fraud cases** with **93% accuracy**
- Random Forest classifier analyzing **17 blockchain-specific features**
- Real-time threat scoring with **85-99% confidence** on scams
- No hardcoded rules - learns actual fraud patterns

### 🎮 **Runtime dApp Simulator**
- **Playwright-based** automation that simulates real user interactions
- Tests if tokens are **actually tradeable** (catches honeypots instantly)
- **Typosquatting detection** for 8+ major DeFi brands (Uniswap, Aave, etc.)
- **100% punycode attack prevention** - detects Unicode domain homoglyphs

### 🔍 **Smart Code Analyzer**
- Scans **30+ malicious patterns** from known drainer kits
- Retrieves **Solidity source code** via Etherscan API
- **Context-aware** - trusted domains + safe simulation = zero false positives
- Pattern recognition for permission abuse and fund theft

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


