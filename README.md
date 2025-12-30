# Web3 Risk Guard

AI-powered security extension for Ethereum that protects users from scams, phishing, and malicious contracts.

## Project Structure

```
.
├── web/                    # Landing page (React + Vite)
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── App.jsx
│   │   └── main.jsx
│   └── package.json
│
├── backend/                # Flask API server
│   ├── api.py             # Main API with ML model
│   └── requirements.txt
│
├── ml/                     # Machine Learning models
│   ├── train_real_model.py
│   ├── model_v2.pkl       # Trained model
│   └── data/              # Training datasets
│
├── manifest.json          # Extension manifest
├── popup.html             # Extension popup (redesigned)
├── popup.js
├── background.js          # Main detection logic
├── content.js
└── inpage.js
```

## Features

### Landing Page
- Modern Uniswap-inspired design
- 3D animated hero section
- Interactive scanner for addresses and websites
- Real-time risk analysis

### Browser Extension
- Real-time wallet transaction monitoring
- Hybrid scoring system (ML + GoPlus + Blacklist)
- Detection of unlimited approvals, honeypots, phishing
- Beautiful, user-friendly popup interface

### Backend API
- ML model trained on 667+ verified fraud cases
- GoPlus Security API integration
- Website verification and dApp audit checking
- Multi-layer detection system

## Setup

### 1. Backend API

```bash
cd backend
pip install -r requirements.txt

# Add your Etherscan API key to .env
echo "ETHERSCAN_API_KEY=your_key_here" > .env

# Start the API
python api.py
```

### 2. Landing Page

```bash
cd web
npm install
npm run dev
```

### 3. Browser Extension

1. Open Chrome and go to `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select this project folder

## Usage

### Landing Page
Visit `http://localhost:5173` to access the landing page where you can:
- Check Ethereum addresses for fraud
- Verify if websites are safe to connect your wallet
- View real-time risk scores and analysis

### Extension
1. Browse any dApp website
2. When you interact with your wallet, the extension automatically analyzes the transaction
3. Click the extension icon to see detailed risk analysis

## API Endpoints

- `GET /score/<address>` - Get risk score for Ethereum address
- `GET /site?url=<url>` - Check if website/dApp is safe
- `GET /goplus/<address>` - Raw GoPlus security data
- `GET /health` - API health check

## Scoring System

The hybrid scoring system combines:
- **35% Heuristic**: Rule-based detection (approvals, permits, NFT setApprovalForAll)
- **30% Darklist**: 3,580+ known malicious addresses
- **35% ML Model**: Trained on real-world fraud cases with 95% accuracy

## Technologies

- **Frontend**: React, Vite, Three.js, Framer Motion
- **Backend**: Flask, scikit-learn, GoPlus API
- **Extension**: Chrome Extensions API, Manifest V3
- **ML**: Random Forest, trained on 667 GoPlus-verified addresses

## Final Year Project 2024

This project demonstrates:
- Real-world application of machine learning
- Full-stack web development
- Browser extension development
- API integration and security best practices
