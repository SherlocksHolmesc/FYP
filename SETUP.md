# Web3 Risk Guard - Setup Guide

Complete setup instructions for running the landing page, backend API, and browser extension.

## Prerequisites

- Node.js 18+ and npm
- Python 3.8+
- Chrome browser
- Etherscan API key (free from https://etherscan.io/apis)

## Step-by-Step Setup

### 1. Backend API Setup

The backend API powers the ML model and integrates with GoPlus Security API.

```bash
# Navigate to backend folder
cd backend

# Install Python dependencies
pip install -r requirements.txt

# Create environment file
echo "ETHERSCAN_API_KEY=your_key_here" > .env

# Start the API server
python api.py
```

The API will start on `http://localhost:5000`

You should see:
```
[OK] Model loaded with 17 features
[SERVER] Starting Web3 Risk Guard API on http://localhost:5000
```

### 2. Landing Page Setup

The landing page provides a user interface for checking addresses and websites.

```bash
# Navigate to web folder
cd web

# Install dependencies
npm install

# Start development server
npm run dev
```

The landing page will open at `http://localhost:5173`

Features:
- 3D animated hero section
- Address scanner
- Website checker
- Real-time risk analysis

### 3. Browser Extension Setup

The extension monitors wallet transactions in real-time.

1. Open Chrome and navigate to `chrome://extensions`

2. Enable "Developer mode" (toggle in top right)

3. Click "Load unpacked"

4. Select the project root folder (where `manifest.json` is located)

5. The extension should now appear in your extensions list

6. Pin it to your toolbar for easy access

### 4. Testing the Extension

1. Visit any dApp website (e.g., Uniswap, OpenSea)

2. Connect your wallet

3. Initiate a transaction or approval

4. Click the extension icon to see risk analysis

## Features Overview

### Landing Page (`http://localhost:5173`)

- **Hero Section**: 3D animated sphere with project info
- **Features**: Overview of security capabilities
- **Address Checker**: Enter any Ethereum address to check risk
- **Website Checker**: Verify if a dApp is safe

### Extension Popup

When you click the extension icon, you'll see:

- **Risk Score**: 0-100 score with color-coded severity
- **Risk Level**: LOW, MEDIUM, HIGH, or CRITICAL
- **Detection Breakdown**: Shows scores from ML, Blacklist, and Heuristic engines
- **Risk Indicators**: Specific flags like "Unlimited approval", "Honeypot detected", etc.

### API Endpoints

Test the API directly:

```bash
# Check an address
curl http://localhost:5000/score/0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb

# Check a website
curl "http://localhost:5000/site?url=https://uniswap.org"

# Health check
curl http://localhost:5000/health
```

## Architecture

```
User Browser
    ↓
┌─────────────────┐
│  Extension      │ ← Monitors wallet transactions
│  (popup.html)   │
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│  Background.js  │ ← Hybrid scoring engine
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│  Backend API    │ ← ML model + GoPlus integration
│  (Flask)        │
└────────┬────────┘
         │
         ├──→ ML Model (trained on fraud data)
         ├──→ GoPlus Security API
         └──→ Blacklist (3,580 addresses)
```

## Troubleshooting

### Backend API Issues

**Problem**: `ModuleNotFoundError`
```bash
pip install -r backend/requirements.txt
```

**Problem**: Model not loading
```bash
# Make sure these files exist:
ls ml/model_v2.pkl
ls ml/scaler_v2.pkl
ls ml/features_v2.json
```

**Problem**: Etherscan rate limit
- Get a free API key from https://etherscan.io/apis
- Add it to `backend/.env`

### Landing Page Issues

**Problem**: Cannot connect to API
- Make sure backend is running on port 5000
- Check browser console for CORS errors

**Problem**: 3D animation not working
- Try refreshing the page
- Check if WebGL is enabled in your browser

### Extension Issues

**Problem**: Extension not detecting transactions
- Make sure you've loaded the extension in Chrome
- Check that background.js is running (in chrome://extensions)
- Open console in the extension popup for errors

**Problem**: No risk data showing
- Backend API must be running
- Check Network tab in browser DevTools

## Development

### Backend Development
```bash
cd backend
python api.py  # Edit and restart to see changes
```

### Landing Page Development
```bash
cd web
npm run dev  # Hot reload enabled
```

### Extension Development
- Edit files
- Go to `chrome://extensions`
- Click the refresh icon on your extension

## Production Build

### Landing Page
```bash
cd web
npm run build
# Outputs to web/dist/
```

### Extension
The extension files are production-ready in the root folder.

## Next Steps

1. Try scanning some addresses:
   - Safe: `0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb` (Binance)
   - Risky: Use addresses from `data/darklist.json`

2. Test with real dApps:
   - Visit Uniswap and attempt a swap
   - Visit OpenSea and approve an NFT

3. Customize the extension:
   - Edit `popup.html` for UI changes
   - Modify `background.js` for detection logic
   - Update weights in `WEIGHTS` object

## Support

For issues or questions, check:
- GitHub issues
- Project documentation
- Backend API logs

## Security Note

This is a Final Year Project for educational purposes. While the detection is accurate, always:
- Verify transactions before approving
- Use hardware wallets for large amounts
- Research projects before investing
- Never share private keys
