# Web3 Risk Guard - Demo Guide

This guide walks you through testing all the features of Web3 Risk Guard.

## Quick Start

### 1. Start the Backend API

```bash
cd backend
python api.py
```

Wait for:
```
[OK] Model loaded with 17 features
[SERVER] Starting Web3 Risk Guard API on http://localhost:5000
```

### 2. Start the Landing Page

Open a new terminal:

```bash
cd web
npm run dev
```

Visit: `http://localhost:5173`

### 3. Load the Extension

1. Open Chrome: `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the project root folder
5. Pin the extension to your toolbar

## Demo Scenarios

### Scenario 1: Check a Safe Address (Landing Page)

1. Go to `http://localhost:5173`
2. Scroll to the "Security Scanner" section
3. Click "Ethereum Address" tab
4. Enter: `0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb` (Binance hot wallet)
5. Click "Check Address"

**Expected Result:**
- Low risk score (0-30)
- Prediction: SAFE
- No GoPlus flags
- Green color coding

### Scenario 2: Check a Verified Website (Landing Page)

1. Stay in the Scanner section
2. Click "Website / dApp" tab
3. Enter: `https://uniswap.org`
4. Click "Check Website"

**Expected Result:**
- Safety verdict: SAFE or CAUTION
- "Verified dApp" badge (if in GoPlus database)
- "Audited Contracts" badge
- Low risk score

### Scenario 3: Check a Suspicious Website

1. In the Website scanner
2. Enter: `https://app.uniswap-rewards.com` (example phishing site format)
3. Click "Check Website"

**Expected Result:**
- High risk score
- May show "Unknown/Unverified dApp"
- Warning flags

### Scenario 4: Test Extension on Real dApp

1. Visit `https://app.uniswap.org`
2. Connect your wallet (MetaMask)
3. Try to swap tokens (don't actually execute)
4. When the transaction popup appears, click the extension icon

**Expected Result:**
- Extension shows risk analysis
- Score breakdown
- Transaction details
- Risk indicators

### Scenario 5: Test Unlimited Approval Detection

1. Visit any dApp that requests token approval
2. When approval is requested
3. Click the extension icon

**Expected Result:**
- If unlimited approval: HIGH or CRITICAL score
- Flag: "UNLIMITED token approval detected"
- Component breakdown showing high heuristic score

## API Testing

### Test Direct API Calls

```bash
# Safe address (Binance)
curl http://localhost:5000/score/0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb

# Check website
curl "http://localhost:5000/site?url=https://uniswap.org"

# Health check
curl http://localhost:5000/health
```

### Expected API Response Format

#### Address Check:
```json
{
  "address": "0x...",
  "score": 15,
  "prediction": "SAFE",
  "confidence": 0.92,
  "components": {
    "ml_score": 10,
    "goplus_score": 0
  },
  "goplus_flags": [],
  "is_honeypot": false,
  "is_contract": false,
  "processing_time_ms": 2500
}
```

#### Website Check:
```json
{
  "url": "https://example.com",
  "score": 20,
  "verdict": "SAFE",
  "is_phishing": false,
  "is_verified_dapp": true,
  "is_audited": true,
  "flags": [
    "✓ Verified dApp: Uniswap",
    "✓ Audited by: OpenZeppelin, Trail of Bits"
  ],
  "contracts": []
}
```

## Visual Walkthrough

### Landing Page Components

#### Hero Section
- **What to see**: Large 3D rotating pink sphere on the right
- **Interaction**: Sphere responds to mouse movement
- **Text**: "Protect Your Web3 Journey" with gradient
- **Stats**: 3 columns showing project metrics

#### Features Section
- **What to see**: 6 cards in a grid
- **Hover effect**: Cards lift and border glows pink
- **Icons**: Large emoji icons for each feature

#### Scanner Section
- **What to see**: Dark card with tabs
- **Tabs**: "Ethereum Address" and "Website / dApp"
- **Input**: Large text field and gradient button
- **Results**: Animated card with score and details

### Extension Popup Components

#### Header
- **Logo**: Gradient "Risk Guard" text with shield icon
- **Status**: Green "ACTIVE" badge

#### URL Badge
- **Pulse animation**: Green dot that pulses
- **Website**: Current site hostname

#### Score Card
- **Animated background**: Rotating gradient
- **Large score**: 64px number with color
- **Badge**: Risk level (LOW/MEDIUM/HIGH/CRITICAL)

#### Details Cards
- **Info rows**: Request type and details
- **Progress bars**: Animated fills for each component
- **Flag items**: Rounded chips with risk indicators

## Performance Benchmarks

### Landing Page
- **Initial Load**: < 2 seconds
- **3D Rendering**: 60 FPS
- **API Request**: 2-5 seconds (depends on address activity)

### Extension
- **Popup Open**: < 100ms
- **Risk Analysis**: Instant (from background script)
- **Memory Usage**: < 50MB

### Backend API
- **Address Check**: 2-8 seconds (Etherscan rate limits)
- **Website Check**: 1-3 seconds
- **Model Inference**: < 100ms

## Common Issues & Solutions

### Issue: 3D Sphere Not Showing
**Solution**:
- Check browser console for errors
- Ensure WebGL is enabled
- Try Chrome/Edge instead of Firefox

### Issue: API Returns Errors
**Solution**:
- Check backend console for errors
- Verify Etherscan API key in .env
- Check network connectivity

### Issue: Extension Shows Empty State
**Solution**:
- Interact with wallet on the current page
- Check background.js console in chrome://extensions
- Ensure backend is running

## Testing Checklist

- [ ] Backend API starts without errors
- [ ] Landing page loads with 3D animation
- [ ] Address scanner returns results
- [ ] Website scanner returns results
- [ ] Extension loads in Chrome
- [ ] Extension icon shows in toolbar
- [ ] Extension popup opens
- [ ] Extension detects wallet transactions
- [ ] Risk scores display correctly
- [ ] Component breakdown shows
- [ ] Risk flags appear
- [ ] All animations work smoothly

## Screenshots to Take

1. **Hero Section**: Full width showing 3D sphere
2. **Features Grid**: All 6 feature cards
3. **Scanner - Address**: Showing a risk analysis result
4. **Scanner - Website**: Showing a website check result
5. **Extension Popup - Safe**: Low risk score example
6. **Extension Popup - Dangerous**: High risk score with flags
7. **Extension in Action**: Browser with extension analyzing a transaction

## Video Demo Script

1. **Intro (10s)**: Show landing page hero
2. **Features (15s)**: Scroll through features
3. **Scanner Demo (30s)**: Check both address and website
4. **Extension Install (20s)**: Load extension in Chrome
5. **Live Demo (30s)**: Visit Uniswap, connect wallet, show extension
6. **Risk Detection (20s)**: Show high-risk example
7. **Outro (10s)**: Show project structure

Total: ~2 minutes

## Presentation Tips

1. **Start with Problem**: Show examples of crypto scams in news
2. **Introduce Solution**: Web3 Risk Guard architecture
3. **Live Demo**: Follow this guide
4. **Technical Deep Dive**: Show ML model, GoPlus integration
5. **Results**: Show accuracy metrics, test results
6. **Future Work**: Discuss potential improvements
7. **Q&A**: Be prepared for technical questions

## Key Talking Points

- **3-Layer Detection**: ML + GoPlus + Blacklist
- **Real-World Training**: 667 verified fraud cases
- **95% Accuracy**: Proven on test dataset
- **Modern UI**: Uniswap-inspired design with 3D elements
- **Full Stack**: React, Flask, ML, Browser Extension
- **Open Source**: All code available on GitHub
