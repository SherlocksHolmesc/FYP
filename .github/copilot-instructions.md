# Web3 Risk Guard - AI Coding Instructions

## Project Overview

Web3 Risk Guard is a multi-layered Ethereum security system consisting of:

1. **Browser Extension** (manifest v3) - Real-time wallet transaction monitoring
2. **Flask Backend API** - ML model inference and external API integration
3. **React Landing Page** - Public-facing scanner interface
4. **ML Training Pipeline** - Model training on verified fraud cases

**Key Insight**: The ML model predicts GoPlus Security API risk flags before addresses are added to their database, trained on 667+ verified fraud cases from multiple sources (GoPlus, darklist, known safe exchanges).

## Architecture & Data Flow

### Extension Request Flow

```
User Wallet Interaction → inpage.js (intercepts window.ethereum)
  → content.js (forwards to background) → background.js (hybrid scoring)
  → ML API (/score/<address>) + Darklist + Heuristics → popup.js (displays results)
```

### Hybrid Scoring System (background.js)

- **35% ML Model**: Random Forest trained on transaction patterns
- **30% Darklist**: 3,580+ known malicious addresses from data/darklist.json
- **35% Heuristics**: Rule-based detection (unlimited approvals, honeypots)

### Critical API Endpoints (backend/api.py)

- `/score/<address>` - Address risk score (GoPlus labels + ML behavioral analysis + **Smart Contract Source Code Analysis**)
- `/site?url=<url>` - Website phishing detection (ML + typosquat + code analysis)
- `/analyze-code?url=<url>` - JavaScript source code pattern analysis with line numbers
- `/analyze-browser?url=<url>` - Browser-based code analysis using Playwright (bypasses anti-bot)
- `/goplus/<address>` - Raw GoPlus Security API data
- `/debug/<address>` - Full feature breakdown for model debugging

**Important Distinction**:

- **ADDRESS scanning**:
  - GoPlus returns descriptive flags ("HONEYPOT", "Stealing Attack") from their database
  - **NEW: Smart Contract Analysis** - Fetches verified Solidity source from Etherscan, analyzes for malicious patterns (honeypot code, balance manipulation, hidden owner), returns actual code with line numbers
- **WEBSITE scanning**: code_analyzer.py fetches and analyzes actual JavaScript/HTML, returns findings with line numbers and code snippets

## Development Workflow

### Quick Start

```bash
# Windows
start.bat

# Linux/Mac
./start.sh
```

This launches backend (localhost:5000) and landing page (localhost:5173) in separate terminals.

### Testing the Extension

1. Load unpacked extension from project root (manifest.json location)
2. Visit any dApp (e.g., Uniswap, Aave)
3. Initiate wallet transaction → popup shows risk analysis
4. Check browser console for `[W3RG]` debug logs

### ML Model Training

```bash
cd ml
python train_real_model.py  # Trains model_v2.pkl for ADDRESS detection
python train_website_model.py  # Trains website_model.pkl for URL detection
```

**Important**: Models are version-controlled. Feature names must match exactly between training (`features_v2.json`) and inference (`backend/api.py::compute_features()`).

### Testing API Endpoints

```powershell
# Address scoring
Invoke-RestMethod "http://localhost:5000/score/0xYourAddress"

# Website analysis (with extended timeout for Playwright)
Invoke-RestMethod "http://localhost:5000/analyze-browser?url=https://example.com" -TimeoutSec 120
```

## Critical Conventions

### Feature Engineering Consistency

The ML model depends on **exact feature alignment** between training and inference:

- Feature computation in `backend/api.py::compute_features()` must produce features in the same order as `ml/features_v2.json`
- If adding features: Update training script → retrain model → update feature_names JSON → update API computation
- Use `scaler_v2.pkl` for StandardScaler normalization (trained during model training)

### Extension Messaging Protocol

All extension messages use this structure:

```javascript
// From inpage.js to content.js
window.postMessage({ __W3RG__: true, payload: { ts, origin, href, method, params } })

// From content.js to background.js
chrome.runtime.sendMessage({ type: "WALLET_REQUEST", payload: {...} })

// From popup.js to background.js
chrome.runtime.sendMessage({ type: "GET_LATEST", tabId })
```

### Darklist Management

- Maintained at `data/darklist.json` (3,580+ entries)
- Format: `[{ "address": "0x...", "comment": "...", "date": "..." }]`
- Loaded once at extension startup in `background.js::loadDarklist()`
- To add: Use `ml/add_safe_addresses.py` or manually append to JSON

### Website Analysis Fallback Chain

1. **Primary**: `code_analyzer.py::analyze_website()` - HTTP request analysis
2. **Fallback**: `browser_analyzer.py::analyze_website_sync()` - Playwright for anti-scraping sites
3. Controlled by `BROWSER_ANALYZER_AVAILABLE` flag in api.py

## Key Files & Their Roles

- **background.js** (384 lines): Core risk detection engine, hybrid scoring logic, ML API integration
- **backend/api.py** (1,900+ lines): Flask server with 9 endpoints, feature computation, GoPlus integration, **Solidity source code analysis**
- **ml/train_real_model.py**: Training script using sklearn RandomForestClassifier, generates model_v2.pkl
- **data/legit_domains.py**: 339-line curated list of legitimate crypto brands for typosquat detection
- **popup.js/popup.html**: Uniswap-inspired UI with animated marquee, gradient backgrounds, component scores
- **backend/code_analyzer.py**: JavaScript/HTML analysis for wallet drainers, fetches and scans website code

## Common Pitfalls

1. **ML Cache Timeout**: `background.js` caches ML scores for 5 minutes. Clear `mlScoreCache` when debugging.
2. **Etherscan API V2**: Must include `chainid: 1` param. V1 endpoints will fail.
3. **Browser Analyzer Timeout**: Playwright can take 30-60s. Use `-TimeoutSec 120` in PowerShell.
4. **Feature Count Mismatch**: If API returns error "Expected X features, got Y", feature computation is out of sync with trained model.
5. **CORS in Extension**: `manifest.json` requires `"host_permissions": ["<all_urls>"]` for API calls.
6. **Contract Source Not Verified**: Smart contract analysis only works for verified contracts on Etherscan. Unverified contracts will show "source not available."
7. **Mock vs Real Data**: Scanner.jsx RISK_EXPLANATIONS (lines 9-617) are educational examples for GoPlus flags. Real code findings come from `result.data.contract_analysis.findings` (Solidity) or `codeAnalysis.findings` (JavaScript)
8. **Mock vs Real Data**: Scanner.jsx RISK_EXPLANATIONS (lines 9-617) are educational examples with mock Solidity code - NOT actual findings. Real findings come from codeAnalysis.findings array.

## External Dependencies

- **GoPlus Security API** (free, no key): Real-time contract honeypot/phishing detection
- **Etherscan API** (free key required): Transaction history for feature computation
- **Playwright** (optional): For analyzing anti-scraping websites (install via `pip install playwright; playwright install chromium`)

## Debugging Tips

- Extension logs: Browser DevTools Console (filter by `[W3RG]`)
- Backend logs: Terminal running `python api.py` shows `[DEBUG]`, `[ERROR]` prefixed logs
- Feature debugging: `/debug/<address>` endpoint returns full feature vector
- Model visualization: `ml/visualize_model.py` generates feature importance plots
