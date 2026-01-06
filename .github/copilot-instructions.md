# Web3 Risk Guard - AI Coding Instructions

## Project Overview

Web3 Risk Guard is a multi-layered Ethereum security system consisting of:

1. **Browser Extension** (manifest v3) - Real-time wallet transaction monitoring
2. **Flask Backend API** - ML model inference and external API integration
3. **React Landing Page** - Public-facing scanner interface with dApp simulation
4. **ML Training Pipeline** - Model training on verified fraud cases

**Key Insight**: The system uses **context-aware scoring** - combining ML predictions, dApp runtime simulation, and code analysis. Trusted domains (Uniswap, Aave, etc.) verified safe by simulation skip detailed code analysis to eliminate false positives.

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

- `/score/<address>` - Address risk score (GoPlus + ML behavioral analysis + Smart Contract source analysis)
- `/site?url=<url>` - Website phishing detection (ML + typosquat + code analysis)
- `/analyze-browser?url=<url>` - **Primary scanner endpoint** - Browser-based analysis with Playwright
  - Accepts `simulation_is_safe` and `simulation_confidence` params for context-aware filtering
  - Trusted domain + safe simulation = skips code analysis entirely (0 findings)
- `/simulate-dapp?url=<url>` - Runtime dApp behavior simulation (honeypot, typosquatting detection)
- `/goplus/<address>` - Raw GoPlus Security API data
- `/debug/<address>` - Full feature breakdown for model debugging

**Context-Aware Architecture**:
1. ML model predicts phishing (website_model.pkl)
2. dApp simulator checks runtime behavior (dapp_simulator.py - 100% typosquatting accuracy)
3. Code analyzer scans JavaScript/Solidity (code_analyzer.py + browser_analyzer.py)
4. **If trusted domain + safe simulation → skip code analysis** (eliminates false positives)

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

1. **Primary**: `browser_analyzer.py::analyze_website_sync()` - Playwright with context-aware skip logic
2. **Fallback**: `code_analyzer.py::analyze_website()` - HTTP request analysis
3. **Skip Logic**: Both analyzers check if `trusted domain + safe simulation (>=85% confidence)` → return CLEAN with 0 findings

**Critical Pattern Files**:
- `code_analyzer.py` lines 44-78: TRUSTED_DEFI_DOMAINS list (25+ verified DeFi sites)
- `code_analyzer.py` lines 80-350: DRAINER_PATTERNS dictionary with severity/category/legit_use flags
- `code_analyzer.py` lines 105-150: SUSPICIOUS_COMBINATIONS for behavioral pattern learning
- `code_analyzer.py` lines 572-578: Category-based filtering (only show "Known Drainer Kit" + "Key Theft" on trusted domains)
- `code_analyzer.py` lines 708-713: Skip logic - trusted + safe simulation returns immediately
- `browser_analyzer.py` lines 208-219: Skip logic - same pattern as code_analyzer

## Key Files & Their Roles

- **background.js** (384 lines): Core risk detection engine, hybrid scoring logic, ML API integration
- **backend/api.py** (2,400+ lines): Flask server with 9 endpoints, feature computation, GoPlus integration, **Solidity source code analysis**
- **backend/code_analyzer.py** (863 lines): Pattern-based detection with 30+ malicious patterns, context-aware filtering, behavioral pattern learning
- **backend/browser_analyzer.py** (420+ lines): Playwright-based analysis with skip logic for trusted domains
- **backend/dapp_simulator.py** (750+ lines): Runtime dApp behavior simulation, 100% typosquatting detection accuracy
- **ml/train_real_model.py**: Training script using sklearn RandomForestClassifier, generates model_v2.pkl
- **ml/train_website_model.py**: Website phishing model training, generates website_model.pkl
- **data/legit_domains.py**: 339-line curated list of legitimate crypto brands for typosquat detection
- **popup.js/popup.html**: Uniswap-inspired UI with animated marquee, gradient backgrounds, component scores
- **web/src/pages/Scanner.jsx** (2,882 lines): Main scanner UI with ML analysis, dApp simulation, and source code display

## Common Pitfalls

1. **ML Cache Timeout**: `background.js` caches ML scores for 5 minutes. Clear `mlScoreCache` when debugging.
2. **Etherscan API V2**: Must include `chainid: 1` param. V1 endpoints will fail.
3. **Browser Analyzer Timeout**: Playwright can take 30-60s. Use `-TimeoutSec 120` in PowerShell.
4. **Feature Count Mismatch**: If API returns error "Expected X features, got Y", feature computation is out of sync with trained model.
5. **CORS in Extension**: `manifest.json` requires `"host_permissions": ["<all_urls>"]` for API calls.
6. **Contract Source Not Verified**: Smart contract analysis only works for verified contracts on Etherscan. Unverified contracts will show "source not available."
7. **Simulation Context Passing**: Frontend sends `simulation_is_safe` as boolean, backend must check for both `'true'` and `'True'` (case-sensitive string comparison issue at api.py line 2289)
8. **Backend Restart Required**: After editing code_analyzer.py or browser_analyzer.py patterns, Flask server MUST be restarted to apply changes
9. **False Positive Patterns**: When adding patterns to DRAINER_PATTERNS, set `'legit_use': True` for patterns that appear in legitimate dApps (e.g., eth_sign, permit signatures)
10. **Skip Logic Order**: Context-aware skip logic MUST be checked BEFORE fetching website data to avoid unnecessary processing

## External Dependencies

- **GoPlus Security API** (free, no key): Real-time contract honeypot/phishing detection
- **Etherscan API** (free key required): Transaction history for feature computation
- **Playwright** (optional): For analyzing anti-scraping websites (install via `pip install playwright; playwright install chromium`)

## Debugging Tips

- Extension logs: Browser DevTools Console (filter by `[W3RG]`)
- Backend logs: Terminal running `python api.py` shows `[DEBUG]`, `[ERROR]` prefixed logs
- Feature debugging: `/debug/<address>` endpoint returns full feature vector
- Model visualization: `ml/visualize_model.py` generates feature importance plots
