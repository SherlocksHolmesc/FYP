"""
Web3 Risk Guard - Backend API
==============================

This API provides real-time address risk scoring by:
1. Fetching address transaction history from Etherscan
2. Computing the same features used in training
3. Running inference through the trained ML model
4. Querying GoPlus Security API for contract/honeypot detection
5. Returning a combined risk score to the browser extension

SETUP:
1. Get free API key from https://etherscan.io/apis
2. Create .env file with: ETHERSCAN_API_KEY=your_key
3. pip install -r requirements.txt
4. python api.py
"""

import os
import pickle
import json
import time
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import numpy as np
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)  # Allow requests from browser extension

# ============================================================
# CONFIGURATION
# ============================================================

ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY', '')
ETHERSCAN_BASE_URL = 'https://api.etherscan.io/v2/api'  # V2 API
GOPLUS_BASE_URL = 'https://api.gopluslabs.io/api/v1'  # GoPlus Security API (free, no key needed)

# Model v2 - trained on 667 real GoPlus-verified addresses
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'ml', 'model_v2.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), '..', 'ml', 'scaler_v2.pkl')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), '..', 'ml', 'features_v2.json')

# Load model and scaler
model = None
scaler = None
feature_names = None

def load_model():
    global model, scaler, feature_names
    try:
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        with open(SCALER_PATH, 'rb') as f:
            scaler = pickle.load(f)
        with open(FEATURES_PATH, 'r') as f:
            feature_names = json.load(f)['features']
        print(f"[OK] Model loaded with {len(feature_names)} features")
    except Exception as e:
        print(f"[ERROR] Failed to load model: {e}")

# ============================================================
# ETHERSCAN API FUNCTIONS
# ============================================================

def etherscan_request(params):
    """Make a request to Etherscan API V2."""
    params['apikey'] = ETHERSCAN_API_KEY
    params['chainid'] = 1  # Ethereum mainnet for V2 API
    try:
        response = requests.get(ETHERSCAN_BASE_URL, params=params, timeout=15)
        data = response.json()
        print(f"[DEBUG] Etherscan response status: {data.get('status')}, message: {data.get('message')}")
        if data.get('status') == '1':
            return data.get('result', [])
        # Handle "No transactions found" as empty list, not error
        if 'No transactions found' in str(data.get('message', '')):
            return []
        return []
    except Exception as e:
        print(f"[ERROR] Etherscan request failed: {e}")
        return []

def get_normal_transactions(address):
    """Get normal transactions for an address."""
    return etherscan_request({
        'module': 'account',
        'action': 'txlist',
        'address': address,
        'startblock': 0,
        'endblock': 99999999,
        'sort': 'asc'
    })

def get_erc20_transactions(address):
    """Get ERC20 token transactions for an address."""
    return etherscan_request({
        'module': 'account',
        'action': 'tokentx',
        'address': address,
        'startblock': 0,
        'endblock': 99999999,
        'sort': 'asc'
    })

def get_balance(address):
    """Get ETH balance for an address."""
    result = etherscan_request({
        'module': 'account',
        'action': 'balance',
        'address': address,
        'tag': 'latest'
    })
    try:
        return int(result) / 1e18 if result else 0
    except:
        return 0

# ============================================================
# GOPLUS SECURITY API
# ============================================================

def get_goplus_address_security(address):
    """
    Check if address is flagged as malicious by GoPlus.
    Returns risk flags like stealing_attack, phishing, honeypot_related, etc.
    """
    try:
        url = f"{GOPLUS_BASE_URL}/address_security/{address}"
        response = requests.get(url, timeout=10)
        data = response.json()
        
        if data.get('code') == 1 and data.get('result'):
            return data['result']
        return None
    except Exception as e:
        print(f"[ERROR] GoPlus address security failed: {e}")
        return None

def get_goplus_token_security(address, chain_id=1):
    """
    Check token contract security (honeypot, rug pull risks, etc).
    chain_id=1 for Ethereum mainnet.
    """
    try:
        url = f"{GOPLUS_BASE_URL}/token_security/{chain_id}"
        params = {'contract_addresses': address}
        response = requests.get(url, params=params, timeout=10)
        data = response.json()
        
        if data.get('code') == 1 and data.get('result'):
            # Result is keyed by address (lowercase)
            return data['result'].get(address.lower())
        return None
    except Exception as e:
        print(f"[ERROR] GoPlus token security failed: {e}")
        return None

def get_goplus_phishing_site(url):
    """
    Check if a URL is a known phishing site.
    """
    try:
        api_url = f"{GOPLUS_BASE_URL}/phishing_site"
        params = {'url': url}
        response = requests.get(api_url, params=params, timeout=10)
        data = response.json()
        
        if data.get('code') == 1 and data.get('result'):
            return data['result']
        return None
    except Exception as e:
        print(f"[ERROR] GoPlus phishing site check failed: {e}")
        return None

def get_goplus_dapp_security(url):
    """
    Get security info for a dApp/website including audit status and contract risks.
    """
    try:
        api_url = f"{GOPLUS_BASE_URL}/dapp_security"
        params = {'url': url}
        response = requests.get(api_url, params=params, timeout=10)
        data = response.json()
        
        if data.get('code') == 1 and data.get('result'):
            return data['result']
        return None
    except Exception as e:
        print(f"[ERROR] GoPlus dApp security check failed: {e}")
        return None

def analyze_site_risks(url):
    """
    Comprehensive site/dApp risk analysis.
    Detects phishing sites, fake dApps, and malicious contracts.
    """
    risks = {
        'url': url,
        'score': 50,  # Default uncertain
        'is_phishing': False,
        'is_verified_dapp': False,
        'is_audited': False,
        'flags': [],
        'dapp_info': None,
        'contracts': [],
        'raw': {}
    }
    
    # 1. Check if it's a known phishing site
    phishing_result = get_goplus_phishing_site(url)
    if phishing_result:
        risks['raw']['phishing'] = phishing_result
        if phishing_result.get('phishing_site') == 1:
            risks['is_phishing'] = True
            risks['score'] = 100
            risks['flags'].append('🚨 KNOWN PHISHING SITE')
            return risks  # Immediate danger, no need to check more
        
        # Check contracts associated with the site
        site_contracts = phishing_result.get('website_contract_security', [])
        for contract in site_contracts:
            if contract.get('is_malicious_contract') == 1:
                risks['flags'].append(f"Malicious Contract: {contract.get('contract_address', 'unknown')[:10]}...")
                risks['score'] = max(risks['score'], 90)
    
    # 2. Check dApp security info
    dapp_result = get_goplus_dapp_security(url)
    if dapp_result:
        risks['raw']['dapp'] = dapp_result
        risks['dapp_info'] = {
            'name': dapp_result.get('project_name'),
            'is_trusted': dapp_result.get('trust_list') == 1,
            'is_audited': dapp_result.get('is_audit') == 1,
        }
        
        # Positive signals
        if dapp_result.get('trust_list') == 1:
            risks['is_verified_dapp'] = True
            risks['flags'].append(f"✓ Verified dApp: {dapp_result.get('project_name', 'Unknown')}")
            risks['score'] = max(0, risks['score'] - 40)
        
        if dapp_result.get('is_audit') == 1:
            risks['is_audited'] = True
            audit_info = dapp_result.get('audit_info', [])
            if audit_info:
                firms = [a.get('audit_firm', '') for a in audit_info[:3]]
                risks['flags'].append(f"✓ Audited by: {', '.join(firms)}")
            risks['score'] = max(0, risks['score'] - 20)
        
        # Check contracts deployed by the dApp
        contracts_security = dapp_result.get('contracts_security', [])
        for chain_data in contracts_security:
            for contract in chain_data.get('contracts', []):
                contract_info = {
                    'address': contract.get('contract_address'),
                    'is_malicious': contract.get('malicious_contract') == 1,
                    'malicious_creator': contract.get('malicious_creator') == 1,
                    'is_open_source': contract.get('is_open_source') == 1,
                }
                risks['contracts'].append(contract_info)
                
                if contract.get('malicious_contract') == 1:
                    risks['flags'].append(f"⚠️ Malicious contract detected")
                    risks['score'] = max(risks['score'], 85)
                
                if contract.get('malicious_creator') == 1:
                    behaviors = contract.get('malicious_creator_behavior', [])
                    risks['flags'].append(f"⚠️ Creator has malicious history: {', '.join(behaviors[:2])}")
                    risks['score'] = max(risks['score'], 75)
                
                if contract.get('is_open_source') != 1:
                    risks['flags'].append("Contract not open source")
                    risks['score'] = max(risks['score'], 40)
    else:
        # No dApp info found - unknown site
        risks['flags'].append("⚠️ Unknown/Unverified dApp")
        risks['score'] = max(risks['score'], 60)
    
    # Determine final verdict
    if risks['score'] >= 80:
        risks['verdict'] = 'DANGEROUS'
    elif risks['score'] >= 50:
        risks['verdict'] = 'SUSPICIOUS'
    elif risks['score'] >= 30:
        risks['verdict'] = 'CAUTION'
    else:
        risks['verdict'] = 'SAFE'
    
    return risks

def analyze_goplus_risks(address):
    """
    Comprehensive GoPlus risk analysis.
    Returns a risk score (0-100) and detailed flags.
    """
    risks = {
        'score': 0,
        'flags': [],
        'is_malicious': False,
        'is_honeypot': False,
        'is_contract': False,
        'raw': {}
    }
    
    # Check address security (works for any address)
    addr_security = get_goplus_address_security(address)
    if addr_security:
        risks['raw']['address_security'] = addr_security
        
        # Critical flags - immediate high risk
        critical_flags = [
            ('stealing_attack', 'Stealing Attack', 80),
            ('phishing_activities', 'Phishing', 70),
            ('blackmail_activities', 'Blackmail', 75),
            ('cybercrime', 'Cybercrime', 70),
            ('money_laundering', 'Money Laundering', 60),
            ('financial_crime', 'Financial Crime', 65),
            ('honeypot_related_address', 'Honeypot Related', 80),
            ('fake_kyc', 'Fake KYC', 50),
            ('darkweb_transactions', 'Darkweb Activity', 60),
            ('malicious_mining_activities', 'Malicious Mining', 55),
            ('sanctioned', 'Sanctioned Address', 90),
            ('mixer', 'Mixer Usage', 40),
            ('fake_token', 'Fake Token Creator', 70),
            ('number_of_malicious_contracts_created', 'Malicious Contracts Created', 80),
        ]
        
        for flag_key, flag_name, score_add in critical_flags:
            value = addr_security.get(flag_key, '0')
            # Handle both string "1" and int > 0
            if value and str(value) != '0':
                risks['flags'].append(flag_name)
                risks['score'] = max(risks['score'], score_add)
                risks['is_malicious'] = True
    
    # Check token security (only works for contract addresses)
    token_security = get_goplus_token_security(address)
    if token_security:
        risks['raw']['token_security'] = token_security
        risks['is_contract'] = True
        
        # Honeypot detection - critical
        if token_security.get('is_honeypot') == '1':
            risks['flags'].append('HONEYPOT')
            risks['score'] = max(risks['score'], 95)
            risks['is_honeypot'] = True
            risks['is_malicious'] = True
        
        if token_security.get('honeypot_with_same_creator') == '1':
            risks['flags'].append('Creator Made Honeypots')
            risks['score'] = max(risks['score'], 85)
        
        # Trading restrictions
        if token_security.get('cannot_buy') == '1':
            risks['flags'].append('Cannot Buy')
            risks['score'] = max(risks['score'], 70)
        
        if token_security.get('cannot_sell_all') == '1':
            risks['flags'].append('Cannot Sell All')
            risks['score'] = max(risks['score'], 75)
        
        # Tax analysis
        try:
            buy_tax = float(token_security.get('buy_tax', 0) or 0)
            sell_tax = float(token_security.get('sell_tax', 0) or 0)
            if buy_tax > 0.1:  # >10% buy tax
                risks['flags'].append(f'High Buy Tax ({buy_tax*100:.1f}%)')
                risks['score'] = max(risks['score'], 50 + int(buy_tax * 30))
            if sell_tax > 0.1:  # >10% sell tax
                risks['flags'].append(f'High Sell Tax ({sell_tax*100:.1f}%)')
                risks['score'] = max(risks['score'], 50 + int(sell_tax * 40))
        except:
            pass
        
        # Ownership risks
        if token_security.get('hidden_owner') == '1':
            risks['flags'].append('Hidden Owner')
            risks['score'] = max(risks['score'], 45)
        
        if token_security.get('can_take_back_ownership') == '1':
            risks['flags'].append('Can Reclaim Ownership')
            risks['score'] = max(risks['score'], 50)
        
        if token_security.get('owner_change_balance') == '1':
            risks['flags'].append('Owner Can Change Balances')
            risks['score'] = max(risks['score'], 60)
        
        # Minting risks
        if token_security.get('is_mintable') == '1':
            # Mintable is not always bad (e.g., USDT), but worth noting
            risks['flags'].append('Mintable')
            risks['score'] = max(risks['score'], 20)
        
        # Transfer controls
        if token_security.get('transfer_pausable') == '1':
            risks['flags'].append('Transfer Pausable')
            risks['score'] = max(risks['score'], 35)
        
        if token_security.get('is_blacklisted') == '1':
            risks['flags'].append('Has Blacklist')
            risks['score'] = max(risks['score'], 30)
        
        if token_security.get('is_whitelisted') == '1':
            risks['flags'].append('Has Whitelist')
            risks['score'] = max(risks['score'], 25)
        
        # Positive signals (reduce score)
        if token_security.get('is_open_source') == '1':
            risks['flags'].append('✓ Open Source')
            risks['score'] = max(0, risks['score'] - 10)
        
        if token_security.get('trust_list') == '1':
            risks['flags'].append('✓ Trusted Token')
            risks['score'] = max(0, risks['score'] - 20)
        
        if token_security.get('is_in_cex', {}).get('listed') == '1':
            cex_list = token_security.get('is_in_cex', {}).get('cex_list', [])
            if cex_list:
                risks['flags'].append(f'✓ Listed on {", ".join(cex_list[:3])}')
                risks['score'] = max(0, risks['score'] - 15)
    
    # Cap at 100
    risks['score'] = min(100, risks['score'])
    
    return risks

# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(address):
    """
    Extract the same features used in model training from live Etherscan data.
    
    Returns a dict of features matching the training dataset columns.
    """
    print(f"[INFO] Fetching data for {address}...")
    
    # Fetch transactions
    normal_txs = get_normal_transactions(address)
    erc20_txs = get_erc20_transactions(address)
    balance = get_balance(address)
    
    address_lower = address.lower()
    
    # Separate sent and received transactions
    sent_txs = [tx for tx in normal_txs if tx.get('from', '').lower() == address_lower]
    received_txs = [tx for tx in normal_txs if tx.get('to', '').lower() == address_lower]
    
    # ERC20 sent and received
    erc20_sent = [tx for tx in erc20_txs if tx.get('from', '').lower() == address_lower]
    erc20_received = [tx for tx in erc20_txs if tx.get('to', '').lower() == address_lower]
    
    # Calculate time-based features
    def get_timestamps(txs):
        return sorted([int(tx.get('timeStamp', 0)) for tx in txs])
    
    def avg_time_between(timestamps):
        if len(timestamps) < 2:
            return 0
        diffs = [(timestamps[i+1] - timestamps[i]) / 60 for i in range(len(timestamps)-1)]
        return np.mean(diffs) if diffs else 0
    
    def time_diff_first_last(timestamps):
        if len(timestamps) < 2:
            return 0
        return (timestamps[-1] - timestamps[0]) / 60
    
    sent_times = get_timestamps(sent_txs)
    received_times = get_timestamps(received_txs)
    all_times = sorted(sent_times + received_times)
    
    # Calculate value features (convert from Wei to Ether)
    def get_values_ether(txs):
        return [int(tx.get('value', 0)) / 1e18 for tx in txs]
    
    sent_values = get_values_ether(sent_txs)
    received_values = get_values_ether(received_txs)
    
    # ERC20 unique addresses and tokens
    erc20_sent_addrs = set(tx.get('to', '').lower() for tx in erc20_sent)
    erc20_rec_addrs = set(tx.get('from', '').lower() for tx in erc20_received)
    erc20_sent_tokens = set(tx.get('tokenName', '') for tx in erc20_sent)
    erc20_rec_tokens = set(tx.get('tokenName', '') for tx in erc20_received)
    
    # Build feature dict matching training columns
    features = {
        'Avg min between sent tnx': avg_time_between(sent_times),
        'Avg min between received tnx': avg_time_between(received_times),
        'Time Diff between first and last (Mins)': time_diff_first_last(all_times),
        'Sent tnx': len(sent_txs),
        'Received Tnx': len(received_txs),
        'Number of Created Contracts': sum(1 for tx in sent_txs if tx.get('to', '') == ''),
        'avg val received': np.mean(received_values) if received_values else 0,
        'avg val sent': np.mean(sent_values) if sent_values else 0,
        'total Ether sent': sum(sent_values),
        'total ether received': sum(received_values),
        'total ether balance': balance,
        ' ERC20 total Ether received': 0,  # Would need token prices
        ' ERC20 total ether sent': 0,
        ' ERC20 uniq sent addr': len(erc20_sent_addrs),
        ' ERC20 uniq rec addr': len(erc20_rec_addrs),
        ' ERC20 uniq sent token name': len(erc20_sent_tokens),
        ' ERC20 uniq rec token name': len(erc20_rec_tokens),
    }
    
    print(f"[INFO] Extracted {len(features)} features")
    return features

# ============================================================
# PREDICTION
# ============================================================

def predict_risk(address):
    """
    Main function to predict risk score for an address.
    Combines ML model + GoPlus Security API for comprehensive detection.
    """
    result = {
        'address': address,
        'score': 50,
        'prediction': 'UNKNOWN',
        'confidence': 0,
        'components': {
            'ml_score': None,
            'goplus_score': None,
        },
        'goplus_flags': [],
        'is_honeypot': False,
        'is_contract': False,
    }
    
    # 1. GoPlus Security Analysis (always run - catches honeypots, scams)
    print(f"[INFO] Querying GoPlus Security for {address}...")
    goplus_risks = analyze_goplus_risks(address)
    result['goplus_flags'] = goplus_risks['flags']
    result['is_honeypot'] = goplus_risks['is_honeypot']
    result['is_contract'] = goplus_risks['is_contract']
    result['components']['goplus_score'] = goplus_risks['score']
    
    # If GoPlus finds critical issues (honeypot, stealing), return immediately
    if goplus_risks['score'] >= 80:
        result['score'] = goplus_risks['score']
        result['prediction'] = 'DANGEROUS'
        result['confidence'] = 0.95
        result['reason'] = f"GoPlus flagged: {', '.join(goplus_risks['flags'][:3])}"
        return result
    
    # 2. ML Model Analysis (for transaction pattern detection)
    ml_score = None
    if model and scaler and ETHERSCAN_API_KEY:
        try:
            features = extract_features(address)
            feature_vector = [features.get(f, 0) for f in feature_names]
            X = np.array([feature_vector])
            X_scaled = scaler.transform(X)
            proba = model.predict_proba(X_scaled)[0]
            fraud_probability = proba[1]
            ml_score = int(fraud_probability * 100)
            result['components']['ml_score'] = ml_score
            result['confidence'] = float(max(proba))
        except Exception as e:
            print(f"[ERROR] ML prediction failed: {e}")
    
    # 3. Combine scores intelligently
    # - GoPlus is authoritative for flagged addresses (honeypots, scams)
    # - ML is supplementary - only trust high ML scores when GoPlus also has concerns
    # - This prevents false positives on legitimate low-activity wallets
    
    if goplus_risks['score'] >= 50:
        # GoPlus found issues - combine with ML
        if ml_score is not None and ml_score >= 70:
            # Both agree it's risky
            result['score'] = int(goplus_risks['score'] * 0.6 + ml_score * 0.4)
        else:
            # Trust GoPlus
            result['score'] = goplus_risks['score']
    elif ml_score is not None and ml_score >= 85:
        # ML very confident but GoPlus clean - be cautious, not alarming
        # Could be a new scam not yet in GoPlus, OR a false positive
        result['score'] = int(ml_score * 0.35)  # Reduce significantly
        result['ml_warning'] = True
    elif ml_score is not None:
        # Normal case - ML score below threshold, GoPlus clean
        result['score'] = int(ml_score * 0.25)  # Low weight for ML alone
    else:
        # No ML score, GoPlus clean
        result['score'] = goplus_risks['score']
    
    # Determine prediction label
    if result['score'] >= 70:
        result['prediction'] = 'FRAUD'
    elif result['score'] >= 40:
        result['prediction'] = 'SUSPICIOUS'
    elif result.get('ml_warning') and ml_score >= 85:
        result['prediction'] = 'CAUTION'  # New: ML flagged but unconfirmed
    else:
        result['prediction'] = 'SAFE'
    
    return result

# ============================================================
# API ROUTES
# ============================================================

@app.route('/')
def home():
    return jsonify({
        'service': 'Web3 Risk Guard API',
        'version': '2.1.0',
        'features': ['ML Model', 'GoPlus Security', 'Honeypot Detection', 'Phishing Site Detection', 'dApp Verification'],
        'endpoints': {
            '/score/<address>': 'GET - Get risk score for an Ethereum address',
            '/site': 'GET - Check if a website/dApp is safe (param: url)',
            '/goplus/<address>': 'GET - Get raw GoPlus security data',
            '/health': 'GET - Check API health',
            '/debug/<address>': 'GET - Debug endpoint with raw features'
        }
    })

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'etherscan_configured': bool(ETHERSCAN_API_KEY and ETHERSCAN_API_KEY != 'your_api_key_here'),
        'goplus_enabled': True  # No API key needed
    })

@app.route('/goplus/<address>')
def goplus_raw(address):
    """Get raw GoPlus security data for debugging."""
    if not address or len(address) != 42 or not address.startswith('0x'):
        return jsonify({'error': 'Invalid Ethereum address format'}), 400
    
    risks = analyze_goplus_risks(address)
    return jsonify(risks)

@app.route('/site')
def check_site():
    """
    Check if a website/dApp is safe to connect wallet to.
    
    Query params:
        - url: The website URL to check (required)
    
    Returns:
        - score: 0-100 (higher = more dangerous)
        - verdict: SAFE, CAUTION, SUSPICIOUS, or DANGEROUS
        - is_phishing: Whether it's a known phishing site
        - is_verified_dapp: Whether it's a verified dApp
        - is_audited: Whether contracts are audited
        - flags: List of risk/safety indicators
    """
    url = request.args.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL parameter required. Usage: /site?url=https://example.com'}), 400
    
    # Normalize URL
    if not url.startswith('http'):
        url = 'https://' + url
    
    start_time = time.time()
    result = analyze_site_risks(url)
    result['processing_time_ms'] = int((time.time() - start_time) * 1000)
    
    # Remove raw data from response (too verbose)
    if 'raw' in result:
        del result['raw']
    
    return jsonify(result)

@app.route('/score/<address>')
def score_address(address):
    """
    Get risk score for an Ethereum address.
    
    Returns:
        - score: 0-100 (higher = more risky)
        - probability: raw fraud probability
        - prediction: FRAUD or SAFE
        - confidence: model confidence
    """
    # Validate address format
    if not address or len(address) != 42 or not address.startswith('0x'):
        return jsonify({'error': 'Invalid Ethereum address format'}), 400
    
    start_time = time.time()
    result = predict_risk(address)
    result['processing_time_ms'] = int((time.time() - start_time) * 1000)
    
    return jsonify(result)

@app.route('/debug/<address>')
def debug_address(address):
    """Debug endpoint to see raw features."""
    features = extract_features(address)
    normal_txs = get_normal_transactions(address)
    erc20_txs = get_erc20_transactions(address)
    
    return jsonify({
        'address': address,
        'normal_tx_count': len(normal_txs) if isinstance(normal_txs, list) else 0,
        'erc20_tx_count': len(erc20_txs) if isinstance(erc20_txs, list) else 0,
        'features': features,
        'sample_normal_tx': normal_txs[0] if normal_txs else None
    })

@app.route('/batch', methods=['POST'])
def batch_score():
    """
    Score multiple addresses at once.
    
    POST body: { "addresses": ["0x...", "0x..."] }
    """
    data = request.get_json()
    addresses = data.get('addresses', [])
    
    if not addresses or len(addresses) > 10:
        return jsonify({'error': 'Provide 1-10 addresses'}), 400
    
    results = []
    for addr in addresses:
        results.append(predict_risk(addr))
        time.sleep(0.2)  # Rate limiting for Etherscan
    
    return jsonify({'results': results})

# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    load_model()
    
    if not ETHERSCAN_API_KEY or ETHERSCAN_API_KEY == 'your_api_key_here':
        print("\n" + "="*60)
        print("WARNING: Etherscan API key not configured!")
        print("="*60)
        print("1. Get free API key from: https://etherscan.io/apis")
        print("2. Create .env file in backend/ folder")
        print("3. Add: ETHERSCAN_API_KEY=your_key_here")
        print("="*60 + "\n")
    
    print("\n[SERVER] Starting Web3 Risk Guard API on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
