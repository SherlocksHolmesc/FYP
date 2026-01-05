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
import sys
import pickle
import json
import time
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import numpy as np
from dotenv import load_dotenv

# Add data directory to path for legit_domains module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'data'))
from legit_domains import check_typosquat, is_legitimate_domain, get_brand_names

# Import code analyzer for drainer detection
from code_analyzer import analyze_website as analyze_website_code

# Import browser-based analyzer for sites that block requests
try:
    from browser_analyzer import analyze_website_sync as analyze_website_with_browser
    BROWSER_ANALYZER_AVAILABLE = True
except ImportError as e:
    BROWSER_ANALYZER_AVAILABLE = False
    print(f"[WARN] Browser analyzer not available: {e}")

load_dotenv()

app = Flask(__name__)
CORS(app)  # Allow requests from browser extension

# ============================================================
# CONFIGURATION
# ============================================================

ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY', '')
ETHERSCAN_BASE_URL = 'https://api.etherscan.io/v2/api'  # V2 API
GOPLUS_BASE_URL = 'https://api.gopluslabs.io/api/v1'  # GoPlus Security API (free, no key needed)

# Model v2 - trained on 667 real GoPlus-verified addresses (ADDRESS detection)
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'ml', 'model_v2.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), '..', 'ml', 'scaler_v2.pkl')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), '..', 'ml', 'features_v2.json')

# Website phishing model - trained on 193 URLs (WEBSITE detection)
WEBSITE_MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'ml', 'website_model.pkl')
WEBSITE_SCALER_PATH = os.path.join(os.path.dirname(__file__), '..', 'ml', 'website_scaler.pkl')
WEBSITE_FEATURES_PATH = os.path.join(os.path.dirname(__file__), '..', 'ml', 'website_features.json')

# Load model and scaler
model = None
scaler = None
feature_names = None

# Website model
website_model = None
website_scaler = None
website_feature_names = None

def load_model():
    global model, scaler, feature_names
    global website_model, website_scaler, website_feature_names
    
    # Load address model
    try:
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        with open(SCALER_PATH, 'rb') as f:
            scaler = pickle.load(f)
        with open(FEATURES_PATH, 'r') as f:
            feature_names = json.load(f)['features']
        print(f"[OK] Address model loaded with {len(feature_names)} features")
    except Exception as e:
        print(f"[ERROR] Failed to load address model: {e}")
    
    # Load website model
    try:
        with open(WEBSITE_MODEL_PATH, 'rb') as f:
            website_model = pickle.load(f)
        with open(WEBSITE_SCALER_PATH, 'rb') as f:
            website_scaler = pickle.load(f)
        with open(WEBSITE_FEATURES_PATH, 'r') as f:
            website_feature_names = json.load(f)['features']
        print(f"[OK] Website model loaded with {len(website_feature_names)} features")
    except Exception as e:
        print(f"[ERROR] Failed to load website model: {e}")

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

def get_contract_source(address):
    """Get verified contract source code from Etherscan."""
    try:
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address,
            'apikey': ETHERSCAN_API_KEY,
            'chainid': 1
        }
        response = requests.get(ETHERSCAN_BASE_URL, params=params, timeout=15)
        data = response.json()
        
        if data.get('status') == '1' and data.get('result'):
            result = data['result'][0]
            if result.get('SourceCode'):
                return {
                    'source_code': result['SourceCode'],
                    'contract_name': result.get('ContractName', 'Unknown'),
                    'compiler_version': result.get('CompilerVersion', 'Unknown'),
                    'optimization': result.get('OptimizationUsed', '0') == '1',
                    'is_verified': True,
                    'abi': result.get('ABI', '[]')
                }
        return {'is_verified': False, 'source_code': None}
    except Exception as e:
        print(f"[ERROR] Failed to fetch contract source: {e}")
        return {'is_verified': False, 'error': str(e)}

# ============================================================
# SOLIDITY SOURCE CODE ANALYSIS
# ============================================================

# Malicious Solidity patterns to detect
SOLIDITY_PATTERNS = {
    'honeypot_transfer_block': {
        'patterns': [
            r'require\s*\(\s*from\s*==\s*owner\s*\(\s*\)',
            r'if\s*\(\s*to\s*==\s*uniswapV2Pair\s*\).*require',
            r'if\s*\(\s*to\s*==\s*pair\s*\).*require',
            r'require\s*\(.*tradingEnabled.*\)',
            r'require\s*\(\s*!\s*isBlacklisted\s*\[',
            r'require\s*\(\s*msg\.sender\s*==\s*tx\.origin\s*\)',  # Prevents contract interactions
        ],
        'severity': 'critical',
        'category': 'Honeypot Pattern',
        'description': 'Transfer function has conditional restrictions that may prevent selling'
    },
    'balance_manipulation': {
        'patterns': [
            r'function\s+setBalance\s*\(',
            r'_balances\s*\[\s*\w+\s*\]\s*=\s*\w+(?!.*\+=|-=)',
            r'function\s+\w*burn\w*From\s*\(.*\).*onlyOwner',
        ],
        'severity': 'critical',
        'category': 'Balance Manipulation',
        'description': 'Owner can directly modify token balances'
    },
    'hidden_owner': {
        'patterns': [
            r'address\s+private\s+_\w*owner',
            r'address\s+private\s+_\w*admin',
            r'mapping\s*\(\s*address\s*=>\s*bool\s*\)\s+private\s+_\w*admin',
            r'mapping\s*\(\s*bytes32\s*=>\s*bool\s*\)\s+private\s+admin',  # Hash-based admin check
            r'admin\s*\[\s*keccak256\s*\(',  # Admin verification via hash
        ],
        'severity': 'high',
        'category': 'Hidden Owner',
        'description': 'Ownership stored in private variables, obfuscating control'
    },
    'reclaim_ownership': {
        'patterns': [
            r'function\s+\w*unlock\w*\s*\(',
            r'function\s+\w*reclaim\w*Ownership\s*\(',
            r'_previousOwner\s*=\s*_owner',
            r'if\s*\(\s*block\.timestamp\s*>\s*_lockTime\s*\)',
        ],
        'severity': 'high',
        'category': 'Fake Renouncement',
        'description': 'Contract can reclaim ownership after renouncement'
    },
    'max_sell_restriction': {
        'patterns': [
            r'uint\d*\s+\w*maxSell\w*Percent',
            r'uint\d*\s+\w*maxSell\w*Amount',
            r'require\s*\(.*amount\s*<=\s*maxSell',
            r'require\s*\(.*balanceOf.*\*.*\/\s*100',
        ],
        'severity': 'high',
        'category': 'Sell Restriction',
        'description': 'Limits how much can be sold per transaction'
    },
    'pausable_transfers': {
        'patterns': [
            r'bool\s+\w*paused',
            r'modifier\s+whenNotPaused',
            r'function\s+pause\s*\(\s*\).*onlyOwner',
            r'require\s*\(\s*!\s*paused',
        ],
        'severity': 'medium',
        'category': 'Pausable',
        'description': 'Owner can pause all token transfers'
    },
    'trading_disabled': {
        'patterns': [
            r'bool\s+\w*tradingEnabled\s*=\s*false',
            r'bool\s+\w*tradingOpen\s*=\s*false',
            r'require\s*\(.*tradingEnabled',
        ],
        'severity': 'high',
        'category': 'Trading Disabled',
        'description': 'Trading starts disabled and may never be enabled'
    },
    'high_tax': {
        'patterns': [
            r'uint\d*\s+\w*sellTax\s*=\s*\d+',
            r'uint\d*\s+\w*buyTax\s*=\s*\d+',
            r'taxAmount\s*=\s*amount\s*\*\s*\d+\s*\/\s*100',
        ],
        'severity': 'medium',
        'category': 'Tax Mechanism',
        'description': 'Contract implements buy/sell taxes'
    },
    'blacklist_function': {
        'patterns': [
            r'mapping\s*\(\s*address\s*=>\s*bool\s*\)\s+\w*blacklist',
            r'function\s+\w*blacklist\w*\(',
            r'isBlacklisted\s*\[',
        ],
        'severity': 'medium',
        'category': 'Blacklist',
        'description': 'Contract can blacklist addresses from trading'
    },
    'quiz_honeypot': {
        'patterns': [
            r'payable\s*\(\s*msg\.sender\s*\)\.transfer\s*\(\s*\d+\s+ether\s*\)',  # Fixed refund amount
            r'string\s+public\s+question',  # Quiz question
            r'bytes32\s+private\s+responseHash',  # Hidden answer
            r'FOR\s+INTERNAL\s+TEST\s+ONLY',  # Fake disclaimer
            r'WORKSHOP',  # Fake test context
        ],
        'severity': 'critical',
        'category': 'Quiz Honeypot',
        'description': 'Fake quiz/game contract designed to trap users with fake refund promises'
    },
    'reverse_blacklist': {
        'patterns': [
            r'require\s*\(\s*_blacklisted\s*\[',  # Requires user to BE blacklisted
            r'require\s*\(\s*blacklisted\s*\[',
            r'require\s*\(\s*_?isBlacklisted\s*\(',
            r'if\s*\([^)]*\)\s*\{\s*require\s*\(\s*_?blacklist',  # Conditional blacklist check
        ],
        'severity': 'critical',
        'category': 'Reverse Blacklist Honeypot',
        'description': 'Requires users to be blacklisted to trade - only owner/insiders can sell'
    },
    'suspicious_hooks': {
        'patterns': [
            r'function\s+_\w+Factory\s*\(',  # Suspicious hook names like _tendiesFactory
            r'_\w+Factory\s*\([^)]*from[^)]*to',  # Hook with from/to parameters
            r'function\s+_beforeTokenTransfer.*override',  # Overridden transfer hooks
            r'function\s+_afterTokenTransfer.*override',
        ],
        'severity': 'medium',
        'category': 'Suspicious Transfer Hook',
        'description': 'Custom transfer hooks that may hide malicious logic'
    },
    'proxy_pattern': {
        'patterns': [
            r'delegatecall\s*\(',
            r'function\s+\w*upgrade\w*\(',
            r'address\s+\w*implementation',
        ],
        'severity': 'medium',
        'category': 'Proxy/Upgradeable',
        'description': 'Contract is upgradeable, code can be changed'
    },
}

def is_standard_erc20_function(context_code):
    """Check if code is inside a standard ERC20 function."""
    context_lower = context_code.lower()
    
    # Standard ERC20 internal functions
    standard_functions = [
        'function _transfer',
        'function _mint', 
        'function _burn',
        'function _approve',
        'function transfer(',
        'function transferfrom'
    ]
    
    return any(func in context_lower for func in standard_functions)

def is_legitimate_balance_operation(matched_text, context_code, line_number):
    """Deeply analyze if a balance operation is legitimate."""
    context_lower = context_code.lower()
    matched_lower = matched_text.lower()
    
    # Get the FULL LINE where the match occurred to see complete expression
    lines = context_code.split('\n')
    full_line = None
    for line in lines:
        if f'>>> {line_number:4d} |' in line or f'>>>{line_number:4d} |' in line:
            full_line = line.split('|', 1)[1].strip() if '|' in line else line
            break
    
    if full_line:
        full_line_lower = full_line.lower()
        # LEGITIMATE: Arithmetic operations in the FULL LINE
        # _balances[x] = y - amount
        # _balances[x] = y + amount
        # _balances[x] -= amount
        # _balances[x] += amount
        if any(op in full_line for op in [' - ', ' + ', ' -= ', ' += ', '+=', '-=']):
            return True
    
    # LEGITIMATE: Standard ERC20 arithmetic operations in matched text
    if any(op in matched_text for op in [' - ', ' + ', '-=', '+=']):
        return True
    
    # LEGITIMATE: Inside standard ERC20 functions (_transfer, _burn, _mint)
    if is_standard_erc20_function(context_code):
        # Check if it's normal transfer/burn/mint logic with balance checks
        if any(keyword in context_lower for keyword in ['senderbalance', 'accountbalance', 'recipientbalance']):
            # This is using a local variable after checks - legitimate!
            return True
        if 'require(' in context_lower and 'amount' in context_lower:
            return True
    
    # LEGITIMATE: Constructor initialization
    if 'constructor' in context_lower:
        return True
    
    # MALICIOUS: Direct assignment to arbitrary fixed value
    # _balances[x] = 0 (drain)
    # _balances[x] = totalSupply (inflate)
    if '= 0' in matched_text or '= _totalSupply' in matched_lower or '= totalsupply' in matched_lower:
        # Could be malicious drain unless it's in burn function
        if 'burn' not in context_lower and 'destroy' not in context_lower:
            return False
    
    return False

def is_legitimate_context(matched_text, context_code, pattern_name, finding):
    """Check if the pattern appears in a legitimate context to reduce false positives."""
    context_lower = context_code.lower()
    
    # Balance manipulation - deeply analyze ERC20 context
    if pattern_name == 'balance_manipulation':
        return is_legitimate_balance_operation(matched_text, context_code, finding.get('line_number', 0))
    
    # Honeypot transfer block - only flag if restricting normal transfers
    if pattern_name == 'honeypot_transfer_block':
        # Legitimate: onlyOwner functions are normal access control
        if 'onlyowner' in context_lower.replace(' ', ''):
            # But if it's blocking transfers based on conditions, it's suspicious
            if 'function transfer' in context_lower or 'function _transfer' in context_lower:
                # Check if there are arbitrary restrictions
                if 'tradingenabled' in context_lower.replace(' ', '') or 'cansell' in context_lower.replace(' ', ''):
                    return False  # Suspicious - arbitrary transfer restrictions
            return True  # Just access control, legitimate
    
    # Hidden owner - check if it's standard OpenZeppelin pattern
    if pattern_name == 'hidden_owner':
        if 'ownable' in context_lower or 'openzeppelin' in context_lower:
            return True
    
    # Pausable - legitimate if using OpenZeppelin pattern
    if pattern_name == 'pausable_transfers':
        if 'openzeppelin' in context_lower or 'pausable' in context_lower or 'whennotpaused' in context_lower.replace(' ', ''):
            return True  # Standard pausable pattern
    
    return False

def calculate_confidence_score(finding, full_code):
    """Calculate confidence that this is actually malicious (0-100%)."""
    confidence = 50  # Start neutral
    
    pattern_name = finding['pattern']
    context = finding['context'].lower()
    matched = finding['matched_code'].lower()
    full_code_lower = full_code.lower()
    
    # CRITICAL: Reverse blacklist honeypot - very high confidence
    if pattern_name == 'reverse_blacklist':
        confidence = 90  # Extremely suspicious pattern
        if 'require' in matched and '_blacklisted[' in matched:
            confidence = 95  # Definite honeypot - requires user to BE blacklisted
    
    # CRITICAL: Suspicious transfer hooks
    if pattern_name == 'suspicious_hooks':
        confidence = 65  # Moderately suspicious
        if '_factory' in matched.lower() or 'factory' in matched.lower():
            confidence += 20  # Unusual naming convention for hooks
    
    # Strongly decrease confidence for standard ERC20 operations
    if is_standard_erc20_function(finding['context']):
        confidence -= 40  # Standard ERC20 function - very likely legitimate
    
    # Check for ERC20 standard compliance
    if all(func in full_code_lower for func in ['function transfer(', 'function balanceof(', 'function totalsupply()']):
        confidence -= 15  # Implements ERC20 interface
    
    # Increase confidence for truly suspicious patterns
    if pattern_name == 'balance_manipulation':
        # Only suspicious if NOT using arithmetic operators
        if '=' in matched and all(op not in matched for op in [' - ', ' + ', '+=', '-=']):
            confidence += 35  # Direct assignment without arithmetic
        else:
            confidence -= 30  # Using normal arithmetic - legitimate!
        
        # Check if owner can arbitrarily change balances
        if 'onlyowner' in context and 'function setbalance' in context:
            confidence += 25  # Owner has direct balance setter - very suspicious
    
    if pattern_name == 'honeypot_transfer_block':
        if 'require' in matched and 'owner' in matched:
            if 'function transfer' in context:
                confidence += 45  # Transfer restricted to owner - honeypot!
            else:
                confidence -= 20  # Just access control
        if 'tradingenabled' in context.replace(' ', ''):
            confidence += 25  # Trading control flag - suspicious
    
    if pattern_name == 'blacklist_function':
        confidence += 15  # Blacklists are somewhat suspicious
        # But check if it's for compliance reasons
        if 'compliance' in full_code_lower or 'kyc' in full_code_lower or 'regulation' in full_code_lower:
            confidence -= 20  # Regulatory compliance
    
    # Decrease confidence for legitimate patterns
    if 'openzeppelin' in full_code_lower or '@openzeppelin' in full_code_lower:
        confidence -= 25  # Using audited standard libraries
    
    if any(license in full_code_lower for license in ['mit license', 'apache license', 'gpl', 'bsd']):
        confidence -= 10  # Open source license
    
    # Check for audit mentions
    if any(word in full_code_lower for word in ['audited by', 'certik', 'peckshield', 'slowmist']):
        confidence -= 20  # Professional audit
    
    return min(100, max(0, confidence))

def analyze_solidity_code(source_code, contract_name='Contract'):
    """
    Analyze Solidity source code for malicious patterns with context awareness.
    Reduces false positives by checking if patterns appear in legitimate contexts.
    """
    findings = []
    
    if not source_code:
        return findings
    
    lines = source_code.split('\n')
    full_code_lower = source_code.lower()
    
    for pattern_name, pattern_info in SOLIDITY_PATTERNS.items():
        for pattern in pattern_info['patterns']:
            try:
                regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                
                for match in regex.finditer(source_code):
                    # Get line number
                    line_start = source_code[:match.start()].count('\n') + 1
                    
                    # Get context (10 lines before and after for better analysis)
                    start_line = max(0, line_start - 10)
                    end_line = min(len(lines), line_start + 10)
                    
                    context_lines = []
                    for i in range(start_line, end_line):
                        if i < len(lines):
                            prefix = '>>> ' if i == line_start - 1 else '    '
                            context_lines.append(f"{prefix}{i+1:4d} | {lines[i]}")
                    
                    context_str = '\n'.join(context_lines)
                    matched_text = match.group(0)[:300]
                    
                    # Create preliminary finding for legitimacy check
                    preliminary_finding = {
                        'line_number': line_start,
                        'matched_code': matched_text,
                        'context': context_str
                    }
                    
                    # Check if this is a false positive
                    if is_legitimate_context(matched_text, context_str, pattern_name, preliminary_finding):
                        continue  # Skip legitimate patterns
                    
                    finding = {
                        'pattern': pattern_name,
                        'category': pattern_info['category'],
                        'severity': pattern_info['severity'],
                        'description': pattern_info['description'],
                        'line_number': line_start,
                        'matched_code': matched_text,
                        'context': context_str,
                        'source': contract_name,
                        'file_type': 'solidity'
                    }
                    
                    # Calculate confidence score
                    confidence = calculate_confidence_score(finding, source_code)
                    finding['confidence'] = confidence
                    
                    # Only report findings with confidence >= 40%
                    if confidence < 40:
                        continue
                    
                    # Adjust severity based on confidence
                    if confidence >= 85:
                        finding['severity'] = 'critical'
                    elif confidence >= 65:
                        finding['severity'] = 'high'
                    elif confidence >= 45:
                        finding['severity'] = 'medium'
                    else:
                        finding['severity'] = 'low'
                    
                    # Avoid duplicates on same line
                    is_duplicate = any(
                        f['pattern'] == pattern_name and f['line_number'] == line_start 
                        for f in findings
                    )
                    if not is_duplicate:
                        findings.append(finding)
                        
            except re.error:
                continue
    
    return findings

def analyze_contract_source(address):
    """Fetch and analyze contract source code."""
    result = {
        'has_source': False,
        'is_verified': False,
        'contract_name': None,
        'findings': [],
        'summary': {
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        },
        'risk_level': 'UNKNOWN',
        'full_source': None  # Store for secondary analysis
    }
    
    # Get contract source
    source_data = get_contract_source(address)
    
    if not source_data.get('is_verified'):
        result['error'] = 'Contract source code not verified on Etherscan'
        return result
    
    result['has_source'] = True
    result['is_verified'] = True
    result['contract_name'] = source_data.get('contract_name', 'Unknown')
    result['compiler_version'] = source_data.get('compiler_version')
    
    # Analyze the source code
    source_code = source_data.get('source_code', '')
    result['full_source'] = source_code  # Store for later
    findings = analyze_solidity_code(source_code, result['contract_name'])
    
    # Sort by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    findings.sort(key=lambda x: severity_order.get(x['severity'], 4))
    
    result['findings'] = findings
    
    # Calculate summary
    for finding in findings:
        sev = finding['severity']
        if sev in result['summary']:
            result['summary'][sev] += 1
    result['summary']['total_findings'] = len(findings)
    
    # Determine risk level
    if result['summary']['critical'] > 0:
        result['risk_level'] = 'CRITICAL'
    elif result['summary']['high'] > 0:
        result['risk_level'] = 'HIGH'
    elif result['summary']['medium'] > 0:
        result['risk_level'] = 'MEDIUM'
    else:
        result['risk_level'] = 'CLEAN'
    
    print(f"[CONTRACT ANALYSIS] {address}: {result['risk_level']} | Found {len(findings)} issues")
    
    return result

def extract_suspicious_code_sections(source_code, contract_name):
    """
    Extract code sections containing suspicious keywords with context.
    Used when GoPlus flags honeypot but pattern analysis finds nothing.
    Shows ACTUAL CODE with line numbers.
    """
    findings = []
    lines = source_code.split('\n')
    
    # Keywords to look for (broader than pattern matching)
    suspicious_keywords = {
        'blacklist': ('HIGH', 'Blacklist mechanism'),
        '_blacklist': ('HIGH', 'Private blacklist variable'),
        'onlyOwner': ('MEDIUM', 'Owner-only function'),
        'selfdestruct': ('CRITICAL', 'Self-destruct capability'),
        '_burn': ('MEDIUM', 'Token burning'),
        'transferOwnership': ('MEDIUM', 'Ownership transfer'),
        'pause': ('HIGH', 'Pausable functionality'),
        '_pause': ('HIGH', 'Pause mechanism'),
        'renounceOwnership': ('MEDIUM', 'Ownership renouncement'),
        '_mint': ('MEDIUM', 'Token minting'),
        'require(': ('LOW', 'Access control check'),
        'revert': ('LOW', 'Transaction revert'),
        '_transfer(': ('MEDIUM', 'Custom transfer logic'),
        'balanceOf[': ('MEDIUM', 'Balance manipulation'),
        '_balances[': ('MEDIUM', 'Balance storage access'),
    }
    
    for i, line in enumerate(lines, 1):
        line_lower = line.lower()
        
        for keyword, (severity, description) in suspicious_keywords.items():
            if keyword.lower() in line_lower:
                # Get context (3 lines before and after)
                start_line = max(1, i - 3)
                end_line = min(len(lines), i + 3)
                
                context_lines = []
                for j in range(start_line - 1, end_line):
                    line_num = j + 1
                    prefix = '→ ' if line_num == i else '  '
                    context_lines.append(f"{prefix}{line_num:4d} | {lines[j]}")
                
                code_snippet = '\n'.join(context_lines)
                
                findings.append({
                    'category': f'Code Analysis: {description}',
                    'severity': severity.lower(),
                    'description': f'Found {keyword} at line {i}. This may be related to honeypot behavior detected by GoPlus.',
                    'line_number': i,
                    'code_snippet': code_snippet,
                    'confidence': '40-60%',  # Lower confidence since no pattern match
                    'recommendation': 'Review this code section. GoPlus detected honeypot behavior but exact mechanism unclear from static analysis.'
                })
    
    # Remove duplicates (same line)
    seen_lines = set()
    unique_findings = []
    for finding in findings:
        line = finding['line_number']
        if line not in seen_lines:
            seen_lines.add(line)
            unique_findings.append(finding)
    
    # Limit to top 10 most suspicious
    priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    unique_findings.sort(key=lambda x: priority_order.get(x['severity'], 4))
    
    return unique_findings[:10]

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
    ML-based site/dApp risk analysis.
    Uses trained model for URL classification + GoPlus API for verification.
    """
    from urllib.parse import urlparse
    
    # Extract domain for analysis
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.lower().replace('www.', '')
    
    risks = {
        'url': url,
        'domain': domain,
        'score': 0,
        'is_phishing': False,
        'is_verified_dapp': False,
        'is_audited': False,
        'flags': [],
        'dapp_info': None,
        'contracts': [],
        'raw': {},
        'ml_prediction': None
    }
    
    # Known legitimate domains - whitelist (takes precedence)
    TRUSTED_DOMAINS = {
        # Major DeFi
        'uniswap.org', 'app.uniswap.org',
        'aave.com', 'app.aave.com',
        'compound.finance', 'app.compound.finance',
        'curve.fi',
        'balancer.fi', 'app.balancer.fi',
        'sushi.com', 'app.sushi.com',
        '1inch.io', 'app.1inch.io',
        'pancakeswap.finance',
        'quickswap.exchange',
        'raydium.io',
        'gmx.io', 'app.gmx.io',
        'dydx.exchange',
        'yearn.finance',
        'convexfinance.com',
        
        # NFT Marketplaces
        'opensea.io',
        'blur.io',
        'looksrare.org',
        'x2y2.io',
        'rarible.com',
        'foundation.app',
        'zora.co',
        'superrare.com',
        'niftygateway.com',
        'magiceden.io',
        
        # Exchanges
        'binance.com',
        'coinbase.com',
        'kraken.com',
        'gemini.com',
        'kucoin.com',
        'okx.com',
        'bybit.com',
        'crypto.com',
        'bitstamp.net',
        'huobi.com',
        'gate.io',
        
        # Wallets
        'metamask.io',
        'rainbow.me',
        'phantom.app',
        'trustwallet.com',
        'ledger.com',
        'trezor.io',
        'exodus.com',
        'argent.xyz',
        'gnosis-safe.io', 'app.safe.global', 'safe.global',
        
        # Infrastructure
        'etherscan.io',
        'polygonscan.com',
        'bscscan.com',
        'arbiscan.io',
        'optimistic.etherscan.io',
        'basescan.org',
        'infura.io',
        'alchemy.com',
        'chainlink.com',
        'thegraph.com',
        'moralis.io',
        'quicknode.com',
        
        # Analytics/Tools
        'dextools.io',
        'dexscreener.com',
        'coingecko.com',
        'coinmarketcap.com',
        'defillama.com',
        'dune.com',
        'nansen.ai',
        'zapper.fi',
        'zerion.io',
        'debank.com',
        'tokenterminal.com',
        
        # Bridges
        'bridge.arbitrum.io',
        'app.optimism.io',
        'portal.polygon.technology',
        'stargate.finance',
        'across.to',
        'hop.exchange',
        'cbridge.celer.network',
        
        # Staking/Liquid
        'lido.fi',
        'rocketpool.net',
        'frax.finance',
        'stakewise.io',
        'eigenlayer.xyz',
        
        # ENS & Identity
        'ens.domains',
        'app.ens.domains',
        'unstoppabledomains.com',
        
        # DAO & Governance
        'snapshot.org',
        'tally.xyz',
        'boardroom.io',
        
        # Other trusted
        'guild.xyz',
        'mirror.xyz',
        'paragraph.xyz',
        'gitcoin.co',
        'ethereum.org',
        'polygon.technology',
        'arbitrum.io',
        'optimism.io',
        'base.org',
        'scroll.io',
        'zksync.io',
        'linea.build',
        
        # General
        'github.com',
        'google.com',
        'youtube.com',
        'twitter.com', 'x.com',
        'discord.com',
        'telegram.org',
        'reddit.com',
        'medium.com',
        'substack.com',
        'notion.so',
    }
    
    # Check if domain is in trusted list
    is_trusted_domain = domain in TRUSTED_DOMAINS or any(domain.endswith('.' + td) for td in TRUSTED_DOMAINS)
    
    if is_trusted_domain:
        risks['is_verified_dapp'] = True
        risks['flags'].append(f"✓ Trusted Domain: {domain}")
        risks['score'] = 0
        risks['verdict'] = 'SAFE'
        return risks
    
    # ============================================================
    # ML MODEL PREDICTION
    # ============================================================
    ml_score = 0
    features = {}  # Initialize features outside try block
    
    if website_model is not None and website_scaler is not None:
        try:
            features = extract_website_features(url)
            feature_vector = [features.get(f, 0) for f in website_feature_names]
            feature_scaled = website_scaler.transform([feature_vector])
            
            prediction = website_model.predict(feature_scaled)[0]
            probability = website_model.predict_proba(feature_scaled)[0][1]
            
            ml_score = int(probability * 100)
            
            # Generate detailed ML explanation
            ml_explanation = generate_website_ml_explanation(features, probability, url)
            
            risks['ml_prediction'] = {
                'is_phishing': bool(prediction),
                'confidence': float(probability),
                'score': ml_score,
                'analysis': ml_explanation
            }
            
            if prediction == 1:
                risks['flags'].append(f"🤖 ML Model: Phishing detected (confidence: {probability:.1%})")
            else:
                risks['flags'].append(f"🤖 ML Model: Appears safe (confidence: {1-probability:.1%})")
            
            print(f"[ML] URL: {url[:50]}... -> Score: {ml_score}, Phishing: {prediction}")
        except Exception as e:
            print(f"[ERROR] ML prediction failed: {e}")
            ml_score = 25  # Default to cautious if ML fails
            # Still try to extract features for typosquat detection
            try:
                features = extract_website_features(url)
            except:
                pass
    else:
        print("[WARN] Website model not loaded, using heuristic fallback")
        ml_score = 25
    
    # Base score from ML model
    risks['score'] = ml_score
    
    # ============================================================
    # TYPOSQUATTING DETECTION BOOST
    # ============================================================
    # If typosquatting is detected via the legit domains database,
    # this should significantly increase the risk score
    if features.get('is_typosquat', 0) == 1:
        legit_info = features.get('legit_info', {})
        detected_domain = features.get('detected_brand', 'unknown')
        brand_name = legit_info.get('name', detected_domain) if legit_info else detected_domain
        official_url = legit_info.get('official', '') if legit_info else ''
        
        risks['score'] = max(risks['score'], 85)  # Typosquatting = high risk
        risks['is_typosquat'] = True
        risks['impersonating'] = {
            'domain': detected_domain,
            'brand': brand_name,
            'official_url': official_url,
            'info': legit_info
        }
        risks['flags'].append(f'⚠️ TYPOSQUATTING: Impersonating {brand_name} ({detected_domain})')
        print(f"[TYPOSQUAT] {url} -> Impersonating {brand_name} ({detected_domain})")
    
    # If this is a verified legitimate domain, set score to 0
    if features.get('is_legitimate', 0) == 1:
        legit_info = features.get('legit_info', {})
        risks['score'] = 0
        risks['is_legitimate'] = True
        risks['flags'].append(f'✓ Verified legitimate domain: {legit_info.get("name", "Known site")}')
        print(f"[LEGIT] {url} -> Verified as {legit_info.get('name', 'legitimate')}")
    
    # ============================================================
    # GOPLUS API VERIFICATION (additional signals)
    # ============================================================
    
    # 1. Check if it's a known phishing site in GoPlus database
    phishing_result = get_goplus_phishing_site(url)
    if phishing_result:
        risks['raw']['phishing'] = phishing_result
        if phishing_result.get('phishing_site') == 1:
            risks['is_phishing'] = True
            risks['score'] = 100
            risks['flags'].append('🚨 KNOWN PHISHING SITE (GoPlus database)')
            risks['verdict'] = 'DANGEROUS'
            return risks  # Immediate danger
        
        # Check contracts associated with the site
        site_contracts = phishing_result.get('website_contract_security', [])
        for contract in site_contracts:
            if contract.get('is_malicious_contract') == 1:
                risks['flags'].append(f"⚠️ Malicious Contract: {contract.get('contract_address', 'unknown')[:10]}...")
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
        
        # Positive signals - verified dApp OVERRIDES ML score
        if dapp_result.get('trust_list') == 1:
            risks['is_verified_dapp'] = True
            risks['flags'].append(f"✓ Verified dApp: {dapp_result.get('project_name', 'Unknown')}")
            risks['score'] = 0  # Verified = safe
        
        if dapp_result.get('is_audit') == 1:
            risks['is_audited'] = True
            audit_info = dapp_result.get('audit_info', [])
            if audit_info:
                firms = [a.get('audit_firm', '') for a in audit_info[:3]]
                risks['flags'].append(f"✓ Audited by: {', '.join(firms)}")
            risks['score'] = max(0, risks['score'] - 30)
        
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
    
    # Determine final verdict based on score
    if risks['score'] >= 70:
        risks['verdict'] = 'DANGEROUS'
    elif risks['score'] >= 50:
        risks['verdict'] = 'SUSPICIOUS'
    elif risks['score'] >= 25:
        risks['verdict'] = 'CAUTION'
    else:
        risks['verdict'] = 'SAFE'
    
    return risks


def extract_website_features(url):
    """
    Extract features from a URL for ML classification.
    Mirrors the feature extraction in train_website_model.py
    """
    from urllib.parse import urlparse
    
    # Suspicious keywords commonly found in phishing URLs
    SUSPICIOUS_KEYWORDS = [
        'airdrop', 'claim', 'free', 'bonus', 'reward', 'giveaway',
        'verify', 'validate', 'confirm', 'secure', 'update', 'sync',
        'connect-wallet', 'wallet-connect', 'walletconnect',
        'recover', 'restore', 'unlock', 'login', 'signin',
        'metamask', 'trustwallet', 'coinbase', 'binance',
        'mint', 'drop', 'presale', 'whitelist',
    ]
    
    # Brand keywords for typosquatting detection
    # NOTE: Brand keywords and typosquatting detection are now handled
    # by the legit_domains.py database - see check_typosquat() function
    
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.click', '.link', '.online', '.site', '.website', '.app', '.io']
    SAFE_TLDS = ['.com', '.org', '.net', '.co', '.finance', '.exchange']
    
    features = {}
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        path = parsed.path.lower()
        full_url = url.lower()
        
        # Basic URL features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['num_subdomains'] = domain.count('.') 
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_port'] = 1 if parsed.port else 0
        
        # Special character counts
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_at'] = url.count('@')
        features['num_ampersand'] = url.count('&')
        features['num_equals'] = url.count('=')
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_params'] = full_url.count('?') + full_url.count('&')
        
        # Digit ratio in domain
        features['digit_ratio_domain'] = sum(c.isdigit() for c in domain) / max(len(domain), 1)
        
        # TLD analysis
        tld = '.' + domain.split('.')[-1] if '.' in domain else ''
        features['has_suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0
        features['has_safe_tld'] = 1 if tld in SAFE_TLDS else 0
        
        # Keyword analysis
        suspicious_keyword_count = 0
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in full_url:
                suspicious_keyword_count += 1
        features['suspicious_keyword_count'] = suspicious_keyword_count
        features['has_suspicious_keywords'] = 1 if suspicious_keyword_count > 0 else 0
        
        # Brand impersonation detection using legitimate domains database
        brand_in_url = 0
        typosquat_detected = 0
        detected_brand = None
        legit_info = None
        
        # Use the legitimate domains database for typosquat detection
        typosquat_result = check_typosquat(domain)
        
        if typosquat_result['is_legitimate']:
            # This is a legitimate domain
            features['is_legitimate'] = 1
            legit_info = typosquat_result['legit_info']
        elif typosquat_result['is_typosquat']:
            # This is a typosquat!
            typosquat_detected = 1
            brand_in_url = 1
            detected_brand = typosquat_result['matched_domain']
            legit_info = typosquat_result['legit_info']
            features['is_legitimate'] = 0
        else:
            features['is_legitimate'] = 0
        
        features['brand_impersonation_count'] = brand_in_url
        features['has_brand_impersonation'] = 1 if brand_in_url > 0 else 0
        features['is_typosquat'] = 1 if typosquat_detected > 0 else 0
        features['detected_brand'] = detected_brand
        features['legit_info'] = legit_info
        
        # Path analysis
        features['has_claim_path'] = 1 if any(kw in path for kw in ['claim', 'airdrop', 'reward', 'bonus', 'free']) else 0
        features['has_connect_path'] = 1 if any(kw in path for kw in ['connect', 'wallet', 'sync', 'verify']) else 0
        
        # Domain patterns
        features['has_dash_in_domain'] = 1 if '-' in domain.split('.')[0] else 0
        features['has_number_in_domain'] = 1 if any(c.isdigit() for c in domain.split('.')[0]) else 0
        
        # Length-based features
        features['is_long_domain'] = 1 if len(domain) > 25 else 0
        features['is_very_long_url'] = 1 if len(url) > 75 else 0
        
        # Entropy of domain
        domain_chars = domain.replace('.', '')
        if len(domain_chars) > 0:
            char_freq = {}
            for c in domain_chars:
                char_freq[c] = char_freq.get(c, 0) + 1
            entropy = -sum((f/len(domain_chars)) * np.log2(f/len(domain_chars)) for f in char_freq.values())
            features['domain_entropy'] = entropy
        else:
            features['domain_entropy'] = 0
            
        # Suspicious combinations
        features['suspicious_combo'] = 1 if (
            features['has_suspicious_keywords'] and features['has_suspicious_tld']
        ) or (
            features['brand_impersonation_count'] > 0 and features['has_dash_in_domain']
        ) else 0
        
    except Exception as e:
        print(f"[ERROR] Feature extraction failed for {url}: {e}")
        features = {name: 0 for name in [
            'url_length', 'domain_length', 'path_length', 'num_subdomains',
            'has_https', 'has_port', 'num_dots', 'num_hyphens', 'num_underscores',
            'num_slashes', 'num_at', 'num_ampersand', 'num_equals', 'num_digits',
            'num_params', 'digit_ratio_domain', 'has_suspicious_tld', 'has_safe_tld',
            'suspicious_keyword_count', 'has_suspicious_keywords',
            'brand_impersonation_count', 'has_brand_impersonation',
            'has_claim_path', 'has_connect_path', 'has_dash_in_domain',
            'has_number_in_domain', 'is_long_domain', 'is_very_long_url',
            'domain_entropy', 'suspicious_combo'
        ]}
    
    return features


def generate_website_ml_explanation(features, phishing_probability, url):
    """
    Generate human-readable explanation for website ML prediction.
    Analyzes which URL features contributed most to the risk assessment.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.lower().replace('www.', '')
    
    explanation = {
        'risk_score': int(phishing_probability * 100),
        'confidence': float(phishing_probability if phishing_probability > 0.5 else 1 - phishing_probability),
        'verdict': 'SUSPICIOUS' if phishing_probability >= 0.5 else 'LIKELY SAFE',
        'risk_factors': [],
        'safe_factors': [],
        'feature_analysis': [],
        'summary': ''
    }
    
    # Analyze features and build explanations
    risk_factors = []
    safe_factors = []
    
    # 1. Brand impersonation check
    if features.get('has_brand_impersonation', 0) == 1:
        brand_count = features.get('brand_impersonation_count', 0)
        risk_factors.append({
            'factor': 'Brand Impersonation Detected',
            'description': f'Domain contains {brand_count} known brand name(s) but is NOT an official site. Scammers often use brand names to appear legitimate.',
            'importance': 'critical',
            'value': f'{brand_count} brand(s) detected'
        })
    
    # 2. Suspicious keywords
    if features.get('has_suspicious_keywords', 0) == 1:
        keyword_count = features.get('suspicious_keyword_count', 0)
        risk_factors.append({
            'factor': 'Suspicious Keywords in URL',
            'description': f'URL contains {keyword_count} scam-related keyword(s) like "airdrop", "claim", "free", "bonus", "verify" which are commonly used in phishing.',
            'importance': 'high',
            'value': f'{keyword_count} suspicious keyword(s)'
        })
    
    # 3. Suspicious TLD
    if features.get('has_suspicious_tld', 0) == 1:
        risk_factors.append({
            'factor': 'High-Risk Domain Extension',
            'description': 'Domain uses a TLD (.xyz, .tk, .ml, etc.) commonly abused by scammers due to low cost and minimal verification requirements.',
            'importance': 'medium',
            'value': domain.split('.')[-1] if '.' in domain else 'unknown'
        })
    
    # 4. Dash in domain (common in phishing)
    if features.get('has_dash_in_domain', 0) == 1 and features.get('num_hyphens', 0) >= 2:
        risk_factors.append({
            'factor': 'Multiple Hyphens in Domain',
            'description': f'Domain contains {features.get("num_hyphens", 0)} hyphens. Legitimate sites rarely use multiple hyphens; phishing sites like "uniswap-airdrop-claim.com" do.',
            'importance': 'medium',
            'value': f'{features.get("num_hyphens", 0)} hyphens'
        })
    
    # 5. Suspicious path patterns
    if features.get('has_claim_path', 0) == 1:
        risk_factors.append({
            'factor': 'Claim/Airdrop Path Detected',
            'description': 'URL path contains words like "claim", "airdrop", or "reward" which are common in phishing sites designed to steal wallet approvals.',
            'importance': 'high',
            'value': 'claim/airdrop path'
        })
    
    if features.get('has_connect_path', 0) == 1:
        risk_factors.append({
            'factor': 'Wallet Connect Path',
            'description': 'URL path contains "connect" or "wallet" terms, which may be used to direct users to wallet drainer pages.',
            'importance': 'medium',
            'value': 'connect/wallet path'
        })
    
    # 6. Very long URL (common in phishing to hide malicious parts)
    if features.get('is_very_long_url', 0) == 1:
        risk_factors.append({
            'factor': 'Unusually Long URL',
            'description': f'URL is {features.get("url_length", 0)} characters. Extremely long URLs are often used to hide suspicious parameters or confuse users.',
            'importance': 'low',
            'value': f'{features.get("url_length", 0)} characters'
        })
    
    # 7. Numbers in domain
    if features.get('has_number_in_domain', 0) == 1:
        risk_factors.append({
            'factor': 'Numbers in Domain',
            'description': 'Domain contains numbers, which is uncommon for legitimate sites but common in typosquatting (e.g., "un1swap" instead of "uniswap").',
            'importance': 'low',
            'value': f'{features.get("num_digits", 0)} digits in URL'
        })
    
    # 8. Suspicious combo (brand + dash + suspicious keyword)
    if features.get('suspicious_combo', 0) == 1:
        risk_factors.append({
            'factor': 'High-Risk Pattern Combination',
            'description': 'URL combines brand impersonation with hyphens and suspicious structure - a common pattern in sophisticated phishing attacks.',
            'importance': 'critical',
            'value': 'Multiple risk indicators combined'
        })
    
    # 9. Typosquatting detection using legitimate domains database
    if features.get('is_typosquat', 0) == 1:
        detected = features.get('detected_brand', 'unknown')
        legit_info = features.get('legit_info', {})
        brand_name = legit_info.get('name', detected) if legit_info else detected
        official_url = legit_info.get('official', '') if legit_info else ''
        
        risk_factors.append({
            'factor': 'Typosquatting Detected',
            'description': f'This domain is impersonating "{brand_name}" using character substitutions or similar spelling. This is a common phishing technique. The official site is: {official_url}',
            'importance': 'critical',
            'value': f'Impersonating "{brand_name}"',
            'official_domain': detected,
            'official_url': official_url,
            'brand_info': legit_info
        })
    
    # ===== SAFE FACTORS =====
    
    # 0. Verified legitimate domain
    if features.get('is_legitimate', 0) == 1:
        legit_info = features.get('legit_info', {})
        safe_factors.append({
            'factor': 'Verified Legitimate Domain',
            'description': f'This is a known legitimate domain for {legit_info.get("name", "this service")}.',
            'importance': 'high',
            'value': legit_info.get('name', 'Verified')
        })
    
    # 1. Safe TLD
    if features.get('has_safe_tld', 0) == 1:
        safe_factors.append({
            'factor': 'Trusted Domain Extension',
            'description': 'Domain uses a reputable TLD (.com, .org, .net, .finance) which has higher registration standards.',
            'importance': 'medium',
            'value': domain.split('.')[-1] if '.' in domain else 'unknown'
        })
    
    # 2. HTTPS
    if features.get('has_https', 0) == 1:
        safe_factors.append({
            'factor': 'Secure Connection (HTTPS)',
            'description': 'Site uses HTTPS encryption. Note: while necessary, HTTPS alone doesn\'t guarantee a site is legitimate.',
            'importance': 'low',
            'value': 'HTTPS enabled'
        })
    
    # 3. Clean domain (no suspicious patterns)
    if (features.get('has_suspicious_keywords', 0) == 0 and 
        features.get('has_brand_impersonation', 0) == 0 and
        features.get('has_suspicious_tld', 0) == 0):
        safe_factors.append({
            'factor': 'Clean URL Structure',
            'description': 'No suspicious keywords, brand impersonation attempts, or high-risk TLDs detected in the URL.',
            'importance': 'medium',
            'value': 'No red flags in URL'
        })
    
    # 4. Simple domain
    if features.get('num_subdomains', 0) <= 1 and features.get('domain_length', 0) < 20:
        safe_factors.append({
            'factor': 'Simple Domain Structure',
            'description': f'Domain is {features.get("domain_length", 0)} characters with minimal subdomains - typical of legitimate sites.',
            'importance': 'low',
            'value': f'{features.get("domain_length", 0)} chars, {features.get("num_subdomains", 0)} subdomain(s)'
        })
    
    # Build explanation
    explanation['risk_factors'] = risk_factors[:6]  # Top risk factors
    explanation['safe_factors'] = safe_factors[:4]  # Top safe factors
    
    # Generate summary
    if phishing_probability >= 0.7:
        explanation['summary'] = f"High phishing risk detected (ML confidence: {phishing_probability:.0%}). The URL exhibits multiple characteristics commonly found in scam websites."
        explanation['recommendation'] = "Do NOT connect your wallet. This URL has strong indicators of being a phishing attempt."
    elif phishing_probability >= 0.4:
        explanation['summary'] = f"Moderate risk detected (ML confidence: {phishing_probability:.0%}). Some URL characteristics warrant caution."
        explanation['recommendation'] = "Proceed with extreme caution. Verify the URL through official channels before connecting your wallet."
    else:
        explanation['summary'] = f"Low risk based on URL analysis (ML confidence: {1-phishing_probability:.0%}). URL structure appears consistent with legitimate sites."
        explanation['recommendation'] = "URL appears safe, but always verify you're on the official site and never share your seed phrase."
    
    # Feature analysis for technical users
    explanation['feature_analysis'] = [
        f"URL Length: {features.get('url_length', 0)} chars",
        f"Domain Length: {features.get('domain_length', 0)} chars",
        f"Subdomains: {features.get('num_subdomains', 0)}",
        f"Special Characters: {features.get('num_hyphens', 0)} hyphens, {features.get('num_dots', 0)} dots",
        f"Suspicious Keywords: {features.get('suspicious_keyword_count', 0)} found",
        f"Brand Names: {features.get('brand_impersonation_count', 0)} detected"
    ]
    
    return explanation


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


def generate_ml_explanation(features, fraud_probability, feature_names, model):
    """
    Generate human-readable explanation for ML model prediction.
    Analyzes which features contributed most to the risk assessment.
    """
    explanation = {
        'risk_score': int(fraud_probability * 100),
        'confidence': float(fraud_probability if fraud_probability > 0.5 else 1 - fraud_probability),
        'verdict': 'SUSPICIOUS' if fraud_probability >= 0.5 else 'LIKELY SAFE',
        'key_factors': [],
        'behavioral_analysis': [],
        'summary': ''
    }
    
    # Feature importance from model (if Random Forest)
    feature_importance = {}
    if hasattr(model, 'feature_importances_'):
        for fname, imp in zip(feature_names, model.feature_importances_):
            feature_importance[fname] = imp
    
    # Analyze key risk indicators
    risk_factors = []
    safe_factors = []
    
    # 1. Transaction frequency analysis
    sent_txs = features.get('Sent tnx', 0)
    received_txs = features.get('Received Tnx', 0)
    total_txs = sent_txs + received_txs
    
    if total_txs < 5:
        risk_factors.append({
            'factor': 'Very Low Activity',
            'description': f'Only {total_txs} transactions recorded - new or disposable wallet pattern',
            'importance': 'medium',
            'value': total_txs
        })
    elif total_txs > 500:
        safe_factors.append({
            'factor': 'High Activity',
            'description': f'{total_txs} transactions indicate established usage',
            'importance': 'low',
            'value': total_txs
        })
    
    # 2. Transaction ratio (sent vs received)
    if received_txs > 0:
        ratio = sent_txs / received_txs
        if ratio > 5:
            risk_factors.append({
                'factor': 'Drainer Pattern',
                'description': f'Sends {ratio:.1f}x more than receives - typical of wallet drainers',
                'importance': 'high',
                'value': f'{sent_txs} sent / {received_txs} received'
            })
        elif ratio < 0.2 and total_txs > 10:
            risk_factors.append({
                'factor': 'Collection Address',
                'description': f'Mostly receives funds ({received_txs} in vs {sent_txs} out) - could be scam collection',
                'importance': 'medium',
                'value': f'{received_txs} received / {sent_txs} sent'
            })
    
    # 3. Time pattern analysis
    time_diff = features.get('Time Diff between first and last (Mins)', 0)
    avg_sent_interval = features.get('Avg min between sent tnx', 0)
    avg_recv_interval = features.get('Avg min between received tnx', 0)
    
    if time_diff < 60 and total_txs > 5:  # Less than 1 hour
        risk_factors.append({
            'factor': 'Burst Activity',
            'description': f'All {total_txs} transactions in {time_diff:.0f} minutes - automated/attack pattern',
            'importance': 'high',
            'value': f'{time_diff:.0f} minutes'
        })
    elif time_diff > 525600:  # Over 1 year
        safe_factors.append({
            'factor': 'Long History',
            'description': f'Account active for {time_diff/525600:.1f} years',
            'importance': 'medium',
            'value': f'{time_diff/525600:.1f} years'
        })
    
    # 4. Value analysis
    avg_received = features.get('avg val received', 0)
    avg_sent = features.get('avg val sent', 0)
    total_received = features.get('total ether received', 0)
    total_sent = features.get('total Ether sent', 0)
    
    if avg_received > 10 and received_txs < 5:
        risk_factors.append({
            'factor': 'Large Value Recipient',
            'description': f'Avg {avg_received:.2f} ETH per incoming tx with few transactions - potential scam proceeds',
            'importance': 'medium',
            'value': f'{avg_received:.2f} ETH avg'
        })
    
    if total_sent > 100 and features.get('total ether balance', 0) < 0.01:
        risk_factors.append({
            'factor': 'Cleaned Out',
            'description': f'Moved {total_sent:.1f} ETH with near-zero balance remaining',
            'importance': 'medium',
            'value': f'{total_sent:.1f} ETH sent'
        })
    
    # 5. Contract creation
    contracts_created = features.get('Number of Created Contracts', 0)
    if contracts_created > 3:
        risk_factors.append({
            'factor': 'Multiple Contracts',
            'description': f'Created {contracts_created} contracts - check if deploying honeypots/scams',
            'importance': 'medium',
            'value': contracts_created
        })
    
    # 6. ERC20 activity analysis
    erc20_sent_addrs = features.get(' ERC20 uniq sent addr', 0)
    erc20_rec_addrs = features.get(' ERC20 uniq rec addr', 0)
    
    if erc20_sent_addrs > 50 and erc20_rec_addrs < 5:
        risk_factors.append({
            'factor': 'Token Distribution',
            'description': f'Sent tokens to {erc20_sent_addrs} addresses but received from only {erc20_rec_addrs} - airdrop scam pattern',
            'importance': 'high',
            'value': f'{erc20_sent_addrs} recipients'
        })
    
    # Build summary
    explanation['key_factors'] = risk_factors[:5]  # Top 5 risk factors
    explanation['safe_factors'] = safe_factors[:3]  # Top 3 safe factors
    
    # Generate behavioral analysis summary
    if fraud_probability >= 0.7:
        explanation['summary'] = f"High risk address (ML confidence: {fraud_probability:.0%}). Multiple behavioral patterns match known fraud addresses."
        explanation['behavioral_analysis'] = [
            f"Transaction pattern analysis detected {len(risk_factors)} risk indicators",
            "Behavioral fingerprint similar to training data labeled as fraudulent",
            "Recommend avoiding any interaction with this address"
        ]
    elif fraud_probability >= 0.4:
        explanation['summary'] = f"Moderate risk detected (ML confidence: {fraud_probability:.0%}). Some unusual patterns warrant caution."
        explanation['behavioral_analysis'] = [
            "Mixed signals - some patterns match legitimate usage, others are concerning",
            "Recommend verifying through additional sources before interaction",
            f"Found {len(risk_factors)} potential warning signs"
        ]
    else:
        explanation['summary'] = f"Low risk based on behavioral analysis (ML confidence: {1-fraud_probability:.0%})"
        explanation['behavioral_analysis'] = [
            "Transaction patterns consistent with normal wallet usage",
            "No strong indicators of fraudulent activity detected",
            "Standard due diligence still recommended"
        ]
    
    return explanation

# ============================================================
# PREDICTION
# ============================================================

def predict_risk(address):
    """
    Main function to predict risk score for an address.
    Combines ML model + GoPlus Security API + Contract Source Analysis for comprehensive detection.
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
        'contract_analysis': None,
    }
    
    # 1. GoPlus Security Analysis (always run - catches honeypots, scams)
    print(f"[INFO] Querying GoPlus Security for {address}...")
    goplus_risks = analyze_goplus_risks(address)
    result['goplus_flags'] = goplus_risks['flags']
    result['is_honeypot'] = goplus_risks['is_honeypot']
    result['is_contract'] = goplus_risks['is_contract']
    result['components']['goplus_score'] = goplus_risks['score']
    result['goplus_risks'] = goplus_risks  # Include full GoPlus data for frontend
    
    # 2. Contract Source Code Analysis - ALWAYS check for verified source
    # Even if GoPlus flags address, it might be a honeypot contract with verified source
    contract_score = 0
    if ETHERSCAN_API_KEY:
        try:
            print(f"[CONTRACT] Checking for verified source code...")
            contract_analysis = analyze_contract_source(address)
            print(f"[CONTRACT] Analysis complete: has_source={contract_analysis.get('has_source')}")
            
            if contract_analysis.get('has_source'):
                result['contract_analysis'] = contract_analysis
                result['is_contract'] = True  # Override GoPlus if we have source code
                
                # Calculate contract risk score from findings
                summary = contract_analysis.get('summary', {})
                findings_list = contract_analysis.get('findings', [])
                
                print(f"[CONTRACT] GoPlus honeypot: {goplus_risks['is_honeypot']}, findings count: {len(findings_list)}")
                
                # SECONDARY ANALYSIS: If GoPlus detected honeypot but we found 0 patterns,
                # extract suspicious code sections to show user ACTUAL CODE
                if goplus_risks['is_honeypot'] and len(findings_list) == 0:
                    print(f"[CONTRACT] GoPlus honeypot detected but 0 findings. Extracting suspicious code sections...")
                    source_code = contract_analysis.get('full_source')
                    if source_code:
                        secondary_findings = extract_suspicious_code_sections(
                            source_code, 
                            contract_analysis.get('contract_name', 'Unknown')
                        )
                        if secondary_findings:
                            # Add these as low-confidence findings
                            result['contract_analysis']['findings'].extend(secondary_findings)
                            findings_list = result['contract_analysis']['findings']
                            print(f"[CONTRACT] Added {len(secondary_findings)} suspicious code sections for review")
                    else:
                        print(f"[CONTRACT] No source code available for extraction")
                
                # Check for specific critical patterns
                has_reverse_blacklist = any(f.get('pattern') == 'reverse_blacklist' for f in findings_list)
                has_quiz_honeypot = any(f.get('pattern') == 'quiz_honeypot' for f in findings_list)
                
                if summary.get('critical', 0) > 0:
                    contract_score = 95
                elif summary.get('high', 0) > 0:
                    contract_score = 80
                elif summary.get('medium', 0) > 0:
                    # Base score for medium findings
                    contract_score = 60
                    # Boost score for specific honeypot patterns
                    if has_reverse_blacklist:
                        contract_score = 85  # Reverse blacklist is definitive honeypot indicator
                    elif has_quiz_honeypot:
                        contract_score = 80  # Quiz honeypots are also definitive
                elif summary.get('low', 0) > 0:
                    contract_score = 40
                    
                print(f"[CONTRACT] Risk score from source analysis: {contract_score}")
                if has_reverse_blacklist:
                    print(f"[CONTRACT] ⚠️ REVERSE BLACKLIST HONEYPOT DETECTED")
                
        except Exception as e:
            import traceback
            print(f"[ERROR] Contract analysis failed: {e}")
            print(traceback.format_exc())
            result['contract_analysis'] = None
    
    # 3. ML Model Analysis (for transaction pattern detection)
    ml_score = None
    ml_analysis = None
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
            
            # Generate ML explanation based on feature analysis
            ml_analysis = generate_ml_explanation(features, fraud_probability, feature_names, model)
            result['ml_analysis'] = ml_analysis
            
        except Exception as e:
            print(f"[ERROR] ML prediction failed: {e}")
    
    # 4. Combine scores intelligently with multi-layer boosting
    # - Contract analysis has highest priority (actual source code evidence)
    # - GoPlus is authoritative for flagged addresses (honeypots, scams)  
    # - ML is supplementary - only trust high ML scores when GoPlus also has concerns
    # - Multiple detection methods = higher confidence and score boost
    
    goplus_score = goplus_risks['score']
    
    # Start with base score (highest individual detection)
    base_score = max(goplus_score, contract_score)
    
    # Calculate multi-layer boost
    detection_layers = 0
    boost = 0
    
    if goplus_score >= 50:
        detection_layers += 1
    if contract_score >= 50:
        detection_layers += 1
    if ml_score is not None and ml_score >= 60:
        detection_layers += 1
    
    # Boost score when multiple methods agree
    if detection_layers >= 3:
        boost = 10  # All 3 methods agree - very high confidence
    elif detection_layers == 2:
        boost = 5   # 2 methods agree - high confidence
    
    final_score = min(100, base_score + boost)
    
    # Determine primary reason for score
    if contract_score >= goplus_score and contract_score > 0:
        # Contract source code is primary concern
        result['score'] = final_score
        result['primary_detection'] = 'contract_source'
        if result.get('contract_analysis', {}).get('summary'):
            summary = result['contract_analysis']['summary']
            severity_counts = []
            if summary.get('critical', 0) > 0:
                severity_counts.append(f"{summary['critical']} critical")
            if summary.get('high', 0) > 0:
                severity_counts.append(f"{summary['high']} high")
            if summary.get('medium', 0) > 0:
                severity_counts.append(f"{summary['medium']} medium")
            result['reason'] = f"Source code analysis: {', '.join(severity_counts)} risk patterns detected"
            if boost > 0:
                result['reason'] += f" ({detection_layers} detection methods agree)"
    elif goplus_score >= 50:
        # GoPlus found issues
        result['score'] = final_score
        result['primary_detection'] = 'goplus'
        if contract_score > 0:
            # Both GoPlus AND source code found issues - very high confidence
            result['reason'] = f"GoPlus flagged: {', '.join(goplus_risks['flags'][:3])} + Source code patterns detected"
            if boost > 0:
                result['reason'] += f" (+{boost} multi-layer boost)"
        else:
            result['reason'] = f"GoPlus flagged: {', '.join(goplus_risks['flags'][:3])}"
            
        # ML can boost confidence if it agrees
        if ml_score is not None and ml_score >= 70:
            result['confidence'] = 0.95
    elif contract_score > 0:
        # Only contract analysis found issues (GoPlus clean)
        result['score'] = contract_score
        result['primary_detection'] = 'contract_source'
        result['reason'] = "Malicious patterns detected in verified source code"
    elif ml_score is not None and ml_score >= 85:
        # ML very confident but GoPlus clean - be cautious, not alarming
        # Could be a new scam not yet in GoPlus, OR a false positive
        result['score'] = int(ml_score * 0.35)  # Reduce significantly
        result['ml_warning'] = True
        result['primary_detection'] = 'ml_model'
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

@app.route('/analyze-code')
def analyze_code_endpoint():
    """
    Analyze website source code for wallet drainer patterns.
    
    This endpoint fetches the actual JavaScript/HTML from a website
    and scans it for malicious patterns like:
    - setApprovalForAll() calls (NFT drainers)
    - approve() with unlimited amounts (ERC20 drainers)
    - eth_sign / personal_sign abuse
    - permit() signatures (gasless drainers)
    - Obfuscated code patterns
    - Known drainer kit signatures (Inferno, Pink, Angel)
    
    Query params:
        - url: The website URL to analyze (required)
    
    Returns:
        - findings: Array of detected malicious patterns
        - risk_level: CRITICAL, HIGH, MEDIUM, LOW, or CLEAN
        - summary: Count by severity level
    """
    url = request.args.get('url', '')
    use_browser = request.args.get('browser', 'false').lower() == 'true'
    
    if not url:
        return jsonify({'error': 'URL parameter required. Usage: /analyze-code?url=https://example.com'}), 400
    
    # Normalize URL
    if not url.startswith('http'):
        url = 'https://' + url
    
    start_time = time.time()
    
    try:
        # Use browser-based analyzer if requested
        if use_browser:
            from browser_analyzer import analyze_website_sync
            result = analyze_website_sync(url)
            result['method'] = 'browser'
        else:
            result = analyze_website_code(url)
            
            # If simple request failed for any reason, try browser fallback
            error_msg = str(result.get('error', '')).lower()
            needs_browser = (
                result.get('error') and 
                any(x in error_msg for x in [
                    'could not connect', 
                    'forbidden', 
                    'timed out',
                    'ssl',
                    '403',
                    'connection refused',
                    'dns resolution'
                ])
            )
            
            if needs_browser:
                try:
                    print(f"[API] Simple request failed, trying browser mode for: {url}")
                    from browser_analyzer import analyze_website_sync
                    result = analyze_website_sync(url)
                    result['fallback'] = 'Used browser after HTTP request failed'
                    result['method'] = 'browser'
                except Exception as e:
                    print(f"[API] Browser fallback also failed: {e}")
                    # Keep original error but note we tried
                    result['browser_attempted'] = True
                    result['browser_error'] = str(e)
        
        result['processing_time_ms'] = int((time.time() - start_time) * 1000)
        return jsonify(result)
    except Exception as e:
        print(f"[ERROR] Code analysis failed: {e}")
        return jsonify({
            'error': str(e),
            'url': url,
            'status': 'error'
        }), 500

@app.route('/analyze-browser')
def analyze_browser_endpoint():
    """
    Analyze website using a REAL browser (Playwright/Chromium).
    
    This endpoint:
    - Actually loads the page in a headless Chrome browser
    - Executes JavaScript
    - Bypasses basic bot detection
    - Gets dynamically loaded scripts
    
    Use this when /analyze-code fails with "Could not connect"
    
    Query params:
        - url: The website URL to analyze (required)
    """
    url = request.args.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    
    if not url.startswith('http'):
        url = 'https://' + url
    
    start_time = time.time()
    
    try:
        from browser_analyzer import analyze_website_sync
        result = analyze_website_sync(url)
        result['processing_time_ms'] = int((time.time() - start_time) * 1000)
        return jsonify(result)
    except ImportError:
        return jsonify({
            'error': 'Browser analyzer not available. Install: pip install playwright && playwright install chromium',
            'url': url
        }), 500
    except Exception as e:
        print(f"[ERROR] Browser analysis failed: {e}")
        return jsonify({
            'error': str(e),
            'url': url,
            'status': 'error'
        }), 500


# ============================================================
# HONEYPOT RUNTIME SIMULATION
# ============================================================

@app.route('/simulate/<address>', methods=['GET'])
def simulate_honeypot(address):
    """
    Runtime honeypot detection via transaction simulation.
    More reliable than static source code analysis.
    
    Requires: Ganache/Hardhat fork running on localhost:8545
    Setup: ganache --fork https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY --port 8545
    
    Returns:
        {
            'is_honeypot': bool,
            'confidence': int (0-100),
            'reason': str,
            'pattern': str,
            'buy_test': {...},
            'sell_test': {...},
            'malicious_code': [{...}]  # If honeypot detected
        }
    """
    try:
        from honeypot_simulator import HoneypotSimulator
        
        # Validate address
        if not address.startswith('0x') or len(address) != 42:
            return jsonify({'error': 'Invalid Ethereum address'}), 400
        
        print(f"\n[SIMULATE] Starting runtime simulation for {address}")
        
        # Initialize simulator with Etherscan key for source analysis
        simulator = HoneypotSimulator(
            etherscan_key=ETHERSCAN_API_KEY,
            verbose=True
        )
        
        # Run full simulation (buy -> sell -> analyze source if honeypot)
        result = simulator.analyze(address)
        
        # Add metadata
        result['method'] = 'RUNTIME_SIMULATION'
        result['note'] = 'Tests actual transaction behavior, then analyzes source code if honeypot detected'
        
        if result.get('is_honeypot'):
            print(f"[SIMULATE] ✗ HONEYPOT DETECTED - {result['pattern']}")
            if result.get('malicious_code'):
                print(f"[SIMULATE] Found {len(result['malicious_code'])} malicious code pattern(s)")
        elif result.get('is_honeypot') is False:
            print(f"[SIMULATE] ✓ Token appears safe")
        else:
            print(f"[SIMULATE] ? Simulation inconclusive")
        
        return jsonify(result)
        
    except ConnectionError as e:
        return jsonify({
            'error': str(e),
            'setup_required': True,
            'instructions': [
                '1. Install Ganache: npm install -g ganache',
                '2. Get Alchemy key: https://www.alchemy.com/',
                '3. Run: ganache --fork https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY --port 8545'
            ]
        }), 503
        
    except ImportError:
        return jsonify({
            'error': 'Honeypot simulator not available. Install: pip install web3 eth-account',
        }), 500
        
    except Exception as e:
        print(f"[ERROR] Simulation failed: {e}")
        return jsonify({
            'error': str(e),
            'address': address,
            'status': 'error'
        }), 500


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
    # Use threaded=True for better responsiveness
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)

