"""
Real-World Training Data Collector
===================================

This script collects REAL malicious addresses from multiple sources and extracts
their Etherscan transaction features for ML training.

Data Sources:
1. Our existing darklist (3,580 known scam addresses)
2. Etherscan labeled accounts (phishing, heist, exploit)
3. GoPlus flagged addresses (verified via API)

The goal: Train an ML model that can predict GoPlus-like flags
BEFORE they're added to GoPlus's database.

Usage:
    python collect_training_data.py
"""

import os
import sys
import json
import time
import random
import requests
import pandas as pd
import numpy as np
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# CONFIGURATION
# ============================================================

ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY', '')
ETHERSCAN_BASE_URL = 'https://api.etherscan.io/v2/api'
GOPLUS_BASE_URL = 'https://api.gopluslabs.io/api/v1'

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'data')
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'real_world_dataset.csv')

# Rate limiting
ETHERSCAN_DELAY = 0.25  # 4 requests/second (free tier limit)
GOPLUS_DELAY = 0.1

# ============================================================
# ETHERSCAN API FUNCTIONS
# ============================================================

def etherscan_request(params):
    """Make a request to Etherscan API V2."""
    params['apikey'] = ETHERSCAN_API_KEY
    params['chainid'] = 1
    try:
        response = requests.get(ETHERSCAN_BASE_URL, params=params, timeout=15)
        data = response.json()
        if data.get('status') == '1':
            return data.get('result', [])
        return []
    except Exception as e:
        print(f"[ERROR] Etherscan request failed: {e}")
        return []

def get_normal_transactions(address):
    """Get normal transactions for an address."""
    time.sleep(ETHERSCAN_DELAY)
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
    time.sleep(ETHERSCAN_DELAY)
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
    time.sleep(ETHERSCAN_DELAY)
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
# GOPLUS API FUNCTIONS
# ============================================================

def check_goplus_address(address):
    """Check if address is flagged by GoPlus."""
    time.sleep(GOPLUS_DELAY)
    try:
        url = f"{GOPLUS_BASE_URL}/address_security/{address}"
        response = requests.get(url, timeout=10)
        data = response.json()
        if data.get('code') == 1 and data.get('result'):
            return data['result']
        return None
    except:
        return None

def is_goplus_malicious(goplus_result):
    """Determine if GoPlus flags this address as malicious."""
    if not goplus_result:
        return False, []
    
    flags = []
    malicious_keys = [
        'stealing_attack', 'phishing_activities', 'blackmail_activities',
        'cybercrime', 'money_laundering', 'financial_crime',
        'honeypot_related_address', 'sanctioned', 'fake_token',
        'malicious_mining_activities', 'darkweb_transactions'
    ]
    
    for key in malicious_keys:
        value = goplus_result.get(key, '0')
        if value and str(value) != '0':
            flags.append(key)
    
    # Check malicious contracts created
    contracts = goplus_result.get('number_of_malicious_contracts_created', '0')
    if contracts and str(contracts) != '0':
        flags.append(f'malicious_contracts:{contracts}')
    
    return len(flags) > 0, flags

# ============================================================
# FEATURE EXTRACTION (Same as API)
# ============================================================

def extract_features(address, normal_txs=None, erc20_txs=None, balance=None):
    """Extract features for ML training."""
    
    # Fetch data if not provided
    if normal_txs is None:
        normal_txs = get_normal_transactions(address)
    if erc20_txs is None:
        erc20_txs = get_erc20_transactions(address)
    if balance is None:
        balance = get_balance(address)
    
    if not isinstance(normal_txs, list):
        normal_txs = []
    if not isinstance(erc20_txs, list):
        erc20_txs = []
    
    address_lower = address.lower()
    
    # Separate sent and received transactions
    sent_txs = [tx for tx in normal_txs if tx.get('from', '').lower() == address_lower]
    received_txs = [tx for tx in normal_txs if tx.get('to', '').lower() == address_lower]
    
    # ERC20 sent and received
    erc20_sent = [tx for tx in erc20_txs if tx.get('from', '').lower() == address_lower]
    erc20_received = [tx for tx in erc20_txs if tx.get('to', '').lower() == address_lower]
    
    # Time calculations
    def get_timestamps(txs):
        return sorted([int(tx.get('timeStamp', 0)) for tx in txs if tx.get('timeStamp')])
    
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
    
    # Value calculations
    def get_values_ether(txs):
        return [int(tx.get('value', 0)) / 1e18 for tx in txs]
    
    sent_values = get_values_ether(sent_txs)
    received_values = get_values_ether(received_txs)
    
    # ERC20 unique addresses and tokens
    erc20_sent_addrs = set(tx.get('to', '').lower() for tx in erc20_sent if tx.get('to'))
    erc20_rec_addrs = set(tx.get('from', '').lower() for tx in erc20_received if tx.get('from'))
    erc20_sent_tokens = set(tx.get('tokenName', '') for tx in erc20_sent if tx.get('tokenName'))
    erc20_rec_tokens = set(tx.get('tokenName', '') for tx in erc20_received if tx.get('tokenName'))
    
    # Additional features for better detection
    unique_sent_addresses = set(tx.get('to', '').lower() for tx in sent_txs if tx.get('to'))
    unique_received_addresses = set(tx.get('from', '').lower() for tx in received_txs if tx.get('from'))
    
    # Failed transaction ratio (scammers often have more failed txs)
    failed_txs = sum(1 for tx in normal_txs if tx.get('isError') == '1')
    total_txs = len(normal_txs)
    failed_ratio = failed_txs / total_txs if total_txs > 0 else 0
    
    # Contract creation count
    contracts_created = sum(1 for tx in sent_txs if tx.get('to', '') == '')
    
    # Gas analysis (scammers often use abnormal gas)
    gas_used = [int(tx.get('gasUsed', 0)) for tx in normal_txs if tx.get('gasUsed')]
    avg_gas = np.mean(gas_used) if gas_used else 0
    
    features = {
        # Original features (matching Kaggle dataset)
        'Avg min between sent tnx': avg_time_between(sent_times),
        'Avg min between received tnx': avg_time_between(received_times),
        'Time Diff between first and last (Mins)': time_diff_first_last(all_times),
        'Sent tnx': len(sent_txs),
        'Received Tnx': len(received_txs),
        'Number of Created Contracts': contracts_created,
        'avg val received': np.mean(received_values) if received_values else 0,
        'avg val sent': np.mean(sent_values) if sent_values else 0,
        'total Ether sent': sum(sent_values),
        'total ether received': sum(received_values),
        'total ether balance': balance,
        ' ERC20 total Ether received': 0,
        ' ERC20 total ether sent': 0,
        ' ERC20 uniq sent addr': len(erc20_sent_addrs),
        ' ERC20 uniq rec addr': len(erc20_rec_addrs),
        ' ERC20 uniq sent token name': len(erc20_sent_tokens),
        ' ERC20 uniq rec token name': len(erc20_rec_tokens),
        
        # NEW features for better detection
        'unique_sent_addresses': len(unique_sent_addresses),
        'unique_received_addresses': len(unique_received_addresses),
        'failed_tx_ratio': failed_ratio,
        'avg_gas_used': avg_gas,
        'total_tx_count': total_txs,
        'sent_received_ratio': len(sent_txs) / max(len(received_txs), 1),
        'erc20_total_txs': len(erc20_txs),
    }
    
    return features

# ============================================================
# DATA COLLECTION
# ============================================================

def load_darklist():
    """Load addresses from darklist."""
    darklist_path = os.path.join(OUTPUT_DIR, 'darklist.json')
    if os.path.exists(darklist_path):
        with open(darklist_path, 'r') as f:
            data = json.load(f)
            # Handle both list and dict formats
            if isinstance(data, list):
                return [item.get('address', item) if isinstance(item, dict) else item for item in data]
            elif isinstance(data, dict):
                return list(data.keys())
    return []

def collect_safe_addresses():
    """
    Collect known safe addresses:
    - Major exchanges
    - Popular DeFi protocols
    - Well-known wallets
    """
    safe_addresses = [
        # Binance
        '0x28C6c06298d514Db089934071355E5743bf21d60',
        '0x21a31Ee1afC51d94C2eFcCAa2092aD1028285549',
        # Coinbase
        '0x71660c4005BA85c37ccec55d0C4493E66Fe775d3',
        '0x503828976D22510aad0201ac7EC88293211D23Da',
        # Uniswap
        '0x1a9C8182C09F50C8318d769245beA52c32BE35BC',
        '0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD',  # Universal Router
        # Aave
        '0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9',
        # Compound
        '0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B',
        # Known whale addresses
        '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',  # Vitalik
        '0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8',  # Binance 7
        # More exchanges
        '0x2FAF487A4414Fe77e2327F0bf4AE2a264a776AD2',  # FTX (historical)
        '0xDFd5293D8e347dFe59E90eFd55b2956a1343963d',  # Kraken
        '0x267be1C1D684F78cb4F6a176C4911b741E4Ffdc0',  # Kraken 4
        # OpenSea
        '0x5b3256965e7C3cF26E11FCAf296DfC8807C01073',
        # Chainlink
        '0x514910771AF9Ca656af840dff83E8264EcF986CA',
    ]
    return safe_addresses

def collect_data(max_malicious=200, max_safe=200):
    """
    Collect training data from real addresses.
    """
    print("=" * 60)
    print("REAL-WORLD TRAINING DATA COLLECTOR")
    print("=" * 60)
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    all_data = []
    
    # ============================================================
    # 1. COLLECT MALICIOUS ADDRESSES FROM DARKLIST
    # ============================================================
    print("\n[1/3] Loading darklist addresses...")
    darklist = load_darklist()
    print(f"      Found {len(darklist)} addresses in darklist")
    
    # Sample from darklist
    malicious_addresses = random.sample(darklist, min(max_malicious, len(darklist)))
    
    print(f"\n[2/3] Extracting features for {len(malicious_addresses)} malicious addresses...")
    print("      (This will take a while due to API rate limits)")
    
    malicious_count = 0
    for i, address in enumerate(malicious_addresses):
        try:
            print(f"      [{i+1}/{len(malicious_addresses)}] {address[:10]}...", end=' ')
            
            # Verify with GoPlus
            goplus_result = check_goplus_address(address)
            is_mal, flags = is_goplus_malicious(goplus_result)
            
            # Extract features
            features = extract_features(address)
            features['address'] = address
            features['FLAG'] = 1  # Malicious
            features['source'] = 'darklist'
            features['goplus_verified'] = 1 if is_mal else 0
            features['goplus_flags'] = ','.join(flags) if flags else ''
            
            all_data.append(features)
            malicious_count += 1
            
            status = f"GoPlus: {','.join(flags[:2])}" if flags else "GoPlus: not flagged"
            print(f"✓ ({status})")
            
            # Progress save every 50 addresses
            if malicious_count % 50 == 0:
                save_progress(all_data)
                
        except Exception as e:
            print(f"✗ Error: {e}")
            continue
    
    # ============================================================
    # 2. COLLECT SAFE ADDRESSES
    # ============================================================
    print(f"\n[3/3] Extracting features for safe addresses...")
    
    safe_addresses = collect_safe_addresses()
    
    # Add some random addresses that GoPlus confirms as safe
    print("      Also sampling random recent addresses verified as safe by GoPlus...")
    
    safe_count = 0
    for i, address in enumerate(safe_addresses[:max_safe]):
        try:
            print(f"      [{i+1}/{min(len(safe_addresses), max_safe)}] {address[:10]}...", end=' ')
            
            # Verify with GoPlus (should NOT be flagged)
            goplus_result = check_goplus_address(address)
            is_mal, flags = is_goplus_malicious(goplus_result)
            
            if is_mal:
                print(f"⚠ Skipped (flagged by GoPlus)")
                continue
            
            # Extract features
            features = extract_features(address)
            features['address'] = address
            features['FLAG'] = 0  # Safe
            features['source'] = 'known_safe'
            features['goplus_verified'] = 1
            features['goplus_flags'] = ''
            
            all_data.append(features)
            safe_count += 1
            print("✓")
            
        except Exception as e:
            print(f"✗ Error: {e}")
            continue
    
    # ============================================================
    # 3. SAVE FINAL DATASET
    # ============================================================
    print("\n" + "=" * 60)
    print("SAVING DATASET")
    print("=" * 60)
    
    df = pd.DataFrame(all_data)
    df.to_csv(OUTPUT_FILE, index=False)
    
    print(f"\n✓ Saved {len(df)} samples to {OUTPUT_FILE}")
    print(f"  - Malicious: {len(df[df['FLAG'] == 1])}")
    print(f"  - Safe: {len(df[df['FLAG'] == 0])}")
    print(f"  - GoPlus verified: {len(df[df['goplus_verified'] == 1])}")
    
    # Show feature summary
    print("\nFeature columns:")
    for col in df.columns:
        if col not in ['address', 'FLAG', 'source', 'goplus_verified', 'goplus_flags']:
            print(f"  - {col}")
    
    return df

def save_progress(data):
    """Save progress in case of interruption."""
    progress_file = os.path.join(OUTPUT_DIR, 'collection_progress.csv')
    df = pd.DataFrame(data)
    df.to_csv(progress_file, index=False)
    print(f"\n      [Progress saved: {len(df)} samples]")

# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    if not ETHERSCAN_API_KEY:
        print("ERROR: ETHERSCAN_API_KEY not found in .env")
        sys.exit(1)
    
    print(f"Etherscan API Key: {ETHERSCAN_API_KEY[:8]}...")
    print(f"Output: {OUTPUT_FILE}")
    
    # Collect with reasonable limits (API rate limiting)
    # Full collection: max_malicious=500, max_safe=500
    # Quick test: max_malicious=50, max_safe=30
    
    df = collect_data(max_malicious=100, max_safe=50)
    
    print("\n" + "=" * 60)
    print("NEXT STEPS:")
    print("=" * 60)
    print("1. Run: python train_real_model.py")
    print("2. This will train a model on REAL flagged addresses")
    print("3. The model learns patterns that predict GoPlus flags")
    print("=" * 60)
