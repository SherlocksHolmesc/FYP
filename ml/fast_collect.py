"""
Fast Data Collection Script
============================
Collects training data from ALL darklist addresses with:
- Faster rate (Etherscan Pro allows 5/sec, free tier 0.2s delay)
- Better error handling
- Progress saving every 10 addresses
- Resume capability from where it stopped

Run: python fast_collect.py
"""

import os
import sys
import json
import time
import requests
import pandas as pd
import numpy as np
from dotenv import load_dotenv

load_dotenv()

ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY', '')
ETHERSCAN_BASE_URL = 'https://api.etherscan.io/v2/api'
GOPLUS_BASE_URL = 'https://api.gopluslabs.io/api/v1'
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
OUTPUT_FILE = os.path.join(DATA_DIR, 'real_world_dataset.csv')
PROGRESS_FILE = os.path.join(DATA_DIR, 'collection_progress.json')

# Faster delays for Etherscan Pro tier (if you have it, set to 0.1)
# Free tier should use 0.25
DELAY = 0.2

def etherscan_get(params, retries=3):
    """Etherscan request with retry logic."""
    params['apikey'] = ETHERSCAN_API_KEY
    params['chainid'] = 1
    
    for attempt in range(retries):
        try:
            time.sleep(DELAY)
            resp = requests.get(ETHERSCAN_BASE_URL, params=params, timeout=20)
            data = resp.json()
            if data.get('status') == '1':
                return data.get('result', [])
            return []
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return []
    return []

def goplus_check(address):
    """Quick GoPlus check."""
    try:
        time.sleep(0.05)
        resp = requests.get(f"{GOPLUS_BASE_URL}/address_security/{address}", timeout=10)
        data = resp.json()
        if data.get('code') == 1:
            return data.get('result', {})
    except:
        pass
    return {}

def extract_features(address):
    """Extract features from Etherscan data."""
    # Get transactions
    normal = etherscan_get({'module': 'account', 'action': 'txlist', 'address': address, 'startblock': 0, 'endblock': 99999999, 'sort': 'asc'})
    erc20 = etherscan_get({'module': 'account', 'action': 'tokentx', 'address': address, 'startblock': 0, 'endblock': 99999999, 'sort': 'asc'})
    bal = etherscan_get({'module': 'account', 'action': 'balance', 'address': address, 'tag': 'latest'})
    
    if not isinstance(normal, list): normal = []
    if not isinstance(erc20, list): erc20 = []
    try:
        balance = int(bal) / 1e18 if bal else 0
    except:
        balance = 0
    
    addr = address.lower()
    sent = [tx for tx in normal if tx.get('from', '').lower() == addr]
    recv = [tx for tx in normal if tx.get('to', '').lower() == addr]
    erc20_sent = [tx for tx in erc20 if tx.get('from', '').lower() == addr]
    erc20_recv = [tx for tx in erc20 if tx.get('to', '').lower() == addr]
    
    def timestamps(txs):
        return sorted([int(tx.get('timeStamp', 0)) for tx in txs if tx.get('timeStamp')])
    
    def avg_time(ts):
        if len(ts) < 2: return 0
        diffs = [(ts[i+1] - ts[i]) / 60 for i in range(len(ts)-1)]
        return np.mean(diffs)
    
    def time_span(ts):
        if len(ts) < 2: return 0
        return (ts[-1] - ts[0]) / 60
    
    sent_ts = timestamps(sent)
    recv_ts = timestamps(recv)
    all_ts = sorted(sent_ts + recv_ts)
    
    def values(txs):
        return [int(tx.get('value', 0)) / 1e18 for tx in txs]
    
    sent_vals = values(sent)
    recv_vals = values(recv)
    
    failed = sum(1 for tx in normal if tx.get('isError') == '1')
    gas = [int(tx.get('gasUsed', 0)) for tx in normal if tx.get('gasUsed')]
    
    return {
        'Avg min between sent tnx': avg_time(sent_ts),
        'Avg min between received tnx': avg_time(recv_ts),
        'Time Diff between first and last (Mins)': time_span(all_ts),
        'Sent tnx': len(sent),
        'Received Tnx': len(recv),
        'Number of Created Contracts': sum(1 for tx in sent if tx.get('to', '') == ''),
        'avg val received': np.mean(recv_vals) if recv_vals else 0,
        'avg val sent': np.mean(sent_vals) if sent_vals else 0,
        'total Ether sent': sum(sent_vals),
        'total ether received': sum(recv_vals),
        'total ether balance': balance,
        ' ERC20 total Ether received': 0,
        ' ERC20 total ether sent': 0,
        ' ERC20 uniq sent addr': len(set(tx.get('to', '').lower() for tx in erc20_sent if tx.get('to'))),
        ' ERC20 uniq rec addr': len(set(tx.get('from', '').lower() for tx in erc20_recv if tx.get('from'))),
        ' ERC20 uniq sent token name': len(set(tx.get('tokenName', '') for tx in erc20_sent if tx.get('tokenName'))),
        ' ERC20 uniq rec token name': len(set(tx.get('tokenName', '') for tx in erc20_recv if tx.get('tokenName'))),
        'unique_sent_addresses': len(set(tx.get('to', '').lower() for tx in sent if tx.get('to'))),
        'unique_received_addresses': len(set(tx.get('from', '').lower() for tx in recv if tx.get('from'))),
        'failed_tx_ratio': failed / len(normal) if normal else 0,
        'avg_gas_used': np.mean(gas) if gas else 0,
        'total_tx_count': len(normal),
        'sent_received_ratio': len(sent) / max(len(recv), 1),
        'erc20_total_txs': len(erc20),
    }

def load_progress():
    """Load collection progress."""
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, 'r') as f:
            return json.load(f)
    return {'processed': [], 'data': []}

def save_progress(progress):
    """Save collection progress."""
    with open(PROGRESS_FILE, 'w') as f:
        json.dump(progress, f)

def main():
    print("=" * 60)
    print("FAST DATA COLLECTION")
    print("=" * 60)
    
    # Load darklist
    darklist_path = os.path.join(DATA_DIR, 'darklist.json')
    with open(darklist_path, 'r') as f:
        darklist = json.load(f)
    
    addresses = [item.get('address', item) if isinstance(item, dict) else item for item in darklist]
    print(f"Loaded {len(addresses)} addresses from darklist")
    
    # Load progress
    progress = load_progress()
    processed = set(progress.get('processed', []))
    data = progress.get('data', [])
    
    print(f"Already processed: {len(processed)}")
    print(f"Remaining: {len(addresses) - len(processed)}")
    
    # Known safe addresses
    safe_addresses = [
        '0x28C6c06298d514Db089934071355E5743bf21d60',  # Binance
        '0x21a31Ee1afC51d94C2eFcCAa2092aD1028285549',  # Binance 2
        '0x71660c4005BA85c37ccec55d0C4493E66Fe775d3',  # Coinbase
        '0x503828976D22510aad0201ac7EC88293211D23Da',  # Coinbase 2
        '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',  # Vitalik
        '0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8',  # Binance 7
        '0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD',  # Uniswap Router
        '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',  # Uniswap V2 Router
        '0xDFd5293D8e347dFe59E90eFd55b2956a1343963d',  # Kraken
        '0x267be1C1D684F78cb4F6a176C4911b741E4Ffdc0',  # Kraken 4
        '0x2FAF487A4414Fe77e2327F0bf4AE2a264a776AD2',  # FTX
        '0x5a52e96bacdabb82fd05763e25335261b270efcb',  # Big whale
        '0x47ac0Fb4F2D84898e4D9E7b4DaB3C24507a6D503',  # Binance 8
        '0xf977814e90da44bfa03b6295a0616a897441acec',  # Binance 14
        '0x1a9C8182C09F50C8318d769245beA52c32BE35BC',  # Uniswap
    ]
    
    # Process malicious addresses
    print("\n[MALICIOUS ADDRESSES]")
    for i, addr in enumerate(addresses):
        if addr.lower() in processed:
            continue
        
        try:
            print(f"[{i+1}/{len(addresses)}] {addr[:12]}...", end=' ', flush=True)
            
            # GoPlus check
            gp = goplus_check(addr)
            flags = []
            for key in ['stealing_attack', 'phishing_activities', 'cybercrime', 'money_laundering', 'honeypot_related_address']:
                if gp.get(key, '0') != '0':
                    flags.append(key)
            
            # Extract features
            features = extract_features(addr)
            features['address'] = addr
            features['FLAG'] = 1  # Malicious
            features['goplus_flags'] = ','.join(flags)
            
            data.append(features)
            processed.add(addr.lower())
            
            flag_str = ','.join(flags[:2]) if flags else 'no flags'
            print(f"✓ ({flag_str})")
            
            # Save every 10
            if len(data) % 10 == 0:
                save_progress({'processed': list(processed), 'data': data})
                print(f"    [Saved {len(data)} samples]")
                
        except Exception as e:
            print(f"✗ {e}")
            continue
    
    # Process safe addresses
    print("\n[SAFE ADDRESSES]")
    for i, addr in enumerate(safe_addresses):
        if addr.lower() in processed:
            continue
            
        try:
            print(f"[{i+1}/{len(safe_addresses)}] {addr[:12]}...", end=' ', flush=True)
            
            features = extract_features(addr)
            features['address'] = addr
            features['FLAG'] = 0  # Safe
            features['goplus_flags'] = ''
            
            data.append(features)
            processed.add(addr.lower())
            print("✓")
            
        except Exception as e:
            print(f"✗ {e}")
            continue
    
    # Save final dataset
    print("\n" + "=" * 60)
    df = pd.DataFrame(data)
    df.to_csv(OUTPUT_FILE, index=False)
    
    mal = len(df[df['FLAG'] == 1])
    safe = len(df[df['FLAG'] == 0])
    print(f"DONE! Saved {len(df)} samples")
    print(f"  Malicious: {mal}")
    print(f"  Safe: {safe}")
    print(f"Output: {OUTPUT_FILE}")
    
    # Clean up progress file
    if os.path.exists(PROGRESS_FILE):
        os.remove(PROGRESS_FILE)

if __name__ == '__main__':
    if not ETHERSCAN_API_KEY:
        print("ERROR: Set ETHERSCAN_API_KEY in .env")
        sys.exit(1)
    main()
