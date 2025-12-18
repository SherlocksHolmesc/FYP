"""
Add More Safe Addresses to Training Data
=========================================
The model has too many fraud (652) vs safe (15) samples.
This script adds more verified safe addresses to balance the dataset.
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
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
DATASET_FILE = os.path.join(DATA_DIR, 'real_world_dataset.csv')
DELAY = 0.25

# MORE safe addresses - exchanges, protocols, whales, normal users
ADDITIONAL_SAFE_ADDRESSES = [
    # User's wallet (verified safe)
    '0xB8E533eF21F248FB71A8e4e7b0023a42C35aCc72',
    
    # Major exchanges (hot wallets)
    '0x28C6c06298d514Db089934071355E5743bf21d60',  # Binance 14
    '0x21a31Ee1afC51d94C2eFcCAa2092aD1028285549',  # Binance 15
    '0xDFd5293D8e347dFe59E90eFd55b2956a1343963d',  # Kraken
    '0x267be1C1D684F78cb4F6a176C4911b741E4Ffdc0',  # Kraken 4
    '0xA9D1e08C7793af67e9d92fe308d5697FB81d3E43',  # Coinbase 10
    '0x71660c4005BA85c37ccec55d0C4493E66Fe775d3',  # Coinbase 4
    '0xe93381fB4c4F14bDa253907b18faD305D799241a',  # Huobi 10
    '0x5f65f7b609678448494De4C87521CdF6cEf1e932',  # Gemini 4
    '0x267be1C1D684F78cb4F6a176C4911b741E4Ffdc0',  # Kraken 4
    '0x2B5634C42055806a59e9107ED44D43c426E58258',  # KuCoin
    
    # DeFi protocols (verified contracts)
    '0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD',  # Uniswap Universal Router
    '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',  # Uniswap V2 Router
    '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',  # Uniswap V3 Router 2
    '0xDef1C0ded9bec7F1a1670819833240f027b25EfF',  # 0x Exchange
    '0x881D40237659C251811CEC9c364ef91dC08D300C',  # Metamask Swap Router
    '0x1111111254fb6c44bAC0beD2854e76F90643097d',  # 1inch Router v4
    '0x6131B5fae19EA4f9D964eAc0408E4408b66337b5',  # Kyber Network
    '0xE592427A0AEce92De3Edee1F18E0157C05861564',  # Uniswap V3 Router
    
    # Well-known whales / clean addresses
    '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',  # Vitalik
    '0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B',  # Vitalik old
    '0x47ac0Fb4F2D84898e4D9E7b4DaB3C24507a6D503',  # Binance 8
    '0xf977814e90da44bfa03b6295a0616a897441acec',  # Binance 14
    '0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8',  # Binance 7
    '0x3DdfA8eC3052539b6C9549F12cEA2C295cfF5296',  # Justin Sun
    '0x0716a17FBAeE714f1E6aB0f9d59edbC5f09815C0',  # Jump Trading
    '0x8103683202aa8DA10536036EDef04CDd865C225E',  # Wintermute
    '0x0D0707963952f2fBA59dD06f2b425ace40b492Fe',  # Gate.io
    '0xb5d85CBf7cB3EE0D56b3bB207D5Fc4B82f43F511',  # Coinbase 5
    '0x98C3d3183C4b8A650614ad179A1a98be0a8d6B8E',  # Bitfinex
    
    # Normal users / small wallets (low activity like user's)
    '0x9696f59E4d72E237BE84fFD425DCaD154Bf96976',  # Random verified
    '0x0a4c79cE84202b03e95B7a692E5D728d83C44c76',  # Random wallet
    '0x220866B1A2219f40e72f5c628B65D54268cA3A9D',  # Normal user
    '0x0F6DDcE5D63C24f27F9AbF57Dc2a3e0f7b2f51B6',  # Retail user
]

def etherscan_get(params, retries=3):
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
    return []

def extract_features(address):
    """Extract features from Etherscan data."""
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

def main():
    print("=" * 60)
    print("ADDING SAFE ADDRESSES TO TRAINING DATA")
    print("=" * 60)
    
    # Load existing dataset
    df = pd.read_csv(DATASET_FILE)
    print(f"Current dataset: {len(df)} samples")
    print(f"  - Fraud: {(df['FLAG'] == 1).sum()}")
    print(f"  - Safe: {(df['FLAG'] == 0).sum()}")
    
    existing = set(df['address'].str.lower())
    new_data = []
    
    print(f"\nProcessing {len(ADDITIONAL_SAFE_ADDRESSES)} safe addresses...")
    
    for i, addr in enumerate(ADDITIONAL_SAFE_ADDRESSES):
        if addr.lower() in existing:
            print(f"[{i+1}] {addr[:12]}... already exists, skipping")
            continue
        
        print(f"[{i+1}/{len(ADDITIONAL_SAFE_ADDRESSES)}] {addr[:12]}...", end=' ', flush=True)
        
        try:
            features = extract_features(addr)
            features['address'] = addr
            features['FLAG'] = 0  # SAFE
            features['goplus_flags'] = ''
            new_data.append(features)
            print("✓")
        except Exception as e:
            print(f"✗ ({e})")
    
    if new_data:
        new_df = pd.DataFrame(new_data)
        combined = pd.concat([df, new_df], ignore_index=True)
        combined.to_csv(DATASET_FILE, index=False)
        
        print(f"\n✓ Added {len(new_data)} new safe addresses")
        print(f"New dataset: {len(combined)} samples")
        print(f"  - Fraud: {(combined['FLAG'] == 1).sum()}")
        print(f"  - Safe: {(combined['FLAG'] == 0).sum()}")
        print(f"\nNow run: python train_real_model.py")
    else:
        print("\nNo new addresses added")

if __name__ == '__main__':
    main()
