"""
Website Phishing Detection Model Training
==========================================

This script trains an ML model to detect phishing websites based on:
1. URL features (length, special chars, suspicious keywords)
2. Domain features (age, TLD, subdomain count)
3. Known patterns (typosquatting, impersonation)

Dataset sources:
- PhishTank (phishing URLs)
- OpenPhish (phishing URLs)
- Legitimate sites (Alexa top sites, known Web3 projects)
"""

import pandas as pd
import numpy as np
import pickle
import json
import re
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import warnings
warnings.filterwarnings('ignore')

# ============================================================
# DATASET - Phishing & Legitimate URLs
# ============================================================

# Known phishing/scam URLs (Web3 focused)
PHISHING_URLS = [
    # Fake Uniswap
    "https://uniswap-app.org/swap",
    "https://uniswap-airdrop.xyz/claim",
    "https://uniswaps.exchange/",
    "https://uni-swap.finance/",
    "https://uniswap-claim.com/",
    "https://uniswap-bonus.io/",
    "https://app-uniswap.org/",
    "https://uniswap-v3.app/",
    
    # Fake OpenSea
    "https://opensea-nft.io/",
    "https://opensea-airdrop.com/",
    "https://opensea-mint.xyz/",
    "https://open-sea.io/",
    "https://opensea-rewards.com/",
    "https://openseas.io/",
    "https://openseaa.io/",
    
    # Fake MetaMask
    "https://metamask-wallet.app/",
    "https://metamask-io.com/",
    "https://meta-mask.io/",
    "https://metamask-connect.com/",
    "https://metamask-update.com/",
    "https://metamasks.io/",
    "https://metamask-verify.com/",
    
    # Fake PancakeSwap
    "https://pancakeswap-finance.org/",
    "https://pancakeswaps.finance/",
    "https://pancake-swap.io/",
    "https://pancakeswap-airdrop.com/",
    
    # Fake airdrops/claims
    "https://airdrop-ethereum.com/",
    "https://claim-nft-rewards.com/",
    "https://free-eth-airdrop.xyz/",
    "https://binance-airdrop.com/",
    "https://coinbase-giveaway.com/",
    "https://crypto-rewards-claim.io/",
    "https://eth-bonus.xyz/",
    "https://nft-free-mint.com/",
    "https://token-airdrop-claim.io/",
    "https://defi-rewards.xyz/",
    
    # Wallet connect scams
    "https://connectwallet-dapp.com/",
    "https://wallet-connect-app.io/",
    "https://walletconnect-dapp.com/",
    "https://connect-your-wallet.xyz/",
    "https://dapp-connect.io/",
    "https://web3-connect.app/",
    
    # Fake exchanges
    "https://binance-us.app/",
    "https://coinbase-pro.io/",
    "https://kraken-exchange.app/",
    "https://binance-trade.com/",
    "https://coinbase-wallet.app/",
    
    # Generic phishing patterns
    "https://verify-wallet.com/",
    "https://secure-metamask.io/",
    "https://update-wallet.xyz/",
    "https://sync-wallet.io/",
    "https://recover-wallet.com/",
    "https://restore-wallet.xyz/",
    "https://validate-wallet.io/",
    "https://unlock-account.com/",
    "https://verify-account.xyz/",
    "https://confirm-transaction.io/",
    
    # NFT scams
    "https://bored-ape-mint.com/",
    "https://cryptopunks-claim.xyz/",
    "https://azuki-free-mint.io/",
    "https://moonbirds-airdrop.com/",
    "https://doodles-mint.xyz/",
    "https://nft-exclusive-drop.io/",
    "https://rare-nft-mint.com/",
    
    # Fake DEXs
    "https://sushiswap-app.io/",
    "https://curve-finance.app/",
    "https://1inch-exchange.io/",
    "https://balancer-finance.xyz/",
    "https://quickswap-dex.com/",
    
    # Suspicious TLDs with crypto keywords
    "https://ethereum-bonus.tk/",
    "https://bitcoin-giveaway.ml/",
    "https://crypto-free.ga/",
    "https://defi-bonus.cf/",
    "https://nft-drop.gq/",
    
    # Typosquatting
    "https://etherscam.io/",
    "https://etherscan-verify.com/",
    "https://polygonscan-io.com/",
    "https://arbiscan-verify.io/",
    "https://bscscan-verify.com/",
]

# Legitimate Web3 URLs
LEGITIMATE_URLS = [
    # Major DeFi
    "https://uniswap.org/",
    "https://app.uniswap.org/",
    "https://aave.com/",
    "https://app.aave.com/",
    "https://compound.finance/",
    "https://app.compound.finance/",
    "https://curve.fi/",
    "https://balancer.fi/",
    "https://app.balancer.fi/",
    "https://sushi.com/",
    "https://app.sushi.com/",
    "https://1inch.io/",
    "https://app.1inch.io/",
    "https://pancakeswap.finance/",
    "https://quickswap.exchange/",
    "https://raydium.io/",
    "https://gmx.io/",
    "https://app.gmx.io/",
    "https://dydx.exchange/",
    "https://yearn.finance/",
    "https://convexfinance.com/",
    
    # NFT Marketplaces
    "https://opensea.io/",
    "https://blur.io/",
    "https://looksrare.org/",
    "https://x2y2.io/",
    "https://rarible.com/",
    "https://foundation.app/",
    "https://zora.co/",
    "https://superrare.com/",
    "https://niftygateway.com/",
    "https://magiceden.io/",
    
    # Exchanges
    "https://binance.com/",
    "https://coinbase.com/",
    "https://kraken.com/",
    "https://gemini.com/",
    "https://kucoin.com/",
    "https://okx.com/",
    "https://bybit.com/",
    "https://crypto.com/",
    "https://bitstamp.net/",
    "https://huobi.com/",
    "https://gate.io/",
    
    # Wallets
    "https://metamask.io/",
    "https://rainbow.me/",
    "https://phantom.app/",
    "https://trustwallet.com/",
    "https://ledger.com/",
    "https://trezor.io/",
    "https://exodus.com/",
    "https://argent.xyz/",
    "https://gnosis-safe.io/",
    "https://safe.global/",
    
    # Infrastructure
    "https://etherscan.io/",
    "https://polygonscan.com/",
    "https://bscscan.com/",
    "https://arbiscan.io/",
    "https://basescan.org/",
    "https://infura.io/",
    "https://alchemy.com/",
    "https://chainlink.com/",
    "https://thegraph.com/",
    "https://moralis.io/",
    "https://quicknode.com/",
    
    # Analytics
    "https://dextools.io/",
    "https://dexscreener.com/",
    "https://coingecko.com/",
    "https://coinmarketcap.com/",
    "https://defillama.com/",
    "https://dune.com/",
    "https://nansen.ai/",
    "https://zapper.fi/",
    "https://zerion.io/",
    "https://debank.com/",
    "https://tokenterminal.com/",
    
    # Bridges
    "https://bridge.arbitrum.io/",
    "https://app.optimism.io/",
    "https://portal.polygon.technology/",
    "https://stargate.finance/",
    "https://across.to/",
    "https://hop.exchange/",
    "https://cbridge.celer.network/",
    
    # Staking
    "https://lido.fi/",
    "https://rocketpool.net/",
    "https://frax.finance/",
    "https://stakewise.io/",
    "https://eigenlayer.xyz/",
    
    # ENS & Identity
    "https://ens.domains/",
    "https://app.ens.domains/",
    "https://unstoppabledomains.com/",
    
    # DAO & Governance
    "https://snapshot.org/",
    "https://tally.xyz/",
    "https://boardroom.io/",
    
    # Other trusted
    "https://guild.xyz/",
    "https://mirror.xyz/",
    "https://paragraph.xyz/",
    "https://gitcoin.co/",
    "https://ethereum.org/",
    "https://polygon.technology/",
    "https://arbitrum.io/",
    "https://optimism.io/",
    "https://base.org/",
    "https://scroll.io/",
    "https://zksync.io/",
    "https://linea.build/",
    
    # General legitimate sites for balance
    "https://github.com/",
    "https://google.com/",
    "https://youtube.com/",
    "https://twitter.com/",
    "https://discord.com/",
    "https://telegram.org/",
    "https://reddit.com/",
    "https://medium.com/",
    "https://substack.com/",
    "https://notion.so/",
]

# ============================================================
# FEATURE EXTRACTION
# ============================================================

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'airdrop', 'claim', 'free', 'bonus', 'reward', 'giveaway',
    'verify', 'validate', 'confirm', 'secure', 'update', 'sync',
    'connect-wallet', 'wallet-connect', 'walletconnect',
    'recover', 'restore', 'unlock', 'login', 'signin',
    'metamask', 'trustwallet', 'coinbase', 'binance',  # When not official domain
    'mint', 'drop', 'presale', 'whitelist',
]

# Legitimate brand keywords (for typosquatting detection)
BRAND_KEYWORDS = [
    'uniswap', 'opensea', 'metamask', 'binance', 'coinbase',
    'aave', 'compound', 'curve', 'sushiswap', 'pancakeswap',
    'ethereum', 'polygon', 'arbitrum', 'optimism',
    'ledger', 'trezor', 'phantom', 'rainbow',
]

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
    '.xyz', '.top', '.club', '.work', '.click',
    '.link', '.online', '.site', '.website',
    '.app', '.io',  # Only suspicious if combined with other signals
]

# Safe TLDs (trusted)
SAFE_TLDS = ['.com', '.org', '.net', '.co', '.finance', '.exchange']


def extract_url_features(url):
    """
    Extract features from a URL for ML classification.
    """
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
        
        # Brand impersonation detection
        brand_in_url = 0
        for brand in BRAND_KEYWORDS:
            if brand in domain:
                # Check if it's NOT the official domain
                official_domains = [f'{brand}.org', f'{brand}.com', f'{brand}.io', f'{brand}.finance', f'{brand}.exchange', f'app.{brand}']
                if not any(domain == od or domain.endswith('.' + od.split('.')[-2] + '.' + od.split('.')[-1]) for od in official_domains if '.' in od):
                    brand_in_url += 1
        features['brand_impersonation_count'] = brand_in_url
        features['has_brand_impersonation'] = 1 if brand_in_url > 0 else 0
        
        # Path analysis
        features['has_claim_path'] = 1 if any(kw in path for kw in ['claim', 'airdrop', 'reward', 'bonus', 'free']) else 0
        features['has_connect_path'] = 1 if any(kw in path for kw in ['connect', 'wallet', 'sync', 'verify']) else 0
        
        # Domain patterns
        features['has_dash_in_domain'] = 1 if '-' in domain.split('.')[0] else 0
        features['has_number_in_domain'] = 1 if any(c.isdigit() for c in domain.split('.')[0]) else 0
        
        # Length-based features (phishing often has long/weird domains)
        features['is_long_domain'] = 1 if len(domain) > 25 else 0
        features['is_very_long_url'] = 1 if len(url) > 75 else 0
        
        # Entropy of domain (random strings have high entropy)
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
        print(f"Error extracting features from {url}: {e}")
        # Return default features
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


def create_dataset():
    """
    Load training dataset from CSV (created by add_legit_websites.py).
    Falls back to creating from hardcoded lists if CSV doesn't exist.
    """
    print("Loading dataset...")
    
    # Try to load existing enhanced dataset first
    try:
        df = pd.read_csv('data/website_dataset.csv')
        print(f"[OK] Loaded enhanced dataset: {len(df)} URLs ({sum(df['label'] == 1)} phishing, {sum(df['label'] == 0)} legitimate)")
        return df
    except FileNotFoundError:
        print("[WARN] Enhanced dataset not found, creating from hardcoded lists...")
        
        data = []
        
        # Process phishing URLs
        for url in PHISHING_URLS:
            features = extract_url_features(url)
            features['url'] = url
            features['label'] = 1  # Phishing
            data.append(features)
        
        # Process legitimate URLs
        for url in LEGITIMATE_URLS:
            features = extract_url_features(url)
            features['url'] = url
            features['label'] = 0  # Legitimate
            data.append(features)
        
        df = pd.DataFrame(data)
        print(f"Dataset created: {len(df)} URLs ({len(PHISHING_URLS)} phishing, {len(LEGITIMATE_URLS)} legitimate)")
        
        return df


def train_model(df):
    """
    Train the website phishing detection model.
    """
    print("\n" + "="*60)
    print("TRAINING WEBSITE PHISHING DETECTION MODEL")
    print("="*60)
    
    # Separate features and labels
    feature_columns = [col for col in df.columns if col not in ['url', 'label']]
    X = df[feature_columns]
    y = df['label']
    
    print(f"\nFeatures ({len(feature_columns)}): {feature_columns}")
    print(f"Dataset size: {len(df)}")
    print(f"Phishing: {sum(y == 1)}, Legitimate: {sum(y == 0)}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train Random Forest
    print("\nTraining Random Forest...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        class_weight='balanced'
    )
    rf_model.fit(X_train_scaled, y_train)
    
    # Evaluate
    y_pred = rf_model.predict(X_test_scaled)
    y_pred_proba = rf_model.predict_proba(X_test_scaled)[:, 1]
    
    print("\n" + "="*60)
    print("MODEL EVALUATION")
    print("="*60)
    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Feature importance
    print("\n" + "="*60)
    print("FEATURE IMPORTANCE (Top 15)")
    print("="*60)
    importance = pd.DataFrame({
        'feature': feature_columns,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    for i, row in importance.head(15).iterrows():
        print(f"  {row['feature']}: {row['importance']:.4f}")
    
    return rf_model, scaler, feature_columns


def save_model(model, scaler, feature_names):
    """
    Save the trained model, scaler, and feature names.
    """
    import os
    
    # Save model
    model_path = os.path.join(os.path.dirname(__file__), 'website_model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"\nModel saved to: {model_path}")
    
    # Save scaler
    scaler_path = os.path.join(os.path.dirname(__file__), 'website_scaler.pkl')
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"Scaler saved to: {scaler_path}")
    
    # Save feature names
    features_path = os.path.join(os.path.dirname(__file__), 'website_features.json')
    with open(features_path, 'w') as f:
        json.dump({'features': feature_names}, f, indent=2)
    print(f"Features saved to: {features_path}")


def test_model(model, scaler, feature_names):
    """
    Test the model on some URLs.
    """
    print("\n" + "="*60)
    print("MODEL TESTING")
    print("="*60)
    
    test_urls = [
        # Should be PHISHING (high score)
        "https://uniswap-airdrop.xyz/claim",
        "https://metamask-wallet.app/connect",
        "https://free-eth-giveaway.tk/",
        "https://opensea-nft-mint.io/",
        "https://claim-your-reward.xyz/",
        
        # Should be SAFE (low score)
        "https://uniswap.org/",
        "https://opensea.io/",
        "https://metamask.io/",
        "https://etherscan.io/",
        "https://github.com/",
        "https://google.com/",
    ]
    
    print("\nPredictions:")
    print("-" * 80)
    
    for url in test_urls:
        features = extract_url_features(url)
        feature_vector = [features[f] for f in feature_names]
        feature_scaled = scaler.transform([feature_vector])
        
        prediction = model.predict(feature_scaled)[0]
        probability = model.predict_proba(feature_scaled)[0][1]
        
        status = "🚨 PHISHING" if prediction == 1 else "✅ SAFE"
        risk_score = int(probability * 100)
        
        print(f"{status} (Score: {risk_score:3d}) - {url[:60]}")


def main():
    """
    Main training pipeline.
    """
    # Create dataset
    df = create_dataset()
    
    # Don't save - preserve enhanced dataset from add_legit_websites.py
    
    # Train model
    model, scaler, feature_names = train_model(df)
    
    # Save model
    save_model(model, scaler, feature_names)
    
    # Test model
    test_model(model, scaler, feature_names)
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)
    print("\nFiles created:")
    print("  - website_model.pkl (trained model)")
    print("  - website_scaler.pkl (feature scaler)")
    print("  - website_features.json (feature names)")
    print("  - data/website_dataset.csv (training data)")
    print("\nNext: Update api.py to use the new ML model for website detection")


if __name__ == '__main__':
    main()
