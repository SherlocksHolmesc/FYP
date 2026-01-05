"""
Legitimate Domains Database
Downloads and maintains a list of legitimate websites from Tranco List
Used for typosquatting detection
"""

import os
import json
import requests
from datetime import datetime, timedelta

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
LEGIT_DOMAINS_FILE = os.path.join(DATA_DIR, 'legit_domains.json')

# Top legitimate domains - curated list of high-value targets for phishing
# These are the most commonly impersonated websites
CURATED_LEGIT_DOMAINS = {
    # Crypto/Web3
    'etherscan.io': {'name': 'Etherscan', 'category': 'crypto', 'official': 'https://etherscan.io'},
    'uniswap.org': {'name': 'Uniswap', 'category': 'crypto', 'official': 'https://app.uniswap.org'},
    'opensea.io': {'name': 'OpenSea', 'category': 'crypto', 'official': 'https://opensea.io'},
    'metamask.io': {'name': 'MetaMask', 'category': 'crypto', 'official': 'https://metamask.io'},
    'binance.com': {'name': 'Binance', 'category': 'crypto', 'official': 'https://www.binance.com'},
    'coinbase.com': {'name': 'Coinbase', 'category': 'crypto', 'official': 'https://www.coinbase.com'},
    'kraken.com': {'name': 'Kraken', 'category': 'crypto', 'official': 'https://www.kraken.com'},
    'blockchain.com': {'name': 'Blockchain.com', 'category': 'crypto', 'official': 'https://www.blockchain.com'},
    'crypto.com': {'name': 'Crypto.com', 'category': 'crypto', 'official': 'https://crypto.com'},
    'ledger.com': {'name': 'Ledger', 'category': 'crypto', 'official': 'https://www.ledger.com'},
    'trezor.io': {'name': 'Trezor', 'category': 'crypto', 'official': 'https://trezor.io'},
    'phantom.app': {'name': 'Phantom', 'category': 'crypto', 'official': 'https://phantom.app'},
    'aave.com': {'name': 'Aave', 'category': 'crypto', 'official': 'https://app.aave.com'},
    'compound.finance': {'name': 'Compound', 'category': 'crypto', 'official': 'https://compound.finance'},
    'curve.fi': {'name': 'Curve', 'category': 'crypto', 'official': 'https://curve.fi'},
    'sushiswap.com': {'name': 'SushiSwap', 'category': 'crypto', 'official': 'https://www.sushi.com'},
    'pancakeswap.finance': {'name': 'PancakeSwap', 'category': 'crypto', 'official': 'https://pancakeswap.finance'},
    'lido.fi': {'name': 'Lido', 'category': 'crypto', 'official': 'https://lido.fi'},
    'dydx.exchange': {'name': 'dYdX', 'category': 'crypto', 'official': 'https://dydx.exchange'},
    'blur.io': {'name': 'Blur', 'category': 'crypto', 'official': 'https://blur.io'},
    'rarible.com': {'name': 'Rarible', 'category': 'crypto', 'official': 'https://rarible.com'},
    'foundation.app': {'name': 'Foundation', 'category': 'crypto', 'official': 'https://foundation.app'},
    'zapper.fi': {'name': 'Zapper', 'category': 'crypto', 'official': 'https://zapper.fi'},
    'zerion.io': {'name': 'Zerion', 'category': 'crypto', 'official': 'https://zerion.io'},
    'debank.com': {'name': 'DeBank', 'category': 'crypto', 'official': 'https://debank.com'},
    'rainbow.me': {'name': 'Rainbow', 'category': 'crypto', 'official': 'https://rainbow.me'},
    'trustwallet.com': {'name': 'Trust Wallet', 'category': 'crypto', 'official': 'https://trustwallet.com'},
    'exodus.com': {'name': 'Exodus', 'category': 'crypto', 'official': 'https://www.exodus.com'},
    'solscan.io': {'name': 'Solscan', 'category': 'crypto', 'official': 'https://solscan.io'},
    'polygonscan.com': {'name': 'PolygonScan', 'category': 'crypto', 'official': 'https://polygonscan.com'},
    'arbiscan.io': {'name': 'Arbiscan', 'category': 'crypto', 'official': 'https://arbiscan.io'},
    'bscscan.com': {'name': 'BscScan', 'category': 'crypto', 'official': 'https://bscscan.com'},
    'ftmscan.com': {'name': 'FTMScan', 'category': 'crypto', 'official': 'https://ftmscan.com'},
    'snowtrace.io': {'name': 'Snowtrace', 'category': 'crypto', 'official': 'https://snowtrace.io'},
    
    # Tech Giants
    'google.com': {'name': 'Google', 'category': 'tech', 'official': 'https://www.google.com'},
    'microsoft.com': {'name': 'Microsoft', 'category': 'tech', 'official': 'https://www.microsoft.com'},
    'apple.com': {'name': 'Apple', 'category': 'tech', 'official': 'https://www.apple.com'},
    'amazon.com': {'name': 'Amazon', 'category': 'tech', 'official': 'https://www.amazon.com'},
    'github.com': {'name': 'GitHub', 'category': 'tech', 'official': 'https://github.com'},
    'gitlab.com': {'name': 'GitLab', 'category': 'tech', 'official': 'https://gitlab.com'},
    'dropbox.com': {'name': 'Dropbox', 'category': 'tech', 'official': 'https://www.dropbox.com'},
    'zoom.us': {'name': 'Zoom', 'category': 'tech', 'official': 'https://zoom.us'},
    'slack.com': {'name': 'Slack', 'category': 'tech', 'official': 'https://slack.com'},
    'notion.so': {'name': 'Notion', 'category': 'tech', 'official': 'https://www.notion.so'},
    'figma.com': {'name': 'Figma', 'category': 'tech', 'official': 'https://www.figma.com'},
    'adobe.com': {'name': 'Adobe', 'category': 'tech', 'official': 'https://www.adobe.com'},
    'nvidia.com': {'name': 'NVIDIA', 'category': 'tech', 'official': 'https://www.nvidia.com'},
    'amd.com': {'name': 'AMD', 'category': 'tech', 'official': 'https://www.amd.com'},
    'intel.com': {'name': 'Intel', 'category': 'tech', 'official': 'https://www.intel.com'},
    
    # Social Media
    'twitter.com': {'name': 'Twitter/X', 'category': 'social', 'official': 'https://twitter.com'},
    'x.com': {'name': 'X', 'category': 'social', 'official': 'https://x.com'},
    'facebook.com': {'name': 'Facebook', 'category': 'social', 'official': 'https://www.facebook.com'},
    'instagram.com': {'name': 'Instagram', 'category': 'social', 'official': 'https://www.instagram.com'},
    'linkedin.com': {'name': 'LinkedIn', 'category': 'social', 'official': 'https://www.linkedin.com'},
    'reddit.com': {'name': 'Reddit', 'category': 'social', 'official': 'https://www.reddit.com'},
    'discord.com': {'name': 'Discord', 'category': 'social', 'official': 'https://discord.com'},
    'telegram.org': {'name': 'Telegram', 'category': 'social', 'official': 'https://telegram.org'},
    'whatsapp.com': {'name': 'WhatsApp', 'category': 'social', 'official': 'https://www.whatsapp.com'},
    'tiktok.com': {'name': 'TikTok', 'category': 'social', 'official': 'https://www.tiktok.com'},
    'youtube.com': {'name': 'YouTube', 'category': 'social', 'official': 'https://www.youtube.com'},
    'twitch.tv': {'name': 'Twitch', 'category': 'social', 'official': 'https://www.twitch.tv'},
    'snapchat.com': {'name': 'Snapchat', 'category': 'social', 'official': 'https://www.snapchat.com'},
    'pinterest.com': {'name': 'Pinterest', 'category': 'social', 'official': 'https://www.pinterest.com'},
    
    # Finance/Banking
    'paypal.com': {'name': 'PayPal', 'category': 'finance', 'official': 'https://www.paypal.com'},
    'stripe.com': {'name': 'Stripe', 'category': 'finance', 'official': 'https://stripe.com'},
    'wise.com': {'name': 'Wise', 'category': 'finance', 'official': 'https://wise.com'},
    'revolut.com': {'name': 'Revolut', 'category': 'finance', 'official': 'https://www.revolut.com'},
    'robinhood.com': {'name': 'Robinhood', 'category': 'finance', 'official': 'https://robinhood.com'},
    'venmo.com': {'name': 'Venmo', 'category': 'finance', 'official': 'https://venmo.com'},
    'chase.com': {'name': 'Chase', 'category': 'finance', 'official': 'https://www.chase.com'},
    'wellsfargo.com': {'name': 'Wells Fargo', 'category': 'finance', 'official': 'https://www.wellsfargo.com'},
    'bankofamerica.com': {'name': 'Bank of America', 'category': 'finance', 'official': 'https://www.bankofamerica.com'},
    
    # Shopping
    'ebay.com': {'name': 'eBay', 'category': 'shopping', 'official': 'https://www.ebay.com'},
    'walmart.com': {'name': 'Walmart', 'category': 'shopping', 'official': 'https://www.walmart.com'},
    'target.com': {'name': 'Target', 'category': 'shopping', 'official': 'https://www.target.com'},
    'bestbuy.com': {'name': 'Best Buy', 'category': 'shopping', 'official': 'https://www.bestbuy.com'},
    'etsy.com': {'name': 'Etsy', 'category': 'shopping', 'official': 'https://www.etsy.com'},
    'aliexpress.com': {'name': 'AliExpress', 'category': 'shopping', 'official': 'https://www.aliexpress.com'},
    
    # Email/Productivity
    'gmail.com': {'name': 'Gmail', 'category': 'email', 'official': 'https://mail.google.com'},
    'outlook.com': {'name': 'Outlook', 'category': 'email', 'official': 'https://outlook.live.com'},
    'proton.me': {'name': 'Proton', 'category': 'email', 'official': 'https://proton.me'},
    'protonmail.com': {'name': 'ProtonMail', 'category': 'email', 'official': 'https://protonmail.com'},
    'icloud.com': {'name': 'iCloud', 'category': 'email', 'official': 'https://www.icloud.com'},
    
    # Gaming
    'steam.com': {'name': 'Steam', 'category': 'gaming', 'official': 'https://store.steampowered.com'},
    'steampowered.com': {'name': 'Steam', 'category': 'gaming', 'official': 'https://store.steampowered.com'},
    'epicgames.com': {'name': 'Epic Games', 'category': 'gaming', 'official': 'https://www.epicgames.com'},
    'playstation.com': {'name': 'PlayStation', 'category': 'gaming', 'official': 'https://www.playstation.com'},
    'xbox.com': {'name': 'Xbox', 'category': 'gaming', 'official': 'https://www.xbox.com'},
    'roblox.com': {'name': 'Roblox', 'category': 'gaming', 'official': 'https://www.roblox.com'},
    'ea.com': {'name': 'EA', 'category': 'gaming', 'official': 'https://www.ea.com'},
    
    # News/Media
    'bbc.com': {'name': 'BBC', 'category': 'news', 'official': 'https://www.bbc.com'},
    'cnn.com': {'name': 'CNN', 'category': 'news', 'official': 'https://www.cnn.com'},
    'nytimes.com': {'name': 'New York Times', 'category': 'news', 'official': 'https://www.nytimes.com'},
    'theguardian.com': {'name': 'The Guardian', 'category': 'news', 'official': 'https://www.theguardian.com'},
    'reuters.com': {'name': 'Reuters', 'category': 'news', 'official': 'https://www.reuters.com'},
    'bloomberg.com': {'name': 'Bloomberg', 'category': 'news', 'official': 'https://www.bloomberg.com'},
    'coindesk.com': {'name': 'CoinDesk', 'category': 'news', 'official': 'https://www.coindesk.com'},
    'cointelegraph.com': {'name': 'Cointelegraph', 'category': 'news', 'official': 'https://cointelegraph.com'},
}

# Typosquatting character substitutions
TYPOSQUAT_MAP = {
    '1': 'i', 'l': 'i', '!': 'i', '|': 'i',
    '0': 'o', 
    '3': 'e',
    '4': 'a', '@': 'a',
    '5': 's', '$': 's',
    '7': 't',
    '8': 'b',
}

TYPOSQUAT_MULTI = {
    'vv': 'w', 'uu': 'w',
    'rn': 'm', 'nn': 'm',
    'cl': 'd', 'ci': 'a',
}


def normalize_typosquat(text):
    """Convert typosquatted text to normalized form"""
    result = text.lower()
    # Multi-character substitutions first
    for fake, real in TYPOSQUAT_MULTI.items():
        result = result.replace(fake, real)
    # Single character substitutions
    for fake, real in TYPOSQUAT_MAP.items():
        result = result.replace(fake, real)
    return result


def levenshtein_distance(s1, s2):
    """Calculate the Levenshtein distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def extract_domain_name(domain):
    """Extract the main domain name without TLD"""
    # Remove common TLDs
    parts = domain.split('.')
    if len(parts) >= 2:
        # Handle special cases like .co.uk
        if parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu']:
            return parts[-3] if len(parts) >= 3 else parts[0]
        return parts[-2]
    return domain


def check_typosquat(input_domain, threshold=2):
    """
    Check if a domain is a typosquat of a legitimate domain
    
    Args:
        input_domain: The domain to check
        threshold: Maximum Levenshtein distance to consider as typosquat
        
    Returns:
        dict with 'is_typosquat', 'matched_domain', 'similarity', 'legit_info'
    """
    input_domain = input_domain.lower().replace('www.', '')
    input_name = extract_domain_name(input_domain)
    normalized_input = normalize_typosquat(input_name)
    
    best_match = None
    best_similarity = float('inf')
    
    for legit_domain, info in CURATED_LEGIT_DOMAINS.items():
        legit_name = extract_domain_name(legit_domain)
        
        # Check if it's the exact legitimate domain
        if input_domain == legit_domain or input_domain.endswith('.' + legit_domain):
            return {
                'is_typosquat': False,
                'is_legitimate': True,
                'matched_domain': legit_domain,
                'legit_info': info,
                'similarity': 1.0
            }
        
        # Check normalized version (catches 3th3rscan -> etherscan)
        normalized_legit = normalize_typosquat(legit_name)
        
        if normalized_input == normalized_legit and input_name != legit_name:
            return {
                'is_typosquat': True,
                'is_legitimate': False,
                'matched_domain': legit_domain,
                'legit_info': info,
                'similarity': 0.95,
                'detection_method': 'character_substitution'
            }
        
        # Check Levenshtein distance
        distance = levenshtein_distance(input_name, legit_name)
        
        # Also check against normalized versions
        norm_distance = levenshtein_distance(normalized_input, normalized_legit)
        
        min_distance = min(distance, norm_distance)
        
        if min_distance <= threshold and min_distance < best_similarity:
            best_similarity = min_distance
            best_match = (legit_domain, info)
    
    if best_match and best_similarity <= threshold:
        legit_domain, info = best_match
        legit_name = extract_domain_name(legit_domain)
        similarity = 1 - (best_similarity / max(len(input_name), len(legit_name)))
        
        return {
            'is_typosquat': True,
            'is_legitimate': False,
            'matched_domain': legit_domain,
            'legit_info': info,
            'similarity': similarity,
            'distance': best_similarity,
            'detection_method': 'levenshtein'
        }
    
    return {
        'is_typosquat': False,
        'is_legitimate': False,
        'matched_domain': None,
        'legit_info': None,
        'similarity': 0
    }


def is_legitimate_domain(domain):
    """Check if a domain is in our legitimate domains list"""
    domain = domain.lower().replace('www.', '')
    
    # Exact match
    if domain in CURATED_LEGIT_DOMAINS:
        return True, CURATED_LEGIT_DOMAINS[domain]
    
    # Check if subdomain of legitimate domain
    for legit_domain in CURATED_LEGIT_DOMAINS:
        if domain.endswith('.' + legit_domain):
            return True, CURATED_LEGIT_DOMAINS[legit_domain]
    
    return False, None


def get_all_legit_domains():
    """Return all legitimate domains"""
    return CURATED_LEGIT_DOMAINS


def get_brand_names():
    """Return list of brand names for keyword matching"""
    brands = set()
    for domain, info in CURATED_LEGIT_DOMAINS.items():
        # Extract brand name from domain
        name = extract_domain_name(domain)
        brands.add(name)
        # Also add the display name (lowercased, no spaces)
        brands.add(info['name'].lower().replace(' ', ''))
    return list(brands)


# Test the module
if __name__ == '__main__':
    test_domains = [
        'eth3rscan.com',      # Typosquat of etherscan
        'g1thub.com',         # Typosquat of github
        'go0gle.com',         # Typosquat of google
        'rnicrosoft.com',     # Typosquat of microsoft (rn -> m)
        'paypa1.com',         # Typosquat of paypal
        'faceb00k.com',       # Typosquat of facebook
        'discord.com',        # Legitimate
        'etherscan.io',       # Legitimate
        'github.com',         # Legitimate
        'unisvvap.org',       # Typosquat of uniswap (vv -> w)
        'metamask-io.com',    # Similar to metamask
        'binancee.com',       # Extra letter
        'coinbose.com',       # Wrong letter
    ]
    
    print("Typosquat Detection Test Results:")
    print("=" * 60)
    for domain in test_domains:
        result = check_typosquat(domain)
        if result['is_legitimate']:
            print(f"✅ {domain:25} -> LEGITIMATE ({result['matched_domain']})")
        elif result['is_typosquat']:
            print(f"⚠️  {domain:25} -> TYPOSQUAT of {result['matched_domain']} ({result['legit_info']['name']})")
            print(f"   Detection: {result.get('detection_method', 'unknown')}, Similarity: {result['similarity']:.2f}")
        else:
            print(f"❓ {domain:25} -> UNKNOWN")
    print("=" * 60)
