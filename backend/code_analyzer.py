"""
Website Code Analyzer for Wallet Drainer Detection
===================================================

This module fetches website source code and analyzes it for malicious patterns
that could indicate wallet drainer functionality.

Detects:
- setApprovalForAll() calls (NFT drainers)
- approve() with unlimited amounts (ERC20 drainers)
- eth_sign / personal_sign abuse
- permit() signatures (gasless drainers)
- Obfuscated malicious code
- External scripts from suspicious domains

NOTE: Many patterns (like approve, permit) are used by LEGITIMATE sites too.
This analyzer focuses on SUSPICIOUS usage patterns, not just function presence.
Results should be combined with domain reputation for accurate assessment.
"""

import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import time

# Request timeout and headers
TIMEOUT = 15
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Cache-Control': 'max-age=0',
}

# TRUSTED DOMAINS - reduce severity for known legitimate sites
TRUSTED_DEFI_DOMAINS = {
    # DeFi
    'uniswap.org', 'app.uniswap.org',
    'aave.com', 'app.aave.com',
    'opensea.io', 'blur.io',
    'compound.finance', 'curve.fi',
    'sushi.com', '1inch.io',
    'pancakeswap.finance', 'gmx.io',
    'lido.fi', 'eigenlayer.xyz',
    'balancer.fi', 'yearn.finance',
    'metamask.io', 'rainbow.me',
    'safe.global', 'gnosis-safe.io',
    # Major websites (non-crypto) - skip analysis entirely
    'youtube.com', 'www.youtube.com',
    'google.com', 'www.google.com',
    'github.com', 'www.github.com',
    'twitter.com', 'x.com',
    'facebook.com', 'www.facebook.com',
    'instagram.com', 'www.instagram.com',
    'linkedin.com', 'www.linkedin.com',
    'reddit.com', 'www.reddit.com',
    'amazon.com', 'www.amazon.com',
    'netflix.com', 'www.netflix.com',
    'microsoft.com', 'www.microsoft.com',
    'apple.com', 'www.apple.com',
    'discord.com', 'discord.gg',
    'telegram.org', 't.me',
    'medium.com', 'substack.com',
    'notion.so', 'figma.com',
    'stackoverflow.com',
}

# TRUSTED CDN & ANALYTICS DOMAINS - Never flag scripts from these
TRUSTED_CDN_DOMAINS = {
    # Google Services
    'google.com', 'www.google.com', 'google-analytics.com', 'googletagmanager.com',
    'googleapis.com', 'gstatic.com', 'doubleclick.net', 'googlesyndication.com',
    # CDNs
    'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com', 'jsdelivr.net',
    'cloudflare.com', 'cf.com', 'cloudflareinsights.com',
    # Analytics & Tracking (Legit)
    'facebook.net', 'connect.facebook.net',
    'analytics.twitter.com', 'platform.twitter.com',
    'cdn.segment.com', 'segment.com', 'segment.io',
    'hotjar.com', 'static.hotjar.com',
    'mixpanel.com',
    # Major Services
    'stripe.com', 'js.stripe.com',
    'paypal.com',
    'recaptcha.net', 'www.recaptcha.net',
    # Web3 Infrastructure
    'infura.io', 'alchemy.com', 'quicknode.com',
    'etherscan.io', 'etherscan.com',
    'walletconnect.com', 'walletconnect.org',
}

# Malicious code patterns to detect
# CRITICAL = Almost always malicious
# HIGH = Suspicious, needs context
# MEDIUM = Common in both legit and malicious, flagged for awareness
# INFO = Just informational
DRAINER_PATTERNS = {
    # ========== CRITICAL - These are almost always malicious ==========
    'inferno_drainer': {
        'pattern': r'inferno|seaport.*fulfillOrder.*drain|blur.*executeSell.*steal',
        'severity': 'critical',
        'description': 'Known drainer kit signature detected (Inferno Drainer). This is malware.',
        'category': 'Known Drainer Kit',
        'legit_use': False
    },
    'pink_drainer': {
        'pattern': r'pinkdrainer|pink_drainer|multicall.*drain.*all|batchTransfer.*steal',
        'severity': 'critical',
        'description': 'Known drainer kit signature detected (Pink Drainer). This is malware.',
        'category': 'Known Drainer Kit',
        'legit_use': False
    },
    'angel_drainer': {
        'pattern': r'angeldrainer|angel.*claim.*drain|venom.*drain.*wallet',
        'severity': 'critical',
        'description': 'Known drainer kit signature detected (Angel/Venom Drainer). This is malware.',
        'category': 'Known Drainer Kit',
        'legit_use': False
    },
    'private_key_input': {
        'pattern': r'<input[^>]*(?:private.?key|seed.?phrase|mnemonic|secret.?key)[^>]*>|getElementById\(["\'](?:privateKey|seedPhrase|mnemonic)',
        'severity': 'critical',
        'description': 'Website asks for private key or seed phrase input. NEVER enter these anywhere!',
        'category': 'Key Theft',
        'legit_use': False
    },
    'eth_sign_raw': {
        'pattern': r'eth_sign\s*["\'][^"\']*["\']|request\(\s*{\s*method:\s*["\']eth_sign["\']',
        'severity': 'critical',
        'description': 'Uses eth_sign which can sign arbitrary data. High risk of asset theft.',
        'category': 'Dangerous Signature',
        'legit_use': True  # Legitimate dApps like Uniswap use this for signatures
    },
    'hidden_approval_all': {
        'pattern': r'setApprovalForAll\s*\([^)]*true[^)]*\)(?!.*(?:opensea|blur|uniswap|legitimate))',
        'severity': 'critical',
        'description': 'Hidden setApprovalForAll(true) - grants full NFT access to attacker.',
        'category': 'NFT Drainer',
        'legit_use': False
    },
    
    # ========== HIGH - Suspicious patterns that need investigation ==========
    'obfuscation_eval': {
        'pattern': r'eval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(|Function\s*\(["\']["\'],\s*(?:atob|unescape)',
        'severity': 'high',
        'description': 'Obfuscated code execution detected. Malicious code may be hidden.',
        'category': 'Obfuscation',
        'legit_use': False
    },
    'suspicious_hex_payload': {
        'pattern': r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){20,}',
        'severity': 'high',
        'description': 'Long hex-encoded payload detected. Often used to hide malicious code.',
        'category': 'Obfuscation',
        'legit_use': False
    },
    'clipboard_address_swap': {
        'pattern': r'navigator\.clipboard\.writeText\s*\([^)]*0x[a-fA-F0-9]{40}',
        'severity': 'high',
        'description': 'Clipboard manipulation with crypto address. May swap copied addresses.',
        'category': 'Clipboard Hijack',
        'legit_use': False
    },
    'fake_claim_airdrop': {
        'pattern': r'(?:claim|airdrop|reward)\s*(?:your|free|bonus).*(?:connect.*wallet|approve)|(?:free|bonus)\s+(?:mint|nft|token|crypto|eth|coin).*(?:claim|get|receive)',
        'severity': 'high',
        'description': 'Suspicious claim/airdrop pattern combined with wallet connection.',
        'category': 'Fake Airdrop',
        'legit_use': False
    },
    'max_approval_hardcoded': {
        'pattern': r'approve\s*\([^,]+,\s*["\']?(?:0x[fF]{64}|115792089237316195423570985008687907853269984665640564039457584007913129639935)["\']?\s*\)',
        'severity': 'high',
        'description': 'Hardcoded unlimited approval amount. Legitimate apps usually let users choose.',
        'category': 'Unlimited Approval',
        'legit_use': False
    },
    
    # ========== MEDIUM - Context dependent, flag for awareness ==========
    'permit_signature': {
        'pattern': r'signTypedData.*[Pp]ermit|permit\s*\(\s*owner|EIP2612|permitSingle|permitBatch',
        'severity': 'medium',
        'description': 'Permit signature pattern - allows gasless approvals. Used by both legit dApps and drainers.',
        'category': 'Permit Function',
        'legit_use': True  # Uniswap, 1inch use this
    },
    'transfer_from_pattern': {
        'pattern': r'(?:safe)?[Tt]ransferFrom\s*\(\s*(?:msg\.sender|owner|from)',
        'severity': 'medium',
        'description': 'TransferFrom pattern detected. Normal for DeFi, but verify the destination.',
        'category': 'Transfer Function',
        'legit_use': True
    },
    
    # ========== INFO - Just informational, not necessarily bad ==========
    'wallet_connect_usage': {
        'pattern': r'@walletconnect|walletconnect.*v2|relay\.walletconnect\.com',
        'severity': 'info',
        'description': 'WalletConnect integration detected. This is normal for most dApps.',
        'category': 'Wallet Connection',
        'legit_use': True
    },
    'contract_interaction': {
        'pattern': r'ethers\.Contract|web3\.eth\.Contract|new Contract\s*\(',
        'severity': 'info',
        'description': 'Smart contract interaction code. Normal for any dApp.',
        'category': 'Contract Usage',
        'legit_use': True
    },
    
    # ========== SCAM INDICATORS - General scam site detection ==========
    'fake_countdown_urgency': {
        'pattern': r'countdown|timer.*(?:expire|end|left)|(?:hurry|limited|act now|last chance).*(?:offer|bonus|reward)',
        'severity': 'medium',
        'description': 'Urgency tactics detected (countdown/limited offer). Common in scam sites.',
        'category': 'Scam Tactics',
        'legit_use': False
    },
    'fake_profit_claims': {
        'pattern': r'(?:guaranteed|daily|weekly|monthly)\s*(?:profit|return|income|yield).*\d+\s*%|earn\s+\$?\d+(?:,\d+)*\s*(?:daily|per day|weekly)',
        'severity': 'high',
        'description': 'Unrealistic profit claims detected. Likely investment scam.',
        'category': 'Investment Scam',
        'legit_use': False
    },
    'fake_testimonials': {
        'pattern': r'(?:testimonial|review|user.?said).*(?:made|earned|withdrew)\s*\$?\d+(?:,\d+)*|"[^"]*(?:withdrew|profit|earned)[^"]*\$\d+[^"]*"',
        'severity': 'medium',
        'description': 'Fake testimonials with specific earnings. Common scam tactic.',
        'category': 'Fake Testimonials',
        'legit_use': False
    },
    'crypto_deposit_address': {
        'pattern': r'deposit.*(?:address|wallet).*(?:0x[a-fA-F0-9]{40}|bc1|[13][a-zA-Z0-9]{25,34})|send.*(?:btc|eth|usdt).*to',
        'severity': 'high',
        'description': 'Direct crypto deposit solicitation. Could be recovery scam or fake investment.',
        'category': 'Deposit Scam',
        'legit_use': False
    },
    'impersonation_brand': {
        'pattern': r'(?:official|verify|support).*(?:binance|coinbase|kraken|metamask|trust.?wallet)|(?:binance|coinbase|kraken).*(?:official|support|help)',
        'severity': 'high',
        'description': 'Possible brand impersonation detected. Verify you are on the real website.',
        'category': 'Impersonation',
        'legit_use': False
    },
    'login_credential_theft': {
        'pattern': r'<input[^>]*(?:password|login|email)[^>]*>.*<input[^>]*(?:password|login)[^>]*>|getElementById\(["\'](?:password|userPassword)',
        'severity': 'medium',
        'description': 'Login form detected. Ensure you are on the legitimate website.',
        'category': 'Credential Theft',
        'legit_use': True
    },
    'suspicious_domain_age': {
        'pattern': r'(?:registered|created).*202[5-9]|domain.*(?:new|recent)',
        'severity': 'low',
        'description': 'Website may be newly registered. New domains are riskier.',
        'category': 'Domain Age',
        'legit_use': True
    },
    'fake_live_chat': {
        'pattern': r'live.?chat.*(?:online|available|24.?7)|support.*(?:agent|representative).*online',
        'severity': 'low',
        'description': 'Live chat widget detected. Scam sites often use fake support.',
        'category': 'Fake Support',
        'legit_use': True
    },
    'recovery_scam_keywords': {
        'pattern': r'(?:recover|retrieve|get back).*(?:stolen|lost|scam).*(?:crypto|funds|bitcoin|money)|(?:hack|scam).*(?:recovery|retrieval)',
        'severity': 'critical',
        'description': 'Recovery scam keywords detected. NO ONE can recover stolen crypto!',
        'category': 'Recovery Scam',
        'legit_use': True  # Help docs may mention "recover lost funds" as warnings
    },
    'pump_dump_signals': {
        'pattern': r'(?:pump|moon|100x|1000x).*(?:signal|alert|call)|(?:insider|whale).*(?:tip|info|signal)',
        'severity': 'high',
        'description': 'Pump & dump signal group indicators. These are scams.',
        'category': 'Pump Scam',
        'legit_use': False
    },
    'fake_exchange_platform': {
        'pattern': r'(?:trade|trading|exchange).*(?:platform|system).*(?:register|signup|join)|(?:instant|fast).*(?:withdraw|withdrawal)',
        'severity': 'medium',
        'description': 'Trading platform detected. Verify this is a real registered exchange.',
        'category': 'Fake Exchange',
        'legit_use': True
    },
    'whatsapp_telegram_support': {
        'pattern': r'(?:whatsapp|telegram|contact).*(?:\+\d{10,}|t\.me/|wa\.me/)|(?:support|help).*(?:whatsapp|telegram)',
        'severity': 'medium',
        'description': 'Support via WhatsApp/Telegram. Legitimate companies use official channels.',
        'category': 'Suspicious Support',
        'legit_use': False
    }
}

# Suspicious external domains
SUSPICIOUS_SCRIPT_DOMAINS = [
    'pastebin.com', 'paste.ee', 'hastebin.com',  # Paste sites - never legit for scripts
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl',  # URL shorteners
    '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs often abused
]


def fetch_website_code(url):
    """
    Fetch HTML and JavaScript code from a website.
    Returns dict with HTML, inline scripts, and external script URLs.
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    if not url.startswith('http'):
        url = 'https://' + url
    
    result = {
        'url': url,
        'html': None,
        'scripts': [],
        'inline_scripts': [],
        'external_scripts': [],
        'error': None
    }
    
    # Try HTTPS first, then HTTP if it fails
    urls_to_try = [url]
    if url.startswith('https://'):
        urls_to_try.append(url.replace('https://', 'http://'))
    
    last_error = None
    
    for try_url in urls_to_try:
        try:
            # Create a session for better connection handling
            session = requests.Session()
            session.headers.update(HEADERS)
            
            # Try with SSL verification first, then without if it fails
            for verify_ssl in [True, False]:
                try:
                    response = session.get(
                        try_url, 
                        timeout=TIMEOUT, 
                        allow_redirects=True,
                        verify=verify_ssl
                    )
                    response.raise_for_status()
                    
                    result['html'] = response.text
                    result['final_url'] = response.url
                    result['ssl_verified'] = verify_ssl
                    
                    # Parse HTML
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract inline scripts
                    for i, script in enumerate(soup.find_all('script')):
                        if script.string:
                            result['inline_scripts'].append({
                                'index': i,
                                'content': script.string,
                                'length': len(script.string)
                            })
                        elif script.get('src'):
                            src = script.get('src')
                            # Convert relative URLs to absolute
                            if not src.startswith('http'):
                                src = urljoin(try_url, src)
                            result['external_scripts'].append({
                                'index': i,
                                'src': src,
                                'content': None
                            })
                    
                    # Fetch external scripts (limit to first 3 to avoid timeout)
                    for i, ext_script in enumerate(result['external_scripts'][:3]):
                        try:
                            script_response = session.get(
                                ext_script['src'], 
                                timeout=8,
                                verify=verify_ssl
                            )
                            if script_response.status_code == 200:
                                result['external_scripts'][i]['content'] = script_response.text[:50000]
                                result['external_scripts'][i]['length'] = len(script_response.text)
                        except Exception as e:
                            result['external_scripts'][i]['error'] = str(e)[:100]
                    
                    return result  # Success!
                    
                except requests.exceptions.SSLError:
                    if verify_ssl:
                        continue  # Try without SSL verification
                    raise
                    
        except requests.exceptions.Timeout:
            last_error = 'Request timed out - website took too long to respond'
        except requests.exceptions.SSLError as e:
            last_error = f'SSL/TLS error - website has certificate issues'
        except requests.exceptions.ConnectionError as e:
            error_str = str(e).lower()
            if 'name or service not known' in error_str or 'nodename nor servname' in error_str:
                last_error = 'Domain does not exist or DNS resolution failed'
            elif 'connection refused' in error_str:
                last_error = 'Connection refused - website may be down'
            elif 'no route to host' in error_str:
                last_error = 'Cannot reach website - network issue'
            else:
                last_error = 'Could not connect to website'
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response else 'unknown'
            if status == 403:
                last_error = 'Access forbidden (403) - website blocks automated requests'
            elif status == 404:
                last_error = 'Page not found (404)'
            elif status == 503:
                last_error = 'Service unavailable (503) - website may be overloaded'
            elif status == 429:
                last_error = 'Rate limited (429) - too many requests'
            else:
                last_error = f'HTTP error {status}'
        except Exception as e:
            last_error = str(e)[:200]
    
    result['error'] = last_error
    return result


def is_trusted_domain(url):
    """Check if URL belongs to a trusted DeFi domain."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        return domain in TRUSTED_DEFI_DOMAINS or any(domain.endswith('.' + td) for td in TRUSTED_DEFI_DOMAINS)
    except:
        return False

def is_trusted_cdn(url_or_domain):
    """Check if URL/domain is from a trusted CDN or analytics service."""
    try:
        if not url_or_domain:
            return False
        # Handle both URLs and domains
        if url_or_domain.startswith('http'):
            parsed = urlparse(url_or_domain)
            domain = parsed.netloc.lower()
        else:
            domain = url_or_domain.lower()
        
        domain = domain.replace('www.', '')
        # Check exact match or subdomain match
        return domain in TRUSTED_CDN_DOMAINS or any(domain.endswith('.' + cdn) for cdn in TRUSTED_CDN_DOMAINS)
    except:
        return False


# Behavioral Pattern Learning - Suspicious pattern combinations
SUSPICIOUS_COMBINATIONS = {
    # Critical combinations (3+ patterns)
    'drainer_combo_critical': {
        'patterns': ['wallet_connect_pattern', 'obfuscation_eval', 'external_data_exfil'],
        'min_patterns': 3,
        'severity': 'critical',
        'description': 'Highly suspicious: Wallet connection + obfuscation + data exfiltration'
    },
    'approval_drainer': {
        'patterns': ['approve_unlimited', 'obfuscation_eval', 'external_data_exfil'],
        'min_patterns': 3,
        'severity': 'critical',
        'description': 'Approval drainer pattern: Unlimited approval + obfuscation + external call'
    },
    'clipboard_hijack_combo': {
        'patterns': ['clipboard_address_swap', 'obfuscation_eval'],
        'min_patterns': 2,
        'severity': 'critical',
        'description': 'Clipboard hijacking with obfuscation detected'
    },
    
    # High severity combinations (2 patterns)
    'permit_drainer': {
        'patterns': ['permit_signature', 'obfuscation_eval'],
        'min_patterns': 2,
        'severity': 'high',
        'description': 'Suspicious: Permit signature with code obfuscation'
    },
    'approval_with_obfuscation': {
        'patterns': ['approve_unlimited', 'suspicious_hex_payload'],
        'min_patterns': 2,
        'severity': 'high',
        'description': 'Suspicious: Token approval with obfuscated payload'
    },
    'fake_claim_with_urgency': {
        'patterns': ['fake_claim_airdrop', 'fake_countdown_urgency'],
        'min_patterns': 2,
        'severity': 'high',
        'description': 'Scam tactics: Fake airdrop claim with urgency tactics'
    }
}


def detect_pattern_combinations(all_findings):
    """
    Detect suspicious combinations of patterns (Behavioral Pattern Learning).
    Returns additional high-severity findings based on pattern combinations.
    """
    if len(all_findings) < 2:
        return []
    
    # Extract pattern names from findings
    detected_patterns = set(f['pattern'] for f in all_findings)
    
    combination_findings = []
    
    for combo_name, combo_info in SUSPICIOUS_COMBINATIONS.items():
        required_patterns = set(combo_info['patterns'])
        matched_patterns = required_patterns & detected_patterns
        
        # Check if we have enough patterns for this combination
        if len(matched_patterns) >= combo_info['min_patterns']:
            # Find the findings that are part of this combination
            related_findings = [f for f in all_findings if f['pattern'] in matched_patterns]
            
            # Create a combined finding
            combined_finding = {
                'pattern': combo_name,
                'category': 'Behavioral Pattern',
                'severity': combo_info['severity'],
                'description': combo_info['description'],
                'line_number': min(f['line_number'] for f in related_findings),
                'matched_code': f"PATTERN COMBINATION: {', '.join(sorted(matched_patterns))}",
                'context': f"Multiple suspicious patterns detected:\n" + "\n".join(
                    f"  - {f['category']}: {f['pattern']}" for f in related_findings
                ),
                'source': 'pattern_combination',
                'legit_use': False,
                'is_combination': True,
                'matched_patterns': list(matched_patterns)
            }
            
            combination_findings.append(combined_finding)
    
    return combination_findings


def analyze_code_for_drainers(code, source_name='inline', is_trusted=False):
    """
    Analyze JavaScript code for drainer patterns.
    Returns list of detected patterns with code snippets.
    
    If is_trusted=True, only returns critical/high severity findings
    and skips patterns that have legit_use=True.
    """
    if not code:
        return []
    
    # Skip analysis for trusted CDN scripts entirely
    if is_trusted_cdn(source_name):
        return []
    
    findings = []
    lines = code.split('\n')
    
    for pattern_name, pattern_info in DRAINER_PATTERNS.items():
        # Skip legitimate patterns on trusted domains
        if is_trusted and pattern_info.get('legit_use', False):
            continue
        
        # On trusted domains, ONLY report known drainer kits (not common DeFi patterns)
        if is_trusted:
            # Only show patterns from "Known Drainer Kit" and "Key Theft" categories
            if pattern_info['category'] not in ['Known Drainer Kit', 'Key Theft']:
                continue
            
        try:
            regex = re.compile(pattern_info['pattern'], re.IGNORECASE | re.MULTILINE)
            
            for match in regex.finditer(code):
                # Get line number
                line_start = code[:match.start()].count('\n') + 1
                
                # Get context (3 lines before and after)
                start_line = max(0, line_start - 3)
                end_line = min(len(lines), line_start + 3)
                
                context_lines = []
                for i in range(start_line, end_line):
                    if i < len(lines):
                        prefix = '>>> ' if i == line_start - 1 else '    '
                        context_lines.append(f"{prefix}{i+1:4d} | {lines[i][:200]}")  # Limit line length
                
                # Get the matched code snippet
                matched_text = match.group(0)[:200]  # Limit match length
                
                finding = {
                    'pattern': pattern_name,
                    'category': pattern_info['category'],
                    'severity': pattern_info['severity'],
                    'description': pattern_info['description'],
                    'line_number': line_start,
                    'matched_code': matched_text,
                    'context': '\n'.join(context_lines),
                    'source': source_name,
                    'legit_use': pattern_info.get('legit_use', False)
                }
                
                # Avoid duplicate findings for same pattern on same line
                is_duplicate = any(
                    f['pattern'] == pattern_name and f['line_number'] == line_start 
                    for f in findings
                )
                if not is_duplicate:
                    findings.append(finding)
                    
        except re.error:
            continue  # Skip invalid regex patterns
    
    return findings


def check_suspicious_externals(external_scripts):
    """
    Check if external scripts are loaded from suspicious domains.
    Only flag genuinely suspicious sources, not CDNs.
    """
    suspicious = []
    
    for script in external_scripts:
        src = script.get('src', '')
        
        # Skip trusted CDNs
        if is_trusted_cdn(src):
            continue
            
        parsed = urlparse(src)
        domain = parsed.netloc.lower()
        
        for sus_domain in SUSPICIOUS_SCRIPT_DOMAINS:
            if sus_domain in domain:
                suspicious.append({
                    'src': src,
                    'reason': f'Script loaded from suspicious domain: {sus_domain}',
                    'severity': 'high'
                })
                break
    
    return suspicious


def analyze_website(url, simulation_result=None):
    """
    Main function to analyze a website for drainer code.
    
    Args:
        url: Website URL to analyze
        simulation_result: Optional dApp simulation result for context-aware scoring
        
    Returns comprehensive analysis results with intelligent filtering.
    """
    print(f"[CODE ANALYZER] Analyzing: {url}")
    
    # Check if this is a trusted domain
    trusted = is_trusted_domain(url)
    if trusted:
        print(f"[CODE ANALYZER] Trusted domain detected - reducing false positives")
    
    # Context-Aware Scoring: Check simulation result
    simulation_is_safe = False
    if simulation_result:
        is_malicious = simulation_result.get('is_malicious', False)
        confidence = simulation_result.get('confidence', 0)
        simulation_is_safe = (not is_malicious) and (confidence >= 85)
        
        if simulation_is_safe:
            print(f"[CODE ANALYZER] Simulation marked as SAFE ({confidence}% confidence) - reducing code analysis")
    
    result = {
        'url': url,
        'analyzed_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'success',
        'is_trusted_domain': trusted,
        'simulation_is_safe': simulation_is_safe,
        'findings': [],
        'pattern_combinations': [],
        'summary': {
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        },
        'scripts_analyzed': 0,
        'suspicious_externals': [],
        'error': None
    }
    
    # Context-Aware: If both trusted AND simulation says safe, skip detailed analysis
    if trusted and simulation_is_safe:
        result['risk_level'] = 'CLEAN'
        result['note'] = 'Trusted domain verified safe by runtime simulation - skipping code analysis'
        print(f"[CODE ANALYZER] Skipping analysis - trusted domain + safe simulation")
        return result
    
    # Fetch website code
    website_data = fetch_website_code(url)
    
    if website_data.get('error'):
        result['status'] = 'error'
        result['error'] = website_data['error']
        return result
    
    all_findings = []
    
    # Analyze inline scripts
    for script in website_data.get('inline_scripts', []):
        findings = analyze_code_for_drainers(
            script['content'], 
            f"inline_script_{script['index']}",
            is_trusted=trusted
        )
        all_findings.extend(findings)
        result['scripts_analyzed'] += 1
    
    # Analyze external scripts
    for script in website_data.get('external_scripts', []):
        if script.get('content'):
            findings = analyze_code_for_drainers(
                script['content'],
                script['src'],
                is_trusted=trusted
            )
            all_findings.extend(findings)
            result['scripts_analyzed'] += 1
    
    # Analyze HTML for suspicious input fields (always check, even on trusted)
    if website_data.get('html'):
        html_findings = analyze_code_for_drainers(
            website_data['html'],
            'html_document',
            is_trusted=False  # Always check HTML for key theft patterns
        )
        # Only keep critical findings from HTML
        html_findings = [f for f in html_findings if f['severity'] == 'critical']
        all_findings.extend(html_findings)
    
    # Check for suspicious external scripts
    result['suspicious_externals'] = check_suspicious_externals(
        website_data.get('external_scripts', [])
    )
    
    # BEHAVIORAL PATTERN LEARNING: Detect suspicious combinations
    combination_findings = detect_pattern_combinations(all_findings)
    result['pattern_combinations'] = combination_findings
    
    # Merge combination findings with regular findings
    all_findings.extend(combination_findings)
    
    # Context-Aware Filtering: If simulation says safe, only keep critical+high
    if simulation_is_safe:
        all_findings = [f for f in all_findings if f['severity'] in ['critical', 'high']]
        print(f"[CODE ANALYZER] Filtered to critical/high only (simulation safe)")
    
    # Context-Aware Filtering: Require multiple patterns for untrusted domains
    if not trusted and not simulation_is_safe:
        # Count patterns by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0}
        for f in all_findings:
            if f['severity'] in severity_counts:
                severity_counts[f['severity']] += 1
        
        # If only 1 medium/high finding and no critical, it might be false positive
        # Keep it but note the low confidence
        if severity_counts['critical'] == 0 and severity_counts['high'] <= 1:
            result['low_confidence'] = True
            print(f"[CODE ANALYZER] Low confidence - single pattern detected, no combinations")
    
    # Sort findings by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    all_findings.sort(key=lambda x: severity_order.get(x['severity'], 5))
    
    # Limit findings to avoid huge responses
    result['findings'] = all_findings[:30]
    
    # Calculate summary
    for finding in all_findings:
        sev = finding['severity']
        if sev in result['summary']:
            result['summary'][sev] += 1
    result['summary']['total_findings'] = len(all_findings)
    
    # Determine overall risk level with context awareness
    if trusted:
        # For trusted domains, only critical findings matter
        if result['summary']['critical'] > 0:
            result['risk_level'] = 'CRITICAL'
        else:
            result['risk_level'] = 'CLEAN'
            result['note'] = 'Trusted domain - normal DeFi patterns detected but not flagged'
    elif simulation_is_safe:
        # If simulation says safe, require critical evidence to override
        if result['summary']['critical'] > 0:
            result['risk_level'] = 'HIGH'  # Downgrade from CRITICAL
            result['note'] = 'Simulation marked safe but code patterns detected - manual review suggested'
        else:
            result['risk_level'] = 'CLEAN'
            result['note'] = 'Verified safe by runtime simulation'
    else:
        # Standard risk calculation for unknown/untrusted domains
        if result['summary']['critical'] > 0 or len(combination_findings) > 0:
            result['risk_level'] = 'CRITICAL'
        elif result['summary']['high'] > 0:
            result['risk_level'] = 'HIGH'
        elif result['summary']['medium'] > 0:
            result['risk_level'] = 'MEDIUM'
        elif result['summary']['low'] > 0:
            result['risk_level'] = 'LOW'
        else:
            result['risk_level'] = 'CLEAN'
    
    # Add pattern combination note if detected
    if len(combination_findings) > 0:
        combo_note = f"{len(combination_findings)} suspicious pattern combination(s) detected"
        if 'note' in result:
            result['note'] += f" | {combo_note}"
        else:
            result['note'] = combo_note
    
    print(f"[CODE ANALYZER] Risk: {result['risk_level']} | Found {len(all_findings)} issues (Critical: {result['summary']['critical']}, High: {result['summary']['high']}, Combinations: {len(combination_findings)})")
    
    return result


# Test the module
if __name__ == '__main__':
    # Test with Uniswap (should be CLEAN since it's trusted)
    print("\n" + "="*60)
    print("Testing TRUSTED domain: app.uniswap.org")
    print("="*60)
    result = analyze_website('https://app.uniswap.org')
    print(f"Risk Level: {result.get('risk_level', 'N/A')}")
    print(f"Is Trusted: {result.get('is_trusted_domain', False)}")
    print(f"Findings: {result['summary']['total_findings']}")
    if result.get('note'):
        print(f"Note: {result['note']}")
    
    # Test with a random domain (should check everything)
    print("\n" + "="*60)
    print("Testing UNKNOWN domain: example.com")
    print("="*60)
    result2 = analyze_website('https://example.com')
    print(f"Risk Level: {result2.get('risk_level', 'N/A')}")
    print(f"Is Trusted: {result2.get('is_trusted_domain', False)}")
    print(f"Findings: {result2['summary']['total_findings']}")
