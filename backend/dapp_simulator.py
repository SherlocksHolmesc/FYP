"""
dApp Security Simulator - Runtime Testing for Web3 dApps

Tests actual dApp behavior by simulating wallet connection and monitoring
transaction requests in a controlled browser environment.

Similar to honeypot_simulator.py but for websites/dApps instead of token contracts.
"""

import time
import json
import re
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from web3 import Web3
from eth_account import Account

class DAppSimulator:
    """
    Runtime simulator for dApp security testing
    
    Opens dApps in headless browser, injects test wallet, monitors transaction
    requests, and detects malicious behavior.
    """
    
    # Common malicious patterns
    MALICIOUS_PATTERNS = {
        'UNLIMITED_APPROVAL': {
            'description': 'Requests unlimited token approval',
            'severity': 'CRITICAL',
            'confidence': 99
        },
        'HIDDEN_TRANSFER': {
            'description': 'Attempts to transfer tokens to unknown address',
            'severity': 'CRITICAL',
            'confidence': 99
        },
        'SUSPICIOUS_CONTRACT': {
            'description': 'Interacts with unverified or suspicious contract',
            'severity': 'HIGH',
            'confidence': 85
        },
        'PHISHING_SIGNATURE': {
            'description': 'Requests signing of suspicious message',
            'severity': 'CRITICAL',
            'confidence': 95
        },
        'CLIPBOARD_HIJACK': {
            'description': 'Attempts to access or modify clipboard',
            'severity': 'HIGH',
            'confidence': 90
        },
        'EXCESSIVE_PERMISSIONS': {
            'description': 'Requests more permissions than necessary',
            'severity': 'MEDIUM',
            'confidence': 75
        }
    }
    
    # Known good contracts (Uniswap, Aave, etc.)
    TRUSTED_CONTRACTS = [
        '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',  # Uniswap V2 Router
        '0xE592427A0AEce92De3Edee1F18E0157C05861564',  # Uniswap V3 Router
        '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',  # Uniswap V3 Router 2
        '0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9',  # Aave Lending Pool
        '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',  # USDC
        '0xdAC17F958D2ee523a2206206994597C13D831ec7',  # USDT
    ]
    
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.w3 = Web3(Web3.HTTPProvider('https://eth-mainnet.g.alchemy.com/v2/demo'))
        
        # Create test wallet
        self.test_account = Account.create()
        self._log(f"[INIT] Test wallet created: {self.test_account.address}")
        
        self.playwright = None
        self.browser = None
        self.context = None
    
    def _log(self, message):
        """Print log message if verbose mode enabled"""
        if self.verbose:
            print(message)
    
    def setup_browser(self):
        """Initialize Playwright browser with wallet injection capabilities"""
        self._log("\n[1] Setting up browser environment...")
        
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(
            headless=True,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-web-security',
                '--disable-features=IsolateOrigins,site-per-process'
            ]
        )
        
        # Create context with permissions
        self.context = self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            permissions=['clipboard-read', 'clipboard-write']
        )
        
        self._log("    ✓ Browser initialized")
    
    def inject_wallet(self, page):
        """
        Inject mock Web3 wallet (like MetaMask) into page
        
        This allows us to intercept wallet connection requests and
        transaction requests from the dApp
        """
        self._log("\n[2] Injecting test wallet...")
        
        # Wallet injection script
        wallet_script = f"""
        // Mock Ethereum provider (like MetaMask)
        window.ethereum = {{
            isMetaMask: true,
            selectedAddress: '{self.test_account.address}',
            chainId: '0x1',
            networkVersion: '1',
            _state: {{
                accounts: ['{self.test_account.address}'],
                isConnected: true,
                isUnlocked: true
            }},
            
            // Store transaction requests
            _transactionRequests: [],
            _signatureRequests: [],
            _approvalRequests: [],
            
            // Request accounts (wallet connection)
            request: async function(args) {{
                console.log('[WALLET] Request:', args);
                
                if (args.method === 'eth_requestAccounts') {{
                    return ['{self.test_account.address}'];
                }}
                
                if (args.method === 'eth_accounts') {{
                    return ['{self.test_account.address}'];
                }}
                
                if (args.method === 'eth_chainId') {{
                    return '0x1';
                }}
                
                if (args.method === 'eth_sendTransaction') {{
                    console.log('[WALLET] Transaction request:', args.params[0]);
                    this._transactionRequests.push(args.params[0]);
                    
                    // Mark in DOM for extraction
                    window._W3RG_TX_REQUESTS = this._transactionRequests;
                    
                    // Return fake tx hash
                    return '0x' + '0'.repeat(64);
                }}
                
                if (args.method === 'personal_sign' || args.method === 'eth_sign') {{
                    console.log('[WALLET] Signature request:', args.params);
                    this._signatureRequests.push(args.params);
                    window._W3RG_SIG_REQUESTS = this._signatureRequests;
                    return '0x' + '0'.repeat(130);
                }}
                
                if (args.method === 'wallet_watchAsset') {{
                    console.log('[WALLET] Token approval request:', args.params);
                    this._approvalRequests.push(args.params);
                    window._W3RG_APPROVAL_REQUESTS = this._approvalRequests;
                    return true;
                }}
                
                return null;
            }},
            
            // Legacy methods
            enable: async function() {{
                return ['{self.test_account.address}'];
            }},
            
            sendAsync: function(payload, callback) {{
                this.request(payload).then(result => callback(null, {{result}}));
            }},
            
            send: function(payload, callback) {{
                if (callback) {{
                    this.sendAsync(payload, callback);
                }} else {{
                    return this.request(payload);
                }}
            }}
        }};
        
        // Also inject as window.web3 for older dApps
        window.web3 = {{
            currentProvider: window.ethereum,
            eth: {{
                defaultAccount: '{self.test_account.address}'
            }}
        }};
        
        // Mark as injected
        window._W3RG_WALLET_INJECTED = true;
        console.log('[W3RG] Test wallet injected');
        """
        
        page.add_init_script(wallet_script)
        self._log(f"    ✓ Wallet injected: {self.test_account.address}")
    
    def monitor_network(self, page):
        """Monitor network requests for suspicious activity"""
        suspicious_requests = []
        
        # Whitelist known good domains (legitimate services)
        trusted_domains = [
            'uniswap.org', 'app.uniswap.org', 'interface.gateway.uniswap.org',
            'aave.com', 'compound.finance', 'curve.fi',
            'sentry.io', 'amplitude.com', 'segment.com',  # Analytics
            'walletconnect.org', 'walletconnect.com',  # WalletConnect protocol
            'trustwallet.com', 'github.com', 'githubusercontent.com',  # Asset repos
            'google-analytics.com', 'googletagmanager.com'  # Analytics
        ]
        
        def is_trusted(url):
            """Check if URL belongs to trusted domain"""
            for domain in trusted_domains:
                if domain in url.lower():
                    return True
            return False
        
        def handle_request(request):
            url = request.url
            
            # Skip trusted domains
            if is_trusted(url):
                return
            
            # Check for ACTUAL data exfiltration (sending private keys, seeds, etc.)
            if request.method == 'POST' and request.post_data:
                try:
                    data_lower = request.post_data.lower()
                    # High-confidence malicious patterns
                    if any(word in data_lower for word in ['privatekey', 'private_key', 'mnemonic', 'seed_phrase', 'seedphrase']):
                        suspicious_requests.append({
                            'type': 'PRIVATE_KEY_EXFILTRATION',
                            'url': url,
                            'description': 'Attempting to send private keys/seeds to external server!'
                        })
                except:
                    pass
            
            # Check for suspicious domains (typosquatting, look-alikes)
            suspicious_tlds = ['.xyz', '.top', '.live', '.site', '.online', '.click']
            if any(tld in url for tld in suspicious_tlds):
                # But only if it's claiming to be a major service
                if any(brand in url.lower() for brand in ['uniswap', 'metamask', 'aave', 'compound', 'opensea']):
                    suspicious_requests.append({
                        'type': 'PHISHING_DOMAIN',
                        'url': url,
                        'description': f'Suspicious domain mimicking legitimate service'
                    })
        
        page.on('request', handle_request)
        return suspicious_requests
    
    def analyze_transactions(self, transactions):
        """
        Analyze captured transaction requests for malicious patterns
        
        Args:
            transactions: List of transaction objects from dApp
        
        Returns:
            list: List of detected threats
        """
        threats = []
        
        if not transactions:
            return threats
        
        for i, tx in enumerate(transactions):
            self._log(f"\n    [TX {i+1}] Analyzing transaction...")
            self._log(f"        To: {tx.get('to', 'N/A')}")
            self._log(f"        Value: {tx.get('value', '0')}")
            self._log(f"        Data: {tx.get('data', '0x')[:50]}...")
            
            # Check for unlimited approval
            data = tx.get('data', '')
            if data and len(data) > 10:
                # Check for approve() function (0x095ea7b3)
                if data.startswith('0x095ea7b3'):
                    # Extract amount (bytes 36-68)
                    try:
                        amount_hex = data[74:138]  # Skip function selector and address
                        amount = int(amount_hex, 16)
                        
                        # Check if it's max uint256 (unlimited approval)
                        max_uint256 = 2**256 - 1
                        if amount > max_uint256 * 0.9:  # 90% of max = suspicious
                            threats.append({
                                'type': 'UNLIMITED_APPROVAL',
                                'severity': 'CRITICAL',
                                'confidence': 99,
                                'description': f'Requests unlimited token approval',
                                'evidence': f'Amount: {amount} (near max uint256)',
                                'transaction_index': i
                            })
                            self._log(f"        🚨 UNLIMITED APPROVAL DETECTED!")
                    except:
                        pass
                
                # Check for transfer() or transferFrom() to unknown address
                if data.startswith('0xa9059cbb') or data.startswith('0x23b872dd'):
                    try:
                        # Extract recipient address
                        recipient = '0x' + data[34:74]
                        recipient = Web3.to_checksum_address(recipient)
                        
                        # Check if recipient is unknown (not sender, not trusted contract)
                        if recipient.lower() != tx.get('from', '').lower():
                            if recipient not in [c.lower() for c in self.TRUSTED_CONTRACTS]:
                                threats.append({
                                    'type': 'HIDDEN_TRANSFER',
                                    'severity': 'CRITICAL',
                                    'confidence': 95,
                                    'description': f'Transfers tokens to unknown address: {recipient}',
                                    'evidence': f'Recipient: {recipient}',
                                    'transaction_index': i
                                })
                                self._log(f"        🚨 HIDDEN TRANSFER TO: {recipient}")
                    except:
                        pass
            
            # Check if contract is verified
            to_address = tx.get('to', '')
            if to_address and to_address not in [c.lower() for c in self.TRUSTED_CONTRACTS]:
                threats.append({
                    'type': 'SUSPICIOUS_CONTRACT',
                    'severity': 'HIGH',
                    'confidence': 75,
                    'description': f'Interacts with unknown contract: {to_address}',
                    'evidence': f'Contract: {to_address}',
                    'transaction_index': i
                })
                self._log(f"        ⚠ Unknown contract: {to_address}")
        
        return threats
    
    def check_clipboard_access(self, page):
        """Check if page attempts to access clipboard"""
        try:
            # Check if clipboard API was accessed
            clipboard_accessed = page.evaluate("""
                () => {
                    return window._W3RG_CLIPBOARD_ACCESSED || false;
                }
            """)
            
            if clipboard_accessed:
                return {
                    'type': 'CLIPBOARD_HIJACK',
                    'severity': 'HIGH',
                    'confidence': 90,
                    'description': 'Page attempts to access clipboard (address hijacking)',
                    'evidence': 'Clipboard API called'
                }
        except:
            pass
        
        return None
    
    def check_domain_typosquatting(self, url):
        """
        Check if domain is typosquatting a legitimate service
        
        Returns:
            list: List of domain-based threats
        """
        threats = []
        
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Known legitimate brands
        legitimate_brands = {
            'uniswap': ['uniswap.org', 'app.uniswap.org', 'interface.gateway.uniswap.org'],
            'metamask': ['metamask.io'],
            'aave': ['aave.com', 'app.aave.com'],
            'compound': ['compound.finance', 'app.compound.finance'],
            'opensea': ['opensea.io'],
            'curve': ['curve.fi'],
            'pancakeswap': ['pancakeswap.finance'],
            'sushiswap': ['sushi.com', 'app.sushi.com']
        }
        
        # Suspicious TLDs commonly used in phishing
        suspicious_tlds = ['.xyz', '.top', '.live', '.site', '.online', '.click', '.pw', '.tk', '.ml', '.ga', '.cf']
        
        # Check if domain contains brand name but uses wrong TLD
        for brand, legitimate_domains in legitimate_brands.items():
            if brand in domain:
                # Check if it's actually a legitimate domain
                is_legitimate = any(legit_domain in domain for legit_domain in legitimate_domains)
                
                if not is_legitimate:
                    # Check if using suspicious TLD
                    uses_suspicious_tld = any(tld in domain for tld in suspicious_tlds)
                    
                    if uses_suspicious_tld:
                        threats.append({
                            'type': 'TYPOSQUATTING_CRITICAL',
                            'severity': 'CRITICAL',
                            'confidence': 99,
                            'description': f'CRITICAL: Fake {brand.title()} site using suspicious domain',
                            'evidence': f'Domain "{domain}" impersonates {brand.title()} (real: {", ".join(legitimate_domains[:2])})'
                        })
                    else:
                        # Wrong TLD but not obviously suspicious
                        threats.append({
                            'type': 'TYPOSQUATTING_HIGH',
                            'severity': 'HIGH',
                            'confidence': 90,
                            'description': f'Potential {brand.title()} impersonation',
                            'evidence': f'Domain "{domain}" similar to {brand.title()} (real: {", ".join(legitimate_domains[:2])})'
                        })
        
        return threats
    
    def analyze(self, url, timeout=30):
        """
        Full dApp security analysis
        
        Args:
            url: dApp URL to analyze
            timeout: Maximum time to wait for interactions (seconds)
        
        Returns:
            dict: Complete analysis result
        """
        self._log(f"\n{'='*60}")
        self._log(f"DAPP SECURITY SIMULATION: {url}")
        self._log(f"{'='*60}")
        
        result = {
            'url': url,
            'method': 'RUNTIME_SIMULATION',
            'timestamp': int(time.time())
        }
        
        threats = []
        
        # FIRST: Check domain before even loading page
        self._log("\n[1] Analyzing domain...")
        domain_threats = self.check_domain_typosquatting(url)
        threats.extend(domain_threats)
        
        if domain_threats:
            self._log(f"    ⚠ Found {len(domain_threats)} domain-level threat(s)")
        
        try:
            # Setup browser
            self.setup_browser()
            page = self.context.new_page()
            
            # Inject wallet before loading page
            self.inject_wallet(page)
            
            # Monitor network
            suspicious_requests = self.monitor_network(page)
            
            # Load dApp
            self._log(f"\n[2] Loading dApp: {url}")
            try:
                page.goto(url, wait_until='networkidle', timeout=timeout * 1000)
                self._log("    ✓ Page loaded")
            except PlaywrightTimeout:
                self._log("    ⚠ Timeout, continuing with domain-level analysis...")
            except Exception as e:
                self._log(f"    ⚠ Load failed: {str(e)[:100]}")
                # If we already have domain-level threats, continue anyway
                if threats:
                    self._log("    → But domain threats detected, continuing...")
                else:
                    return {
                        **result,
                        'is_malicious': False,
                        'error': f'Failed to load page: {str(e)}',
                        'pattern': 'LOAD_FAILED'
                    }
            
            # Wait for any automatic wallet connection attempts
            self._log("\n[3] Monitoring for automatic interactions...")
            time.sleep(3)
            
            # Try to find and click "Connect Wallet" button
            connect_buttons = [
                "text=/connect wallet/i",
                "text=/connect/i",
                "button:has-text('Connect')",
                "button:has-text('Connect Wallet')",
                "[class*='connect']",
                "#connect-wallet"
            ]
            
            for selector in connect_buttons:
                try:
                    page.click(selector, timeout=2000)
                    self._log(f"    ✓ Clicked connect button: {selector}")
                    time.sleep(2)  # Wait for wallet popup
                    break
                except:
                    continue
            
            # Extract captured requests
            self._log("\n[4] Extracting transaction requests...")
            transactions = []
            signatures = []
            
            try:
                transactions = page.evaluate("window._W3RG_TX_REQUESTS || []")
                signatures = page.evaluate("window._W3RG_SIG_REQUESTS || []")
                
                self._log(f"    → Captured {len(transactions)} transaction request(s)")
                self._log(f"    → Captured {len(signatures)} signature request(s)")
            except:
                self._log("    ⚠ No requests captured")
            
            # Analyze transactions
            if transactions:
                self._log("\n[5] Analyzing transaction requests...")
                tx_threats = self.analyze_transactions(transactions)
                threats.extend(tx_threats)
            
            # Check signatures
            if signatures:
                threats.append({
                    'type': 'SIGNATURE_REQUEST',
                    'severity': 'MEDIUM',
                    'confidence': 70,
                    'description': f'Requests {len(signatures)} signature(s) - verify carefully',
                    'evidence': f'{len(signatures)} signature request(s)'
                })
            
            # Check clipboard access
            clipboard_threat = self.check_clipboard_access(page)
            if clipboard_threat:
                threats.append(clipboard_threat)
            
            # Add network-level threats
            for req in suspicious_requests:
                threats.append({
                    'type': req['type'],
                    'severity': 'HIGH',
                    'confidence': 85,
                    'description': req['description'],
                    'evidence': req['url']
                })
            
            # Determine if malicious
            critical_threats = [t for t in threats if t.get('severity') == 'CRITICAL']
            high_threats = [t for t in threats if t.get('severity') == 'HIGH']
            
            if critical_threats:
                self._log(f"\n[!!!] MALICIOUS DAPP DETECTED - {len(critical_threats)} critical threat(s)")
                result['is_malicious'] = True
                result['confidence'] = max((t.get('confidence', 99) for t in critical_threats), default=99)
                result['reason'] = f'Detected {len(critical_threats)} critical security threat(s)'
            elif high_threats:
                self._log(f"\n[!!] SUSPICIOUS DAPP - {len(high_threats)} high-risk behavior(s)")
                result['is_malicious'] = True
                result['confidence'] = max((t.get('confidence', 85) for t in high_threats), default=85)
                result['reason'] = f'Detected {len(high_threats)} high-risk behavior(s)'
            elif threats:
                # Medium-level threats
                self._log(f"\n[!] POTENTIALLY SUSPICIOUS - {len(threats)} medium-risk behavior(s)")
                result['is_malicious'] = True
                result['confidence'] = 70
                result['reason'] = f'Detected {len(threats)} suspicious behavior(s)'
            else:
                self._log(f"\n[✓] No threats detected")
                result['is_malicious'] = False
                result['confidence'] = 90
                result['reason'] = 'No malicious behavior detected during simulation'
            
            result['threats'] = threats
            result['transactions_captured'] = len(transactions)
            result['signatures_captured'] = len(signatures)
            
        except Exception as e:
            self._log(f"\n[ERROR] Simulation failed: {str(e)}")
            result['is_malicious'] = False
            result['error'] = str(e)
            result['pattern'] = 'SIMULATION_ERROR'
        
        finally:
            # Cleanup
            if self.context:
                self.context.close()
            if self.browser:
                self.browser.close()
            if self.playwright:
                self.playwright.stop()
        
        return result


if __name__ == "__main__":
    # Test with known safe and malicious sites
    simulator = DAppSimulator(verbose=True)
    
    print("\n" + "="*80)
    print("Testing dApp Simulator")
    print("="*80)
    
    # Test with Uniswap (should be safe)
    print("\n\nTEST 1: Uniswap (Should be SAFE)")
    print("-" * 80)
    result = simulator.analyze("https://app.uniswap.org")
    print(f"\nResult: {'MALICIOUS' if result.get('is_malicious') else 'SAFE'}")
    print(f"Confidence: {result.get('confidence', 0)}%")
    print(f"Threats: {len(result.get('threats', []))}")
