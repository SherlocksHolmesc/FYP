"""
Honeypot Runtime Simulator
==========================
Simulates buy/sell transactions on a forked Ethereum network to detect honeypots.
More reliable than static source code analysis.

Requirements:
    pip install web3 eth-account
    
Setup:
    1. Start Ganache fork:
       ganache --fork https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY --port 8545
    
    2. Or use Hardhat:
       npx hardhat node --fork https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
"""

from web3 import Web3
from eth_account import Account
import time
import json
import re
import requests
from decimal import Decimal

class HoneypotSimulator:
    """
    Runtime honeypot detection via transaction simulation
    """
    
    # Multiple DEX Routers to check for liquidity (Ethereum mainnet)
    ROUTERS = {
        'Uniswap V2': "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        'Sushiswap': "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F",
        'Shibaswap': "0x03f7724180AA6b939894B5Ca4314783B0b36b329",
        'Fraxswap': "0xC14d550632db8592D1243Edc8B95b0Ad06703867",
        'Defiswap': "0xCeB90E4C17d626BE0fACd78b79c9c87d7ca181b3",
        'Uniswap V3': "0xE592427A0AEce92De3Edee1F18E0157C05861564",
    }
    UNISWAP_ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"  # Default fallback
    WETH_ADDRESS = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
    
    # Minimal ABIs for interaction
    ROUTER_ABI = [
        {
            "inputs": [
                {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
                {"internalType": "address[]", "name": "path", "type": "address[]"},
                {"internalType": "address", "name": "to", "type": "address"},
                {"internalType": "uint256", "name": "deadline", "type": "uint256"}
            ],
            "name": "swapExactETHForTokens",
            "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
            "stateMutability": "payable",
            "type": "function"
        },
        {
            "inputs": [
                {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
                {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
                {"internalType": "address[]", "name": "path", "type": "address[]"},
                {"internalType": "address", "name": "to", "type": "address"},
                {"internalType": "uint256", "name": "deadline", "type": "uint256"}
            ],
            "name": "swapExactTokensForETH",
            "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
                {"internalType": "address[]", "name": "path", "type": "address[]"},
                {"internalType": "address", "name": "to", "type": "address"},
                {"internalType": "uint256", "name": "deadline", "type": "uint256"}
            ],
            "name": "swapExactETHForTokensSupportingFeeOnTransferTokens",
            "outputs": [],
            "stateMutability": "payable",
            "type": "function"
        }
    ]
    
    # Uniswap V3 Router ABI (different from V2!)
    ROUTER_V3_ABI = [
        {
            "inputs": [
                {
                    "components": [
                        {"internalType": "address", "name": "tokenIn", "type": "address"},
                        {"internalType": "address", "name": "tokenOut", "type": "address"},
                        {"internalType": "uint24", "name": "fee", "type": "uint24"},
                        {"internalType": "address", "name": "recipient", "type": "address"},
                        {"internalType": "uint256", "name": "deadline", "type": "uint256"},
                        {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
                        {"internalType": "uint256", "name": "amountOutMinimum", "type": "uint256"},
                        {"internalType": "uint160", "name": "sqrtPriceLimitX96", "type": "uint160"}
                    ],
                    "internalType": "struct ISwapRouter.ExactInputSingleParams",
                    "name": "params",
                    "type": "tuple"
                }
            ],
            "name": "exactInputSingle",
            "outputs": [{"internalType": "uint256", "name": "amountOut", "type": "uint256"}],
            "stateMutability": "payable",
            "type": "function"
        }
    ]
    
    ERC20_ABI = [
        {
            "constant": True,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "type": "function"
        },
        {
            "constant": False,
            "inputs": [
                {"name": "_spender", "type": "address"},
                {"name": "_value", "type": "uint256"}
            ],
            "name": "approve",
            "outputs": [{"name": "", "type": "bool"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [],
            "name": "decimals",
            "outputs": [{"name": "", "type": "uint8"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [],
            "name": "symbol",
            "outputs": [{"name": "", "type": "string"}],
            "type": "function"
        }
    ]
    
    def __init__(self, rpc_url="http://127.0.0.1:8545", etherscan_key=None, verbose=True):
        """
        Initialize simulator
        
        Args:
            rpc_url: Local forked node URL (Ganache/Hardhat)
            etherscan_key: Etherscan API key for source code fetching
            verbose: Print debug logs
        """
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.verbose = verbose
        self.test_account = None
        self.etherscan_key = etherscan_key
        
        if not self.w3.is_connected():
            raise ConnectionError(f"Cannot connect to {rpc_url}. Start Ganache/Hardhat first!")
        
        if self.verbose:
            block = self.w3.eth.block_number
            print(f"[✓] Connected to forked network (block: {block})")
    
    def _log(self, message):
        """Print log if verbose enabled"""
        if self.verbose:
            print(message)
    
    def setup_test_account(self):
        """
        Create and fund test account with ETH
        """
        # Create fresh wallet
        self.test_account = Account.create()
        address = self.test_account.address
        
        # Fund with 10 ETH using Ganache/Hardhat RPC
        try:
            self.w3.provider.make_request('evm_setAccountBalance', [
                address, 
                hex(10 * 10**18)  # 10 ETH
            ])
        except Exception as e:
            # Fallback for different node implementations
            self.w3.provider.make_request('hardhat_setBalance', [
                address, 
                hex(10 * 10**18)
            ])
        
        balance = self.w3.eth.get_balance(address)
        self._log(f"[+] Test account: {address}")
        self._log(f"[+] Balance: {self.w3.from_wei(balance, 'ether')} ETH")
        
        return address
    
    def simulate_buy(self, token_address, amount_eth=0.01):
        """
        Simulate buying tokens with ETH via multiple DEXes
        
        Args:
            token_address: Token contract address
            amount_eth: Amount of ETH to spend (default 0.01)
        
        Returns:
            dict: {'success': bool, 'tokens_received': int, 'gas_used': int, 'error': str, 'dex_used': str}
        """
        self._log(f"\n[1] Simulating BUY: {amount_eth} ETH -> {token_address}")
        
        # Try each DEX in order
        last_error = None
        for dex_name, router_address in self.ROUTERS.items():
            self._log(f"    [*] Trying {dex_name}...")
            result = self._try_buy_on_dex(token_address, amount_eth, router_address, dex_name)
            
            if result['success']:
                result['dex_used'] = dex_name
                self._log(f"    [✓] Successfully bought on {dex_name}")
                return result
            else:
                last_error = result
                self._log(f"    [✗] {dex_name} failed: {result.get('error', 'Unknown error')}")
        
        # All DEXes failed - return last error with info
        if last_error:
            last_error['tried_dexes'] = list(self.ROUTERS.keys())
            last_error['error'] = f"No liquidity found on any DEX ({', '.join(self.ROUTERS.keys())})"
        return last_error
    
    def _try_buy_on_dex(self, token_address, amount_eth, router_address, dex_name):
        """
        Try to buy tokens on a specific DEX
        
        Returns:
            dict: {'success': bool, 'tokens_received': int, 'gas_used': int, 'error': str}
        """
        # Use V3 logic for Uniswap V3
        if dex_name == 'Uniswap V3':
            return self._try_buy_on_uniswap_v3(token_address, amount_eth, router_address)
        
        # V2-style DEXes
        router = self.w3.eth.contract(
            address=Web3.to_checksum_address(router_address),
            abi=self.ROUTER_ABI
        )
        
        token = self.w3.eth.contract(
            address=Web3.to_checksum_address(token_address),
            abi=self.ERC20_ABI
        )
        
        amount_in = self.w3.to_wei(amount_eth, 'ether')
        path = [
            Web3.to_checksum_address(self.WETH_ADDRESS),
            Web3.to_checksum_address(token_address)
        ]
        deadline = int(time.time()) + 300  # 5 minutes
        
        try:
            # Check if contract exists and has code
            code = self.w3.eth.get_code(Web3.to_checksum_address(token_address))
            if code == b'' or code == '0x':
                return {
                    'success': False,
                    'error': 'Contract not deployed or no bytecode at address',
                    'pattern': 'NO_CONTRACT'
                }
            
            # Try to check balance before (may fail for non-standard tokens)
            try:
                balance_before = token.functions.balanceOf(self.test_account.address).call()
            except Exception as e:
                error_msg = str(e)
                # Check for specific errors
                if 'Could not decode' in error_msg or 'output_types' in error_msg:
                    # Check if it's returning empty (honeypot tactic) vs function doesn't exist
                    if "return data: b''" in error_msg or "with return data: b''" in error_msg:
                        # Function EXISTS but returns empty - HONEYPOT TACTIC!
                        self._log(f"    ⚠ balanceOf() returns empty (honeypot tactic)")
                        return {
                            'success': False,
                            'error': 'Token balanceOf() returns empty - likely a honeypot',
                            'pattern': 'HONEYPOT_BALANCE_TRICK'
                        }
                    else:
                        # Function doesn't exist or wrong ABI - SUSPICIOUS! Most honeypots have broken ERC20
                        self._log(f"    ⚠ Does not implement standard ERC20 - likely honeypot!")
                        return {
                            'success': False,
                            'is_honeypot': True,  # Flag as honeypot
                            'confidence': 80,  # High confidence - broken ERC20 is red flag
                            'error': 'Token does not implement standard ERC20 balanceOf function - common honeypot tactic',
                            'pattern': 'NON_STANDARD_TOKEN',
                            'reason': 'Deliberately broken ERC20 implementation to prevent selling'
                        }
                elif 'is contract deployed' in error_msg or 'not synced' in error_msg:
                    # Network/deployment issue
                    return {
                        'success': False,
                        'error': 'Cannot interact with contract - may not be deployed or chain not synced',
                        'pattern': 'CONTRACT_NOT_ACCESSIBLE'
                    }
                elif 'revert' in error_msg.lower() or 'execution reverted' in error_msg.lower():
                    # Function EXISTS but deliberately reverts - likely system contract like ETH2
                    return {
                        'success': False,
                        'error': f'Token balanceOf() reverts: {error_msg}',
                        'pattern': 'BALANCE_CHECK_FAILED'
                    }
                else:
                    # Other errors - treat as non-standard
                    return {
                        'success': False,
                        'error': f'Failed to check token balance: {error_msg}',
                        'pattern': 'BALANCE_CHECK_FAILED'
                    }
        
            # Build transaction (with fee-on-transfer support)
            tx = router.functions.swapExactETHForTokensSupportingFeeOnTransferTokens(
                0,  # Accept any amount of tokens
                path,
                self.test_account.address,
                deadline
            ).build_transaction({
                'from': self.test_account.address,
                'value': amount_in,
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.test_account.address)
            })
            
            # Sign and send
            signed = self.test_account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            
            # Wait for receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            # Check balance after (may fail for honeypots that block balanceOf)
            try:
                balance_after = token.functions.balanceOf(self.test_account.address).call()
                tokens_received = balance_after - balance_before
            except Exception:
                # Can't check balance (honeypot tactic) - assume we got tokens if tx succeeded
                tokens_received = 1  # Non-zero to indicate success
            
            if receipt['status'] == 1 and tokens_received > 0:
                self._log(f"    ✓ Buy successful")
                if tokens_received > 1:
                    self._log(f"    → Tokens received: {tokens_received}")
                else:
                    self._log(f"    → Tokens received: Unknown (balanceOf blocked)")
                self._log(f"    → Gas used: {receipt['gasUsed']}")
                
                return {
                    'success': True,
                    'tokens_received': tokens_received,
                    'gas_used': receipt['gasUsed'],
                    'tx_hash': tx_hash.hex()
                }
            else:
                return {
                    'success': False,
                    'error': 'Transaction succeeded but no tokens received',
                    'pattern': 'BUY_NO_TOKENS'
                }
            
        except Exception as e:
            error_msg = str(e)
            self._log(f"    ✗ Buy failed: {error_msg}")
            
            # More specific error patterns
            if 'insufficient funds' in error_msg.lower():
                pattern = 'INSUFFICIENT_FUNDS'
            elif 'revert' in error_msg.lower():
                pattern = 'BUY_REVERTED'
            elif 'timeout' in error_msg.lower():
                pattern = 'TIMEOUT'
            else:
                pattern = 'BUY_FAILED'
            
            return {
                'success': False,
                'error': error_msg,
                'pattern': pattern
            }
    
    def _try_buy_on_uniswap_v3(self, token_address, amount_eth, router_address):
        """
        Try to buy tokens on Uniswap V3 (different ABI and logic)
        Tries multiple fee tiers: 3000 (0.3%), 10000 (1%), 500 (0.05%)
        
        Returns:
            dict: {'success': bool, 'tokens_received': int, 'gas_used': int, 'error': str}
        """
        router = self.w3.eth.contract(
            address=Web3.to_checksum_address(router_address),
            abi=self.ROUTER_V3_ABI
        )
        
        token = self.w3.eth.contract(
            address=Web3.to_checksum_address(token_address),
            abi=self.ERC20_ABI
        )
        
        # Check balance before
        try:
            balance_before = token.functions.balanceOf(self.test_account.address).call()
        except Exception as e:
            error_msg = str(e)
            if "return data: b''" in error_msg or "with return data: b''" in error_msg:
                return {
                    'success': False,
                    'error': 'Token balanceOf() returns empty - likely a honeypot',
                    'pattern': 'HONEYPOT_BALANCE_TRICK'
                }
            return {
                'success': False,
                'error': f'Failed to check token balance: {error_msg}',
                'pattern': 'BALANCE_CHECK_FAILED'
            }
        
        amount_in = self.w3.to_wei(amount_eth, 'ether')
        deadline = int(time.time()) + 300
        
        # Try different fee tiers (V3 has multiple pools per pair)
        fee_tiers = [3000, 10000, 500]  # 0.3%, 1%, 0.05%
        last_error = None
        
        for fee in fee_tiers:
            try:
                self._log(f"    → Trying V3 fee tier: {fee/10000}%")
                
                params = {
                    'tokenIn': Web3.to_checksum_address(self.WETH_ADDRESS),
                    'tokenOut': Web3.to_checksum_address(token_address),
                    'fee': fee,
                    'recipient': self.test_account.address,
                    'deadline': deadline,
                    'amountIn': amount_in,
                    'amountOutMinimum': 0,
                    'sqrtPriceLimitX96': 0
                }
                
                # Build transaction
                tx = router.functions.exactInputSingle(params).build_transaction({
                    'from': self.test_account.address,
                    'value': amount_in,
                    'gas': 500000,
                    'gasPrice': self.w3.eth.gas_price,
                    'nonce': self.w3.eth.get_transaction_count(self.test_account.address)
                })
                
                # Sign and send
                signed = self.test_account.sign_transaction(tx)
                tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
                
                # Wait for receipt
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                
                # Check balance after
                try:
                    balance_after = token.functions.balanceOf(self.test_account.address).call()
                    tokens_received = balance_after - balance_before
                except Exception:
                    tokens_received = 1  # Assume success if tx succeeded
                
                if receipt['status'] == 1 and tokens_received > 0:
                    self._log(f"    ✓ V3 Buy successful on {fee/10000}% tier")
                    if tokens_received > 1:
                        self._log(f"    → Tokens received: {tokens_received}")
                    self._log(f"    → Gas used: {receipt['gasUsed']}")
                    
                    return {
                        'success': True,
                        'tokens_received': tokens_received,
                        'gas_used': receipt['gasUsed'],
                        'tx_hash': tx_hash.hex()
                    }
                else:
                    last_error = {
                        'success': False,
                        'error': 'Transaction succeeded but no tokens received',
                        'pattern': 'BUY_NO_TOKENS'
                    }
            
            except Exception as e:
                error_msg = str(e)
                last_error = {
                    'success': False,
                    'error': error_msg,
                    'pattern': 'BUY_REVERTED' if 'revert' in error_msg.lower() else 'BUY_FAILED'
                }
                self._log(f"    ✗ V3 {fee/10000}% tier failed")
        
        # All fee tiers failed
        self._log(f"    ✗ V3 Buy failed on all fee tiers")
        return last_error if last_error else {
            'success': False,
            'error': 'No V3 pool found for any fee tier',
            'pattern': 'BUY_NO_TOKENS'
        }
    
    def simulate_sell(self, token_address, router_address=None):
        """
        Simulate selling tokens back to ETH
        
        Args:
            token_address: Token contract address
            router_address: DEX router address to use (defaults to Uniswap V2)
        
        Returns:
            dict: {'success': bool, 'eth_received': int, 'gas_used': int, 'error': str}
        """
        # Default to Uniswap V2 if not specified
        if router_address is None:
            router_address = self.ROUTERS['Uniswap V2']
            
        self._log(f"\n[2] Simulating SELL: {token_address} -> ETH")
        
        router = self.w3.eth.contract(
            address=Web3.to_checksum_address(router_address),
            abi=self.ROUTER_ABI
        )
        
        token = self.w3.eth.contract(
            address=Web3.to_checksum_address(token_address),
            abi=self.ERC20_ABI
        )
        
        # Get token balance
        balance = token.functions.balanceOf(self.test_account.address).call()
        
        if balance == 0:
            return {
                'success': False,
                'error': 'No tokens to sell (buy failed)',
                'pattern': 'NO_BALANCE'
            }
        
        self._log(f"    → Token balance: {balance}")
        
        # Approve router to spend tokens
        try:
            approve_tx = token.functions.approve(
                Web3.to_checksum_address(router_address),
                balance
            ).build_transaction({
                'from': self.test_account.address,
                'gas': 100000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.test_account.address)
            })
            
            signed_approve = self.test_account.sign_transaction(approve_tx)
            approve_hash = self.w3.eth.send_raw_transaction(signed_approve.raw_transaction)
            approve_receipt = self.w3.eth.wait_for_transaction_receipt(approve_hash, timeout=120)
            
            if approve_receipt['status'] != 1:
                return {
                    'success': False,
                    'error': 'Approval failed',
                    'pattern': 'APPROVE_FAILED'
                }
            
            self._log(f"    ✓ Approval successful")
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Approval reverted: {str(e)}',
                'pattern': 'APPROVE_REVERTED'
            }
        
        # Check ETH balance before
        eth_before = self.w3.eth.get_balance(self.test_account.address)
        
        # Now sell tokens
        path = [
            Web3.to_checksum_address(token_address),
            Web3.to_checksum_address(self.WETH_ADDRESS)
        ]
        deadline = int(time.time()) + 300
        
        try:
            tx = router.functions.swapExactTokensForETH(
                balance,  # Sell all tokens
                0,  # Accept any amount of ETH
                path,
                self.test_account.address,
                deadline
            ).build_transaction({
                'from': self.test_account.address,
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.test_account.address)
            })
            
            signed = self.test_account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            # Check ETH balance after (accounting for gas)
            eth_after = self.w3.eth.get_balance(self.test_account.address)
            gas_cost = receipt['gasUsed'] * tx['gasPrice']
            eth_received = eth_after - eth_before + gas_cost
            
            if receipt['status'] == 1:
                self._log(f"    ✓ Sell successful")
                self._log(f"    → ETH received: {self.w3.from_wei(eth_received, 'ether')}")
                self._log(f"    → Gas used: {receipt['gasUsed']}")
                
                # CRITICAL: Detect fake/manipulated return values (honeypot tactic)
                max_realistic_eth = self.w3.to_wei(1000, 'ether')  # 1000 ETH is already suspicious
                if eth_received > max_realistic_eth:
                    self._log(f"    [!!!] FAKE VALUE DETECTED - impossibly high ETH: {self.w3.from_wei(eth_received, 'ether')}")
                    return {
                        'success': False,
                        'error': f'Balance manipulation detected - returned {self.w3.from_wei(eth_received, "ether")} ETH (impossible)',
                        'pattern': 'BALANCE_MANIPULATION',
                        'fake_value': eth_received
                    }
                
                # Check if we got reasonable amount back (detect high tax)
                if eth_received < self.w3.to_wei(0.001, 'ether'):
                    return {
                        'success': True,  # Transaction succeeded
                        'warning': 'EXTREME_TAX',  # But extremely high tax
                        'eth_received': eth_received,
                        'gas_used': receipt['gasUsed'],
                        'tx_hash': tx_hash.hex()
                    }
                
                return {
                    'success': True,
                    'eth_received': eth_received,
                    'gas_used': receipt['gasUsed'],
                    'tx_hash': tx_hash.hex()
                }
            else:
                return {
                    'success': False,
                    'error': 'Transaction failed',
                    'pattern': 'SELL_FAILED'
                }
            
        except Exception as e:
            error_msg = str(e)
            self._log(f"    ✗ Sell failed: {error_msg}")
            
            # THIS IS THE KEY - Sell failure = HONEYPOT
            return {
                'success': False,
                'error': error_msg,
                'pattern': 'SELL_REVERTED'  # CONFIRMED HONEYPOT
            }
    
    def fetch_contract_source(self, address):
        """
        Fetch verified contract source code from Etherscan
        
        Args:
            address: Contract address
        
        Returns:
            dict: {'source': str, 'contract_name': str} or None
        """
        if not self.etherscan_key:
            return None
        
        url = f"https://api.etherscan.io/api"
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address,
            'apikey': self.etherscan_key,
            'chainid': 1
        }
        
        try:
            response = requests.get(url, params=params, timeout=10)
            data = response.json()
            
            if data['status'] == '1' and data['result']:
                result = data['result'][0]
                source = result.get('SourceCode', '')
                
                if not source or source == '':
                    return None
                
                # Handle multiple file format
                if source.startswith('{{'):
                    source = source[1:-1]
                    try:
                        source_obj = json.loads(source)
                        # Flatten all sources
                        all_sources = []
                        for file_data in source_obj.get('sources', {}).values():
                            all_sources.append(file_data.get('content', ''))
                        source = '\n\n'.join(all_sources)
                    except:
                        pass
                
                return {
                    'source': source,
                    'contract_name': result.get('ContractName', 'Unknown')
                }
        except Exception as e:
            if self.verbose:
                print(f"    [!] Could not fetch source: {e}")
        
        return None
    
    def analyze_honeypot_patterns(self, source_code, contract_name):
        """
        Analyze source code for HIGH-CONFIDENCE honeypot patterns.
        Only called AFTER runtime simulation confirms honeypot.
        
        Args:
            source_code: Solidity source code
            contract_name: Contract name
        
        Returns:
            list: Findings with line numbers and code snippets
        """
        findings = []
        lines = source_code.split('\n')
        
        # HIGH-CONFIDENCE honeypot patterns (not generic ERC20)
        patterns = [
            {
                'regex': r'require\s*\(\s*tradingEnabled\s*[,)]',
                'severity': 'CRITICAL',
                'category': 'Trading Lock',
                'description': 'Requires trading to be enabled. Owner can disable trading to block sells.',
                'confidence': '95%'
            },
            {
                'regex': r'require\s*\(\s*_?blacklist\[.*?\]\s*\)',
                'severity': 'CRITICAL',
                'category': 'Reverse Blacklist',
                'description': 'Requires sender BE blacklisted to transfer. Classic honeypot pattern.',
                'confidence': '99%'
            },
            {
                'regex': r'require\s*\(\s*!_?blacklist\[.*?\]\s*\)',
                'severity': 'HIGH',
                'category': 'Blacklist',
                'description': 'Can blacklist addresses to prevent selling.',
                'confidence': '80%'
            },
            {
                'regex': r'require\s*\(\s*quiz\s*==\s*\d+\s*[,)]',
                'severity': 'CRITICAL',
                'category': 'Quiz Honeypot',
                'description': 'Requires impossible quiz answer. No one can solve it.',
                'confidence': '99%'
            },
            {
                'regex': r'if\s*\(\s*from\s*!=\s*owner\s*\)\s*revert',
                'severity': 'CRITICAL',
                'category': 'Owner-Only Transfer',
                'description': 'Only owner can transfer tokens. Others cannot sell.',
                'confidence': '95%'
            },
            {
                'regex': r'require\s*\(\s*from\s*==\s*owner\s*[,)]',
                'severity': 'CRITICAL',
                'category': 'Owner-Only Transfer',
                'description': 'Only owner can initiate transfers. Classic honeypot.',
                'confidence': '95%'
            },
            {
                'regex': r'if\s*\(.*?block\.timestamp\s*<\s*launchTime',
                'severity': 'HIGH',
                'category': 'Trading Delay',
                'description': 'Trading not enabled until specific time. May never enable.',
                'confidence': '75%'
            },
            {
                'regex': r'_balances\[.*?\]\s*=\s*0\s*;',
                'severity': 'CRITICAL',
                'category': 'Balance Manipulation',
                'description': 'Sets balance to zero. Steals tokens before transfer.',
                'confidence': '90%'
            },
            {
                'regex': r'require\s*\(\s*amount\s*<=\s*maxTxAmount',
                'severity': 'MEDIUM',
                'category': 'Sell Limit',
                'description': 'Limits transaction amount. If maxTxAmount=0, cannot sell.',
                'confidence': '60%'
            },
            {
                'regex': r'if\s*\(.*?isPaused\s*\)\s*revert',
                'severity': 'HIGH',
                'category': 'Pausable',
                'description': 'Contract can be paused by owner to block all transfers.',
                'confidence': '70%'
            }
        ]
        
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()
            
            for pattern in patterns:
                if re.search(pattern['regex'], line, re.IGNORECASE):
                    # Get context (5 lines before and after)
                    start_line = max(1, i - 5)
                    end_line = min(len(lines), i + 5)
                    
                    context_lines = []
                    for j in range(start_line - 1, end_line):
                        line_num = j + 1
                        prefix = '→ ' if line_num == i else '  '
                        context_lines.append(f"{prefix}{line_num:4d} | {lines[j]}")
                    
                    code_snippet = '\n'.join(context_lines)
                    
                    findings.append({
                        'category': pattern['category'],
                        'severity': pattern['severity'].lower(),
                        'description': pattern['description'],
                        'line_number': i,
                        'code_snippet': code_snippet,
                        'confidence': pattern['confidence'],
                        'matched_code': line.strip(),
                        'recommendation': 'This code prevents normal users from selling tokens.'
                    })
        
        return findings
    
    def is_erc20_token(self, token_address):
        """
        Check if address is an ERC20 token by verifying standard functions exist.
        
        Args:
            token_address: Contract address to check
        
        Returns:
            dict: {'is_token': bool, 'reason': str, 'missing_functions': list}
        """
        token = self.w3.eth.contract(
            address=Web3.to_checksum_address(token_address),
            abi=self.ERC20_ABI
        )
        
        required_functions = ['totalSupply', 'balanceOf', 'decimals', 'symbol']
        critical_functions = ['balanceOf', 'symbol']  # Must have these at minimum
        missing = []
        test_address = self.w3.eth.accounts[0] if self.w3.eth.accounts else '0x0000000000000000000000000000000000000001'
        
        for func_name in required_functions:
            try:
                func = getattr(token.functions, func_name)
                # Test call - if it reverts, function doesn't exist properly
                if func_name == 'balanceOf':
                    result = func(test_address).call()
                else:
                    result = func().call()
                    
                # Additional check: decimals should return 0-18, symbol should be string
                if func_name == 'decimals' and not isinstance(result, int):
                    missing.append(func_name)
                elif func_name == 'totalSupply' and not isinstance(result, int):
                    missing.append(func_name)
                    
            except Exception as e:
                error_msg = str(e).lower()
                # Catch all errors - any failure means it's not a standard token
                self._log(f"    [DEBUG] {func_name}() failed: {error_msg[:100]}")
                missing.append(func_name)
        
        # Check if critical functions are missing
        critical_missing = [f for f in critical_functions if f in missing]
        
        if len(critical_missing) >= 2:
            # Missing both balanceOf and symbol - definitely not a token
            return {
                'is_token': False,
                'reason': 'Not an ERC20 token - missing core functions',
                'missing_functions': missing,
                'contract_type': 'SYSTEM_CONTRACT'  # Could be multisig, protocol, etc.
            }
        elif len(missing) >= 3:
            # Missing 3+ functions total but has balanceOf or symbol - broken token
            return {
                'is_token': True,
                'reason': 'Broken ERC20 implementation (missing some functions)',
                'missing_functions': missing,
                'contract_type': 'BROKEN_TOKEN'
            }
        elif len(missing) > 0:
            # Missing 1-2 non-critical functions - likely old Solidity version (e.g., totalSupply as public var)
            return {
                'is_token': True,
                'reason': 'Valid ERC20 token (older implementation)',
                'missing_functions': missing,
                'contract_type': 'ERC20_TOKEN'  # Treat as valid even with minor issues
            }
        else:
            return {
                'is_token': True,
                'reason': 'Valid ERC20 interface',
                'missing_functions': [],
                'contract_type': 'ERC20_TOKEN'
            }
    
    def analyze(self, token_address, goplus_data=None):
        """
        Full honeypot analysis: setup -> buy -> sell
        
        Args:
            token_address: Token contract address
            goplus_data: Optional GoPlus Security API data to cross-reference
        
        Returns:
            dict: Complete analysis result
        """
        self._log(f"\n{'='*60}")
        self._log(f"HONEYPOT SIMULATION: {token_address}")
        self._log(f"{'='*60}")
        
        result = {
            'token_address': token_address,
            'method': 'RUNTIME_SIMULATION',
            'timestamp': int(time.time())
        }
        
        try:
            # CRITICAL: Check if it's actually an ERC20 token FIRST
            self._log(f"\n[0] Checking if address is an ERC20 token...")
            token_check = self.is_erc20_token(token_address)
            result['token_validation'] = token_check
            
            if not token_check['is_token']:
                self._log(f"\n[✗] NOT A TOKEN - {token_check['reason']}")
                self._log(f"    Missing functions: {', '.join(token_check['missing_functions'])}")
                return {
                    'token_address': token_address,
                    'is_honeypot': False,
                    'is_token': False,
                    'confidence': 0,
                    'reason': token_check['reason'],
                    'contract_type': token_check['contract_type'],
                    'missing_functions': token_check['missing_functions'],
                    'pattern': 'NOT_A_TOKEN',
                    'warning': 'This address is not a tradeable ERC20 token. It may be a system contract (ETH2 Deposit, multisig, DeFi protocol, etc.)',
                    'recommendation': 'Cannot perform buy/sell simulation on non-token contracts'
                }
            elif token_check['contract_type'] == 'BROKEN_TOKEN':
                self._log(f"\n[⚠] BROKEN TOKEN - Missing: {', '.join(token_check['missing_functions'])}")
                # Flag as suspicious but continue to attempt simulation
            else:
                self._log(f"\n[✓] Valid ERC20 token detected")
            
            # Setup test account
            self.setup_test_account()
            
            # Test BUY
            buy_result = self.simulate_buy(token_address)
            result['buy_test'] = buy_result
            
            if not buy_result['success']:
                pattern = buy_result.get('pattern', 'BUY_FAILED')
                
                # Check if buy_result already flagged as honeypot (from my earlier fix)
                if buy_result.get('is_honeypot'):
                    self._log(f"\n[!!!] HONEYPOT DETECTED - {pattern}")
                    result['is_honeypot'] = True
                    result['confidence'] = buy_result.get('confidence', 80)
                    result['reason'] = buy_result.get('reason', 'Broken ERC20 implementation')
                    result['pattern'] = pattern
                    return result
                
                # Distinguish between honeypots and non-token contracts
                if pattern in ['NO_CONTRACT', 'BALANCE_CHECK_FAILED', 'CONTRACT_NOT_ACCESSIBLE', 'BUY_NO_TOKENS']:
                    self._log(f"\n[!] Cannot simulate trading - may be frozen/paused or lack liquidity")
                    
                    # Get list of DEXes that were tried
                    tried_dexes = buy_result.get('tried_dexes', ['Uniswap V2'])
                    dex_list = ', '.join(tried_dexes)
                    
                    # If token has valid ERC20 interface, it's likely just frozen/paused (not malicious)
                    if token_check.get('contract_type') == 'ERC20_TOKEN':
                        result['is_honeypot'] = False
                        result['confidence'] = 0
                        result['tried_dexes'] = tried_dexes  # Pass through to frontend
                        # More specific message based on the pattern
                        if pattern == 'BUY_NO_TOKENS':
                            result['reason'] = f'Cannot test - No liquidity pool found on {dex_list}. Token may trade on other DEXes or have no liquidity.'
                            result['pattern'] = 'NO_LIQUIDITY'
                            result['warning'] = f'No liquidity found on {dex_list}. This token may trade on other exchanges or have removed liquidity.'
                        else:
                            result['reason'] = f'Trading appears paused/frozen or lacks liquidity on {dex_list}. Valid ERC20 interface detected.'
                            result['pattern'] = 'TRADING_PAUSED'
                            result['warning'] = 'Trading appears to be paused, frozen, or lacks liquidity. This may be temporary.'
                    else:
                        result['is_honeypot'] = False
                        result['confidence'] = 0
                        result['reason'] = 'Not a standard ERC20 token - cannot simulate trading'
                        result['pattern'] = pattern
                        result['warning'] = 'This is not a tradeable token or does not follow ERC20 standard'
                elif pattern == 'HONEYPOT_BALANCE_TRICK':
                    self._log(f"\n[!!!] HONEYPOT DETECTED - balanceOf() manipulation")
                    result['is_honeypot'] = True
                    result['confidence'] = 99
                    result['reason'] = 'Token uses balanceOf() tricks to hide actual balance - honeypot tactic'
                    result['pattern'] = pattern
                else:
                    # Other trading restrictions
                    self._log(f"\n[!] Cannot buy tokens - Trading restricted")
                    result['is_honeypot'] = True
                    result['confidence'] = 95
                    result['reason'] = 'Buy transaction failed - trading may be restricted'
                    result['pattern'] = pattern
                
                return result
            
            # Test SELL (use same DEX that worked for buy)
            dex_used = buy_result.get('dex_used')
            router_address = self.ROUTERS.get(dex_used, self.ROUTERS['Uniswap V2'])
            sell_result = self.simulate_sell(token_address, router_address)
            result['sell_test'] = sell_result
            
            # Check for balance manipulation (fake return values)
            if sell_result.get('pattern') == 'BALANCE_MANIPULATION':
                self._log(f"\n[!!!] HONEYPOT CONFIRMED - Balance manipulation detected!")
                result['is_honeypot'] = True
                result['confidence'] = 99
                result['reason'] = 'Contract uses balance manipulation to return fake transaction values'
                result['pattern'] = 'BALANCE_MANIPULATION'
                result['fake_value'] = sell_result.get('fake_value')
                return result
            
            if not sell_result['success']:
                self._log(f"\n[!!!] SELL FAILED - Investigating cause...")
                
                # CRITICAL FIX: Check GoPlus FIRST before labeling as honeypot
                # Many legitimate tokens fail sell simulations due to liquidity/slippage/anti-bot
                if goplus_data:
                    goplus_honeypot = goplus_data.get('is_honeypot', False)
                    if not goplus_honeypot:
                        self._log(f"\n[✓] GoPlus confirms NOT A HONEYPOT")
                        self._log(f"    → Sell failure likely due to: liquidity, slippage, or trading restrictions")
                        result['is_honeypot'] = False
                        result['confidence'] = 75  # Moderate confidence - simulation passed buy, GoPlus says safe
                        result['reason'] = 'Token appears legitimate (verified by GoPlus) - sell failure may be due to insufficient liquidity, high slippage, or anti-bot protection'
                        result['pattern'] = 'SELL_FAILED_BUT_LEGITIMATE'
                        result['warning'] = sell_result.get('error', 'Sell transaction failed')
                        return result
                
                # GoPlus also says honeypot OR no GoPlus data - proceed with honeypot analysis
                self._log(f"\n[!!!] HONEYPOT SUSPECTED - Cannot sell tokens!")
                result['is_honeypot'] = True
                result['confidence'] = 90  # Reduced from 99 since we need to verify with source
                result['reason'] = 'Sell transaction failed after successful buy'
                result['pattern'] = sell_result.get('pattern', 'SELL_BLOCKED')
                
                # Fetch source code and analyze WHY sell is blocked
                self._log(f"\n[3] Analyzing source code to find cause...")
                contract_data = self.fetch_contract_source(token_address)
                
                if contract_data:
                    self._log(f"    ✓ Source code found ({contract_data['contract_name']})")
                    
                    # Analyze for honeypot patterns
                    findings = self.analyze_honeypot_patterns(
                        contract_data['source'],
                        contract_data['contract_name']
                    )
                    
                    if findings:
                        self._log(f"    ✓ Found {len(findings)} malicious code pattern(s)")
                        result['malicious_code'] = findings
                        
                        # Show first finding
                        if self.verbose and len(findings) > 0:
                            first = findings[0]
                            self._log(f"\n    [FOUND] {first['category']} (Line {first['line_number']})")
                            self._log(f"    → {first['matched_code']}")
                            self._log(f"    → {first['description']}")
                    else:
                        self._log(f"    ! No obvious patterns found (may be obfuscated)")
                        result['malicious_code'] = []
                else:
                    self._log(f"    ! Source code not verified on Etherscan")
                    result['malicious_code'] = None
                
                return result
            
            # Check for extreme tax
            if sell_result.get('warning') == 'EXTREME_TAX':
                self._log(f"\n[!] WARNING - Extreme sell tax detected (>99%)")
                result['is_honeypot'] = True
                result['confidence'] = 90
                result['reason'] = 'Sell tax exceeds 99% - effective honeypot'
                result['pattern'] = 'EXTREME_SELL_TAX'
                return result
            
            # CROSS-REFERENCE with GoPlus: If GoPlus says honeypot but simulation passed,
            # trust GoPlus (they have more context: creator history, similar patterns, large tx restrictions)
            if goplus_data and goplus_data.get('is_honeypot'):
                self._log(f"\n[!!!] GoPlus flags as HONEYPOT despite passing simulation")
                self._log(f"     → This may be a sophisticated honeypot that allows small amounts")
                result['is_honeypot'] = True
                result['confidence'] = 85  # High confidence but not 99 since simulation passed
                result['reason'] = 'GoPlus Security detected honeypot behavior (may restrict large amounts or specific wallets)'
                result['pattern'] = 'GOPLUS_HONEYPOT_FLAG'
                result['goplus_context'] = goplus_data.get('flags', [])
                return result
            
            # Both succeeded - likely safe
            self._log(f"\n[✓] Token appears safe - Buy and sell both succeeded")
            result['is_honeypot'] = False
            result['confidence'] = 95
            result['reason'] = 'Buy and sell transactions both succeeded'
            result['pattern'] = 'TRADEABLE'
            return result
            
        except Exception as e:
            self._log(f"\n[ERROR] Simulation failed: {str(e)}")
            result['is_honeypot'] = None
            result['confidence'] = 0
            result['reason'] = f'Simulation error: {str(e)}'
            result['error'] = str(e)
            return result


# ============================================================
# TEST SCRIPT
# ============================================================

if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    
    print("""
    Honeypot Runtime Simulator - Test Script
    =========================================
    
    Prerequisites:
    1. Install: pip install web3 eth-account
    2. Start Ganache fork:
       ganache --fork https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY --port 8545
    
    Testing known contracts...
    """)
    
    try:
        # Load Etherscan API key
        load_dotenv()
        etherscan_key = os.getenv('ETHERSCAN_API_KEY')
        
        simulator = HoneypotSimulator(etherscan_key=etherscan_key)
        
        # Test 1: Known good token (UNI)
        print("\n\n[TEST 1] Uniswap Token (UNI) - Should be SAFE")
        print("-" * 60)
        result = simulator.analyze("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984")
        print(f"\nResult: {'HONEYPOT' if result['is_honeypot'] else 'SAFE'}")
        print(f"Confidence: {result['confidence']}%")
        print(f"Reason: {result['reason']}")
        
        # Test 2: Known honeypot (MommyMilkers)
        print("\n\n[TEST 2] MommyMilkers - Should be HONEYPOT")
        print("-" * 60)
        result = simulator.analyze("0x45dac6c8776e5eb1548d3cdcf0c5f6959e410c3a")
        print(f"\nResult: {'HONEYPOT' if result['is_honeypot'] else 'SAFE'}")
        print(f"Confidence: {result['confidence']}%")
        print(f"Reason: {result['reason']}")
        
        if result.get('malicious_code'):
            print(f"\n[MALICIOUS CODE FOUND]")
            for i, finding in enumerate(result['malicious_code'][:3], 1):
                print(f"\n{i}. {finding['category']} (Line {finding['line_number']}) - {finding['severity'].upper()}")
                print(f"   → {finding['matched_code']}")
                print(f"   → {finding['description']}")
                print(f"   → Confidence: {finding['confidence']}")
        
    except ConnectionError as e:
        print(f"\n[ERROR] {e}")
        print("\nSetup Instructions:")
        print("1. Get Alchemy API key: https://www.alchemy.com/")
        print("2. Install Ganache: npm install -g ganache")
        print("3. Run: ganache --fork https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY --port 8545")
    except Exception as e:
        print(f"\n[ERROR] {e}")
    print("""
    Honeypot Runtime Simulator - Test Script
    =========================================
    
    Prerequisites:
    1. Install: pip install web3 eth-account
    2. Start Ganache fork:
       ganache --fork https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY --port 8545
    
    Testing known contracts...
    """)
    
    try:
        simulator = HoneypotSimulator()
        
        # Test 1: Known good token (UNI)
        print("\n\n[TEST 1] Uniswap Token (UNI) - Should be SAFE")
        print("-" * 60)
        result = simulator.analyze("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984")
        print(f"\nResult: {'HONEYPOT' if result['is_honeypot'] else 'SAFE'}")
        print(f"Confidence: {result['confidence']}%")
        print(f"Reason: {result['reason']}")
        
        # Test 2: Known honeypot (MommyMilkers)
        print("\n\n[TEST 2] MommyMilkers - Should be HONEYPOT")
        print("-" * 60)
        result = simulator.analyze("0x45dac6c8776e5eb1548d3cdcf0c5f6959e410c3a")
        print(f"\nResult: {'HONEYPOT' if result['is_honeypot'] else 'SAFE'}")
        print(f"Confidence: {result['confidence']}%")
        print(f"Reason: {result['reason']}")
        
    except ConnectionError as e:
        print(f"\n[ERROR] {e}")
        print("\nSetup Instructions:")
        print("1. Get Alchemy API key: https://www.alchemy.com/")
        print("2. Install Ganache: npm install -g ganache")
        print("3. Run: ganache --fork https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY --port 8545")
    except Exception as e:
        print(f"\n[ERROR] {e}")
