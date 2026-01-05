"""Test PlayQuiz balanceOf call to see exact error"""
from web3 import Web3

# Connect to Ganache
w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
print(f"Connected: {w3.is_connected()}")

token_address = "0x9e6c3DE296E4a51f2b124472Eb3e487C6cFC89a7"
test_address = Web3.to_checksum_address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0")

# Check if contract has bytecode
code = w3.eth.get_code(Web3.to_checksum_address(token_address))
print(f"\nContract bytecode length: {len(code)} bytes")
print(f"Has bytecode: {code != b'' and code != '0x'}")

# Try to call balanceOf
ERC20_ABI = [{"constant":True,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"}]

try:
    token = w3.eth.contract(address=Web3.to_checksum_address(token_address), abi=ERC20_ABI)
    balance = token.functions.balanceOf(test_address).call()
    print(f"\nBalance: {balance}")
except Exception as e:
    print(f"\nERROR calling balanceOf:")
    print(f"Type: {type(e).__name__}")
    print(f"Message: {str(e)}")
    print(f"\nSearching for keywords:")
    error_msg = str(e)
    print(f"  'Could not decode': {'Could not decode' in error_msg}")
    print(f"  'revert': {'revert' in error_msg.lower()}")
    print(f"  'execution reverted': {'execution reverted' in error_msg.lower()}")
    print(f"  'output_types': {'output_types' in error_msg}")
