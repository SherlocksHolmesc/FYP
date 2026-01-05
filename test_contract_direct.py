import requests
import json

# Test Etherscan API directly
addresses = [
    ("DAI", "0x6B175474E89094C44Da98b954EedeAC495271d0F"),
    ("USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"),
    ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
    ("WETH", "0xC02aaA39b223FE8D0A3e5C4F27eAD9083C756Cc2"),
]

API_KEY = "Z9VWEZXXYKBWJQXAPF3BUC6DMS7Z8VUMGE"
BASE_URL = "https://api.etherscan.io/v2/api"

print("\n=== Testing Etherscan Contract Source API ===\n")

for name, address in addresses:
    print(f"Testing {name} ({address})...")
    
    params = {
        'module': 'contract',
        'action': 'getsourcecode',
        'address': address,
        'apikey': API_KEY,
        'chainid': 1
    }
    
    try:
        response = requests.get(BASE_URL, params=params, timeout=15)
        data = response.json()
        
        if data.get('status') == '1' and data.get('result'):
            result = data['result'][0]
            source = result.get('SourceCode', '')
            
            if source:
                print(f"  ✓ Source available! Length: {len(source)}")
                print(f"    Contract: {result.get('ContractName', 'Unknown')}")
                print(f"    Compiler: {result.get('CompilerVersion', 'Unknown')}")
                
                # Check if it's a proxy or complex source
                if source.startswith('{'):
                    print(f"    Type: JSON (Multi-file or Proxy)")
                else:
                    print(f"    Type: Single file")
            else:
                print(f"  ✗ No source code")
        else:
            print(f"  ✗ API Error: {data.get('message', 'Unknown')}")
    
    except Exception as e:
        print(f"  ✗ Exception: {e}")
    
    print()

print("\n=== Testing Local API ===\n")

for name, address in addresses:
    print(f"Testing {name} ({address})...")
    
    try:
        response = requests.get(f"http://localhost:5000/score/{address}", timeout=60)
        data = response.json()
        
        ca = data.get('contract_analysis')
        if ca:
            print(f"  ✓ Contract analysis returned")
            print(f"    Has source: {ca.get('has_source', False)}")
            print(f"    Contract name: {ca.get('contract_name', 'N/A')}")
            print(f"    Risk level: {ca.get('risk_level', 'N/A')}")
            print(f"    Findings: {ca.get('summary', {}).get('total_findings', 0)}")
            if ca.get('error'):
                print(f"    Error: {ca['error']}")
        else:
            print(f"  ✗ No contract analysis")
    
    except Exception as e:
        print(f"  ✗ Exception: {e}")
    
    print()
