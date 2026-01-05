"""
Test script to analyze PlayQuiz honeypot contract
Address: 0x9e6c3DE296E4a51f2b124472Eb3e487C6cFC89a7
"""
import requests
import json

ADDRESS = "0x9e6c3DE296E4a51f2b124472Eb3e487C6cFC89a7"
BASE_URL = "http://localhost:5000"

print("="*70)
print("TESTING PLAYQUIZ HONEYPOT CONTRACT")
print("="*70)
print(f"\nAddress: {ADDRESS}")
print("\nThis is a verified contract on Etherscan with source code.")
print("GoPlus flags it as 'Stealing Attack' but it's actually a quiz honeypot.")

# Test 1: Full scan
print("\n" + "="*70)
print("TEST 1: Full /score endpoint")
print("="*70)
try:
    response = requests.get(f"{BASE_URL}/score/{ADDRESS}", timeout=60)
    result = response.json()
    
    print(f"\nIs Contract: {result.get('is_contract')}")
    print(f"Is Honeypot: {result.get('is_honeypot')}")
    print(f"Score: {result.get('score')}/100")
    print(f"Prediction: {result.get('prediction')}")
    print(f"GoPlus Flags: {result.get('goplus_flags')}")
    
    if result.get('contract_analysis'):
        ca = result['contract_analysis']
        print(f"\nContract Analysis:")
        print(f"  Has Source: {ca.get('has_source')}")
        if ca.get('has_source'):
            print(f"  Contract Name: {ca.get('contract_name')}")
            print(f"  Risk Level: {ca.get('risk_level')}")
            print(f"  Total Findings: {ca.get('summary', {}).get('total_findings')}")
            
            if ca.get('findings'):
                print(f"\n  Findings:")
                for f in ca['findings']:
                    print(f"    - [{f['confidence']}%] {f['severity'].upper()} - {f['category']}")
                    print(f"      Line {f['line_number']}: {f['matched_code'][:60]}")
    else:
        print("\nNo contract analysis performed!")
        print("ISSUE: GoPlus flagged as 'Stealing Attack' before contract analysis could run")
    
except Exception as e:
    print(f"Error: {e}")

# Test 2: Check Etherscan directly
print("\n" + "="*70)
print("TEST 2: Etherscan API - Verify it's a contract")
print("="*70)
try:
    etherscan_key = "Z9VWEZXXYKBWJQXAPF3BUC6DMS7Z8VUMGE"
    url = f"https://api.etherscan.io/v2/api?chainid=1&module=contract&action=getsourcecode&address={ADDRESS}&apikey={etherscan_key}"
    response = requests.get(url, timeout=15)
    data = response.json()
    
    if data['result'][0]['SourceCode']:
        print(f"\n✓ Contract IS verified on Etherscan!")
        print(f"  Contract Name: {data['result'][0]['ContractName']}")
        print(f"  Compiler: {data['result'][0]['CompilerVersion']}")
        print(f"\n  Source code length: {len(data['result'][0]['SourceCode'])} characters")
        
        # Check for honeypot patterns in source
        source = data['result'][0]['SourceCode']
        print(f"\n  Honeypot Pattern Analysis:")
        
        if 'require(msg.sender == tx.origin)' in source:
            print("    ✗ FOUND: require(msg.sender == tx.origin) - Prevents contracts from calling")
        
        if 'payable(msg.sender).transfer(3 ether)' in source:
            print("    ✗ FOUND: Fixed refund amount - May fail if balance insufficient")
        
        if 'admin[keccak256(abi.encodePacked(msg.sender))]' in source:
            print("    ✗ FOUND: Hidden admin check - Uses hash comparison")
        
        if 'isAdmin' in source:
            print("    ✗ FOUND: Admin-only functions - Owner can withdraw all funds")
        
        if 'WORKSHOP' in source or 'INTERNAL TEST' in source:
            print("    ⚠ FOUND: Fake test disclaimer - Classic honeypot social engineering")
        
    else:
        print("\n✗ Contract not verified")
        
except Exception as e:
    print(f"Error: {e}")

# Test 3: GoPlus API check
print("\n" + "="*70)
print("TEST 3: GoPlus API - Raw Response")
print("="*70)
try:
    response = requests.get(f"{BASE_URL}/goplus/{ADDRESS}", timeout=15)
    goplus_data = response.json()
    
    print(f"\nIs Contract: {goplus_data.get('is_contract')}")
    print(f"Is Honeypot: {goplus_data.get('is_honeypot')}")
    print(f"Is Malicious: {goplus_data.get('is_malicious')}")
    print(f"Flags: {goplus_data.get('flags')}")
    
    if goplus_data.get('raw', {}).get('address_security'):
        addr_sec = goplus_data['raw']['address_security']
        print(f"\nAddress Security Flags:")
        for key, value in addr_sec.items():
            if value == '1':
                print(f"  - {key}: {value}")
                
except Exception as e:
    print(f"Error: {e}")

print("\n" + "="*70)
print("SUMMARY")
print("="*70)
print("""
ISSUE IDENTIFIED:
-----------------
1. GoPlus flagged this address as 'Stealing Attack' (address_security)
2. Because score >= 80, predict_risk() returns early at line 1773
3. Contract source code analysis never runs (line 1778)
4. System misses verified honeypot patterns in the actual source code

SOLUTION:
---------
Modify predict_risk() to:
1. Always check if address has verified source code on Etherscan
2. Run contract analysis even if GoPlus flags the address
3. Combine both results - address flags + source code patterns
4. Final score = max(goplus_score, contract_analysis_score)

ACTUAL HONEYPOT PATTERNS IN SOURCE:
-----------------------------------
1. require(msg.sender == tx.origin) - Blocks contract interactions
2. Fixed 3 ether refund - Will fail when balance low
3. Admin-only withdrawal - Owner can drain anytime
4. Hash-based admin check - Hard to verify who's admin
5. Fake "WORKSHOP DAY 1 - FOR INTERNAL TEST" disclaimer
""")
