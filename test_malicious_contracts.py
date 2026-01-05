"""
Test malicious contract patterns with actual smart contracts
"""
import requests
import json
import time

# Known problematic contracts to test
test_addresses = [
    # Squid Game Token - known rug pull
    ("0x87230146E138d3F296a9a77e497A2A83012e9Bc5", "Squid Game Token (Rug Pull)"),
    
    # AnubisDAO - rug pull
    ("0xf8e81D47203A594245E36C48e151709F0C19fBe8", "AnubisDAO (Rug Pull)"),
    
    # Known honeypot examples
    ("0x000000000000000000000000000000000000dead", "Burn Address (Test)"),
    
    # Test with a random token that might have issues
    ("0x4f7f1380239450AAD5af611DB3c3c1bb51049c29", "Random Contract 1"),
]

print("=" * 80)
print("TESTING MALICIOUS CONTRACT DETECTION")
print("=" * 80)

for address, name in test_addresses:
    print(f"\n{'='*80}")
    print(f"Testing: {name}")
    print(f"Address: {address}")
    print("=" * 80)
    
    try:
        response = requests.get(f"http://localhost:5000/score/{address}", timeout=45)
        data = response.json()
        
        print(f"\n[BASIC INFO]")
        print(f"  is_contract: {data.get('is_contract')}")
        print(f"  is_honeypot (GoPlus): {data.get('is_honeypot')}")
        print(f"  prediction: {data.get('prediction')}")
        print(f"  score: {data.get('score')}/100")
        
        if data.get('goplus_flags'):
            print(f"\n[GOPLUS FLAGS]")
            for flag in data['goplus_flags'][:5]:
                print(f"  - {flag}")
        
        ca = data.get('contract_analysis')
        if ca:
            print(f"\n[CONTRACT ANALYSIS]")
            print(f"  has_source: {ca.get('has_source')}")
            print(f"  contract_name: {ca.get('contract_name')}")
            print(f"  risk_level: {ca.get('risk_level')}")
            
            if ca.get('error'):
                print(f"  ERROR: {ca['error']}")
            
            summary = ca.get('summary', {})
            print(f"\n[FINDINGS SUMMARY]")
            print(f"  Total: {summary.get('total_findings', 0)}")
            print(f"  Critical: {summary.get('critical', 0)}")
            print(f"  High: {summary.get('high', 0)}")
            print(f"  Medium: {summary.get('medium', 0)}")
            print(f"  Low: {summary.get('low', 0)}")
            
            if ca.get('findings'):
                print(f"\n[TOP FINDINGS]")
                for i, finding in enumerate(ca['findings'][:3], 1):
                    print(f"\n  {i}. [{finding['severity'].upper()}] {finding['category']}")
                    print(f"     Line {finding['line_number']}")
                    print(f"     Code: {finding['matched_code'][:100]}...")
        else:
            print(f"\n[CONTRACT ANALYSIS]")
            print(f"  ✗ No analysis (contract_analysis is null)")
        
        print(f"\n{'='*80}")
        
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
    
    time.sleep(2)

print(f"\n{'='*80}")
print("TEST COMPLETE")
print("=" * 80)
