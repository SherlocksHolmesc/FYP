import requests
import json

# Test SafeMoon which has trading restrictions
safemoon = '0x8076C74C5e3F5852037F31Ff0093Eeb8c8ADd8D3'

print("=" * 70)
print("TESTING SAFEMOON - Known for trading restrictions")
print("=" * 70)

response = requests.get(f'http://localhost:5000/score/{safemoon}', timeout=60)
result = response.json()

if result.get('contract_analysis', {}).get('has_source'):
    ca = result['contract_analysis']
    print(f"\n✓ Contract: {ca.get('contract_name')}")
    print(f"✓ Verified Source: YES")
    print(f"✓ Risk Level: {ca.get('risk_level')}")
    print(f"✓ Total Findings: {ca.get('summary', {}).get('total_findings')}")
    
    if ca.get('findings'):
        print("\n" + "="*70)
        print("MALICIOUS CODE BREAKDOWN:")
        print("="*70)
        
        for i, finding in enumerate(ca['findings'], 1):
            print(f"\n🚨 FINDING #{i}")
            print(f"   Severity: {finding['severity'].upper()}")
            print(f"   Confidence: {finding.get('confidence', 'N/A')}%")
            print(f"   Category: {finding['category']}")
            print(f"   Line Number: {finding['line_number']}")
            print(f"   Matched Code: {finding['matched_code'][:100]}")
            print(f"   Description: {finding['description']}")
            
            # Show code context
            if finding.get('context'):
                print(f"\n   CODE CONTEXT:")
                lines = finding['context'].split('\n')
                for line in lines[:15]:  # Show first 15 lines
                    print(f"   {line}")
        
        print(f"\n{'='*70}")
        print(f"✅ PASTE THIS IN SCANNER UI: {safemoon}")
        print(f"{'='*70}")
    else:
        print("\n⚠️  No findings detected with current thresholds")
        print("     (Our improved analysis filtered false positives)")
else:
    print("\n❌ Source code not available for this contract")
    print("   (Most scams don't verify their code)")
    
    # Show alternative detection
    if result.get('is_honeypot'):
        print(f"\n✅ BUT STILL DETECTED as honeypot via GoPlus API!")
        print(f"   Score: {result.get('score')}/100")
        if result.get('goplus_flags'):
            print(f"   Flags: {', '.join(result['goplus_flags'])}")
