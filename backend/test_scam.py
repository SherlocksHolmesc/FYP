import requests

# Known scam addresses that should be detected
# These are from real scam reports but may not have verified source code
scam_addresses = [
    '0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE',  # SHIB (has blacklist)
    '0xC0Eb85285d83217CD7c891702bcbC0FC401E2D9D',  # HEX
    '0xa0787daad6062349f63b7c228cbfd5d8a3db08f1',  # Known honeypot
]

print("=" * 60)
print("SEARCHING FOR VERIFIED MALICIOUS CONTRACTS")
print("=" * 60)

for addr in scam_addresses:
    print(f"\nTesting: {addr}")
    try:
        response = requests.get(f'http://localhost:5000/score/{addr}', timeout=40)
        result = response.json()
        
        if result.get('contract_analysis', {}).get('has_source'):
            ca = result['contract_analysis']
            print(f"\n{'='*60}")
            print(f"FOUND VERIFIED CONTRACT WITH SOURCE CODE!")
            print(f"{'='*60}")
            print(f"Contract: {ca.get('contract_name')}")
            print(f"Risk Level: {ca.get('risk_level')}")
            print(f"Total Findings: {ca.get('summary', {}).get('total_findings')}")
            
            if ca.get('findings'):
                print("\nDetected Issues:")
                for finding in ca['findings']:
                    conf = finding.get('confidence', 'N/A')
                    print(f"  [{conf}%] {finding['severity'].upper()} - {finding['category']}")
                    print(f"      Line {finding['line_number']}: {finding['matched_code'][:60]}...")
                    print(f"      {finding['description']}")
            
            print(f"\nUSE THIS ADDRESS IN SCANNER: {addr}")
            break
        else:
            print("  Source code not available")
            
    except Exception as e:
        print(f"  Error: {e}")

print("\n" + "="*60)
