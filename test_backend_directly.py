"""
Direct test of backend contract analysis without going through full API
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Import backend functions
from api import get_contract_source, analyze_contract_source, analyze_solidity_code

# Test address - DAI Stablecoin (verified on Etherscan)
address = "0x6B175474E89094C44Da98b954EedeAC495271d0F"

print("=" * 70)
print("DIRECT BACKEND TEST - Smart Contract Analysis")
print("=" * 70)

print(f"\nStep 1: Fetching source code for {address}...")
source_data = get_contract_source(address)
print(f"  is_verified: {source_data.get('is_verified')}")
print(f"  contract_name: {source_data.get('contract_name')}")
print(f"  has_source_code: {bool(source_data.get('source_code'))}")
if source_data.get('source_code'):
    print(f"  source_code_length: {len(source_data['source_code'])} characters")

if not source_data.get('is_verified'):
    print("\n✗ Contract not verified. Cannot analyze.")
    sys.exit(1)

print(f"\nStep 2: Analyzing source code...")
result = analyze_contract_source(address)

print(f"\nStep 3: Analysis Results:")
print(f"  has_source: {result['has_source']}")
print(f"  contract_name: {result['contract_name']}")
print(f"  risk_level: {result['risk_level']}")
print(f"  total_findings: {result['summary']['total_findings']}")
print(f"  critical: {result['summary']['critical']}")
print(f"  high: {result['summary']['high']}")
print(f"  medium: {result['summary']['medium']}")
print(f"  low: {result['summary']['low']}")

if result.get('error'):
    print(f"\n  ERROR: {result['error']}")

if result['findings']:
    print(f"\nFindings:")
    for i, finding in enumerate(result['findings'][:3], 1):
        print(f"  {i}. [{finding['severity'].upper()}] {finding['category']}")
        print(f"     Line {finding['line_number']}: {finding['matched_code'][:80]}")

print("\n" + "=" * 70)
print("CONCLUSION:")
if result['has_source'] and result['summary']['total_findings'] > 0:
    print("✓ Smart contract analysis is WORKING!")
    print(f"  Found {result['summary']['total_findings']} potential issues")
elif result['has_source']:
    print("✓ Smart contract analysis is WORKING!")
    print("  No suspicious patterns detected (contract is clean)")
else:
    print("✗ Smart contract analysis FAILED")
    if result.get('error'):
        print(f"  Reason: {result['error']}")
print("=" * 70)
