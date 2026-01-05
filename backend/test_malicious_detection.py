"""
Test malicious contract patterns to ensure the analyzer still catches real scams
"""
import requests
import json

# Test contracts with various risk patterns
test_contracts = [
    {
        'name': 'Squid Game Token (Known Scam)',
        'address': '0x87230146E138d3F296a9a77e497A2A83012e9Bc5',
        'description': 'Famous honeypot - could sell but not buy back'
    },
    {
        'name': 'Shiba Inu', 
        'address': '0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE',
        'description': 'Should be clean - legitimate token'
    },
    {
        'name': 'Random Contract',
        'address': '0x09750ad360fdb7a2ee23669c4503c974d86d8694',
        'description': 'Phishing scam from darklist'
    }
]

print("=" * 70)
print(" Testing Various Contracts - Malicious Detection Validation")
print("=" * 70)

for contract in test_contracts:
    print(f"\n{'='*70}")
    print(f"📋 {contract['name']}")
    print(f"   {contract['description']}")
    print(f"   Address: {contract['address']}")
    print("-" * 70)
    
    try:
        response = requests.get(
            f"http://localhost:5000/score/{contract['address']}", 
            timeout=45
        )
        result = response.json()
        
        # Overall score
        print(f"\n🎯 Overall Score: {result.get('score', 'N/A')}/100")
        print(f"📊 Prediction: {result.get('prediction', 'N/A')}")
        
        # ML Analysis
        if 'ml_analysis' in result:
            ml = result['ml_analysis']
            print(f"\n🤖 ML Analysis:")
            print(f"   Risk Score: {ml.get('risk_score', 'N/A')}/100")
            print(f"   Verdict: {ml.get('verdict', 'N/A')}")
        
        # GoPlus flags
        if 'goplus_flags' in result and result['goplus_flags']:
            print(f"\n🚩 GoPlus Flags:")
            for flag in result['goplus_flags'][:5]:
                icon = "✅" if flag.startswith("✓") else "⚠️"
                print(f"   {icon} {flag}")
        
        # Contract analysis
        if 'contract_analysis' in result and result['contract_analysis'].get('has_source'):
            ca = result['contract_analysis']
            print(f"\n💻 Smart Contract Analysis:")
            print(f"   Contract: {ca.get('contract_name', 'Unknown')}")
            print(f"   Risk Level: {ca.get('risk_level', 'N/A')}")
            print(f"   Total Findings: {ca['summary']['total_findings']}")
            
            if ca.get('findings'):
                print(f"\n🔍 Security Findings:")
                for i, finding in enumerate(ca['findings'][:5], 1):
                    conf = finding.get('confidence', 0)
                    severity_icons = {
                        'critical': '🔴',
                        'high': '🟠', 
                        'medium': '🟡',
                        'low': '⚪'
                    }
                    icon = severity_icons.get(finding['severity'].lower(), '⚫')
                    print(f"   {i}. {icon} [{conf}%] {finding['severity'].upper()} - {finding['category']}")
                    print(f"      Line {finding['line_number']}: {finding['matched_code'][:60]}...")
            else:
                print("   ✅ No malicious patterns detected")
        else:
            print(f"\n💻 Contract: Not verified or no source code available")
            
    except requests.exceptions.Timeout:
        print("   ⏱️  Request timeout (contract may be processing)")
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")

print(f"\n{'='*70}")
print("Test Complete!")
print("=" * 70)
