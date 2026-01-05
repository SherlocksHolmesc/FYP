import requests
import time

honeypots = [
    ("0x2f30ff3428d62748a1d993f2cc6c9b55df40b4d7", "Honeypot 1"),
    ("0x80e4f014c98320eab524ae16b0aaf1603f4dc01d", "Honeypot 2"),
    ("0x31b9eb2bb4bd06b56132282c82d0437d77d2339e", "Honeypot 3"),
    ("0xfc6e926ffc17f3bdc32ac434abc895091a151364", "Honeypot 4"),
    ("0xc83be826c29defa7d9109c652713e005cade7d30", "Honeypot 5"),
    ("0x522c6ec96b2d7a2547aaf0bdc18ca3edf58539d3", "Honeypot 6"),
    ("0xa367539c6346c05cd696bb8e14e2a9c563d92ba3", "Honeypot 7"),
    ("0x9e6c3de296e4a51f2b124472eb3e487c6cfc89a7", "PlayQuiz"),
    ("0x8b9773e03e987bed942d1f9695fe6895395ca386", "Babyama"),
    ("0xe3e8a9056b757d6ed2b0f4a2526aeb420c82707a", "Honeypot 11"),
    ("0x944774d4521da53a3a0c72e081b9e9e98a7bee31", "Honeypot 12"),
    ("0x2a6602da1c6516e0266f173d4cbf0996563b6847", "Honeypot 13"),
    ("0x34c6211621f2763c60eb007dc2ae91090a2d22f6", "BELLE"),
    ("0x45dac6c8776e5eb1548d3cdcf0c5f6959e410c3a", "MommyMilkers"),
    ("0xe3b359c15c55821be80d56130acb9f071bb393ec", "Honeypot 9"),
    ("0xf80f6fa4ccb6550c9dc58d58d51fb0928f9b323c", "BELLE Rug Pull"),
]

print("=" * 80)
print("TESTING HONEYPOT DETECTION ON 16 KNOWN HONEYPOTS")
print("=" * 80)

results = {
    'detected': [],
    'missed': [],
    'errors': []
}

for address, name in honeypots:
    try:
        print(f"\n[{name}] Testing {address}...")
        response = requests.get(f"http://localhost:5000/score/{address}", timeout=60)
        data = response.json()
        
        score = data.get('score', 0)
        prediction = data.get('prediction', 'UNKNOWN')
        is_contract = data.get('is_contract', False)
        goplus_flags = data.get('goplus_flags', [])
        
        # Contract analysis
        contract_analysis = data.get('contract_analysis', {})
        has_source = contract_analysis.get('has_source', False)
        findings = contract_analysis.get('findings', [])
        
        status = "✓ DETECTED" if prediction in ['FRAUD', 'DANGEROUS', 'SUSPICIOUS'] or score >= 50 else "✗ MISSED"
        
        print(f"  Score: {score}/100 | Prediction: {prediction} | {status}")
        print(f"  Contract: {is_contract} | Has Source: {has_source} | Findings: {len(findings)}")
        if goplus_flags:
            print(f"  GoPlus: {', '.join(goplus_flags[:3])}")
        
        result_entry = {
            'name': name,
            'address': address,
            'score': score,
            'prediction': prediction,
            'has_source': has_source,
            'findings_count': len(findings),
            'goplus_flags': goplus_flags
        }
        
        if prediction in ['FRAUD', 'DANGEROUS', 'SUSPICIOUS'] or score >= 50:
            results['detected'].append(result_entry)
        else:
            results['missed'].append(result_entry)
            
        time.sleep(2)  # Rate limiting
        
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results['errors'].append({'name': name, 'address': address, 'error': str(e)})

# Summary
print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)
print(f"Total Tested: {len(honeypots)}")
print(f"✓ Detected: {len(results['detected'])} ({len(results['detected'])/len(honeypots)*100:.1f}%)")
print(f"✗ Missed: {len(results['missed'])} ({len(results['missed'])/len(honeypots)*100:.1f}%)")
print(f"⚠ Errors: {len(results['errors'])}")

if results['missed']:
    print(f"\n{'=' * 80}")
    print("MISSED HONEYPOTS - NEED INVESTIGATION:")
    print("=" * 80)
    for item in results['missed']:
        print(f"\n{item['name']} ({item['address']})")
        print(f"  Score: {item['score']} | Prediction: {item['prediction']}")
        print(f"  Has Source: {item['has_source']} | Findings: {item['findings_count']}")
        if item['goplus_flags']:
            print(f"  GoPlus: {', '.join(item['goplus_flags'][:3])}")

if results['detected']:
    print(f"\n{'=' * 80}")
    print("SUCCESSFULLY DETECTED:")
    print("=" * 80)
    for item in results['detected']:
        print(f"  ✓ {item['name']}: Score {item['score']}, {item['prediction']}")
