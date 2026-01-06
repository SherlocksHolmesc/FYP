"""
Test script for dApp Simulator - Phishing and Typosquatting Detection
"""
import requests
import json

BASE_URL = "http://localhost:5000"

# Test cases
test_cases = [
    {
        "name": "Legitimate Uniswap",
        "url": "https://app.uniswap.org",
        "expected": "SAFE",
        "type": "control"
    },
    {
        "name": "Typosquatting - uniswap.live",
        "url": "https://uniswap.live",
        "expected": "MALICIOUS",
        "type": "typosquatting"
    },
    {
        "name": "Typosquatting - uniswap.xyz",
        "url": "https://uniswap.xyz",
        "expected": "MALICIOUS",
        "type": "typosquatting"
    },
    {
        "name": "Typosquatting - metamask.xyz",
        "url": "https://metamask.xyz",
        "expected": "MALICIOUS",
        "type": "typosquatting"
    },
    {
        "name": "Typosquatting - aave.top",
        "url": "https://aave.top",
        "expected": "MALICIOUS",
        "type": "typosquatting"
    },
    {
        "name": "Typosquatting - opensea.site",
        "url": "https://opensea.site",
        "expected": "MALICIOUS",
        "type": "typosquatting"
    },
    {
        "name": "Typosquatting - compound-finance.online",
        "url": "https://compound-finance.online",
        "expected": "MALICIOUS",
        "type": "typosquatting"
    }
]

print("="*80)
print("dApp Simulator - Phishing & Typosquatting Detection Test")
print("="*80)

results = []

for i, test in enumerate(test_cases, 1):
    print(f"\n[{i}/{len(test_cases)}] Testing: {test['name']}")
    print(f"    URL: {test['url']}")
    print(f"    Expected: {test['expected']}")
    
    try:
        response = requests.get(
            f"{BASE_URL}/simulate-dapp",
            params={"url": test["url"]},
            timeout=120
        )
        
        if response.status_code == 200:
            data = response.json()
            
            is_malicious = data.get('is_malicious', False)
            confidence = data.get('confidence', 0)
            reason = data.get('reason', '')
            threats = data.get('threats', [])
            
            # Determine result
            actual = "MALICIOUS" if is_malicious else "SAFE"
            passed = (actual == test['expected'])
            
            results.append({
                'test': test['name'],
                'passed': passed,
                'actual': actual,
                'expected': test['expected'],
                'confidence': confidence,
                'threats': len(threats)
            })
            
            # Print result
            status = "✓ PASS" if passed else "✗ FAIL"
            color = "\033[92m" if passed else "\033[91m"
            reset = "\033[0m"
            
            print(f"    Result: {color}{status}{reset}")
            print(f"    → Malicious: {is_malicious} (Confidence: {confidence}%)")
            print(f"    → Threats: {len(threats)}")
            
            if threats:
                threat_types = set(t.get('type', 'UNKNOWN') for t in threats)
                print(f"    → Types: {', '.join(threat_types)}")
            
            if not passed:
                print(f"    → Reason: {reason}")
        else:
            print(f"    ✗ FAIL - HTTP {response.status_code}")
            print(f"    → Error: {response.text[:200]}")
            results.append({
                'test': test['name'],
                'passed': False,
                'actual': 'ERROR',
                'expected': test['expected'],
                'confidence': 0,
                'threats': 0
            })
    
    except requests.Timeout:
        print(f"    ✗ TIMEOUT")
        results.append({
            'test': test['name'],
            'passed': False,
            'actual': 'TIMEOUT',
            'expected': test['expected'],
            'confidence': 0,
            'threats': 0
        })
    except Exception as e:
        print(f"    ✗ ERROR: {str(e)}")
        results.append({
            'test': test['name'],
            'passed': False,
            'actual': 'ERROR',
            'expected': test['expected'],
            'confidence': 0,
            'threats': 0
        })

# Summary
print("\n" + "="*80)
print("SUMMARY")
print("="*80)

passed = sum(1 for r in results if r['passed'])
total = len(results)
success_rate = (passed / total * 100) if total > 0 else 0

print(f"\nTests Passed: {passed}/{total} ({success_rate:.1f}%)")
print(f"\nDetailed Results:")
print(f"{'Test':<40} {'Expected':<12} {'Actual':<12} {'Status'}")
print("-" * 80)

for r in results:
    status = "✓" if r['passed'] else "✗"
    print(f"{r['test']:<40} {r['expected']:<12} {r['actual']:<12} {status}")

# Breakdown by type
print(f"\nTyposquatting Detection:")
typo_tests = [r for r in results if 'typo' in test_cases[[t['name'] for t in test_cases].index(r['test'])]['type']]
typo_passed = sum(1 for r in typo_tests if r['passed'])
print(f"  {typo_passed}/{len(typo_tests)} detected correctly")

print("\n" + "="*80)
