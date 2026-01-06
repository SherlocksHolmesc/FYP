"""
Test Address Classification
Test all legitimate tokens, system contracts, and honeypots
"""
import requests
import json
import time

API_URL = "http://localhost:5000"

# Test data from user
TEST_ADDRESSES = {
    "legitimate_tokens": [
        ("0x5a3e6a77ba2f983ec0d371ea3b475f8bc0811ad5", "0x0.ai: AI Smart Contract Auditor"),
        ("0x0f71b8de197a1c84d31de0f1fa7926c365f052b3", "Arcona Distribution Contract"),
        ("0x6710c63432a2de02954fc0f851db07146a6c0312", "Smart MFG"),
        ("0x2dcfaac11c9eebd8c6c42103fe9e2a6ad237af27", "Smart Node"),
        ("0x6f6deb5db0c4994a8283a01d6cfeeb27fc3bbe9c", "SmartBillions"),
        ("0xddcc69879e1d2376ce799051afa98c689f234cca", "SmartMoney"),
        ("0x838df5c03147f0b038c24b18af5bb5dee1ffd446", "Edgecoin Smart Token"),
        ("0x22987407fd1fc5a971e3fda3b3e74c88666cda91", "Smart Reward Token"),
        ("0x58aea10748a00d1781d6651f9d78a414ea32ca46", "Vector Smart Gas"),
        ("0xd38de88687172bde440755b5237987e4a87c23a7", "AEN Smart Token"),
        ("0x41b723c73fe13e8f979d5fa80229ce7f24ebedb8", "OnTact"),
        ("0x859e4d219e83204a2ea389dac11048cc880b6aa8", "Idle Smart Treasury Token"),
        ("0x4e9a46ea6a22f3894abee2302ad42fd3b69e21e2", "Binance Smart Chain Girl"),
        ("0xb1cd6e4153b2a390cf00a6556b0fc1458c4a5533", "BNT Smart Token Relay"),
        ("0xdf49c9f599a0a9049d97cff34d0c30e468987389", "Smart Advertising Transaction Token"),
    ],
    "system_contracts": [
        ("0xc0a47dfe034b400b47bdad5fecda2621de6c4d95", "Uniswap: Factory Contract"),
        ("0x00000000000044acf0c243eecb34c8c0069b2e4b", "Uniswap: Vulnerable Contract"),
        ("0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f", "Uniswap V2: Factory Contract"),
        ("0x5a9fd7c39a6c488e715437d7b1f3c823d5596ed1", "LI.Fi smart contract"),
        ("0x97f5f1893e9961ad6adbdfea196d33687fa699b1", "Smart Contract Exploiter"),
        ("0x5e4be8bc9637f0eaa1a755019e06a68ce081d58f", "Uniswap V2: UNI Governance Contract"),
        ("0xef0b56692f78a44cf4034b07f80204757c31bcc9", "MoonPay: Proxy Smart Contract"),
        ("0x0cbc55211c36a6d8fdf4310207ffb286193b4f67", "Smart Alert: SMRT Token"),
        ("0xd54f502e184b6b739d7d27a6410a67dc462d69c8", "dYdX: L2 Perpetual Smart Contract"),
        ("0xfe7290b932cd0d5aec29c57394e87cdaa41cc054", "Smart AI: SMART Token"),
    ],
    "honeypots": [
        ("0x2f30ff3428d62748a1d993f2cc6c9b55df40b4d7", "Compromised: Honeypot"),
        ("0x80e4f014c98320eab524ae16b0aaf1603f4dc01d", "Compromised: Honeypot 2"),
        ("0x31b9eb2bb4bd06b56132282c82d0437d77d2339e", "Compromised: Honeypot 3"),
        ("0xfc6e926ffc17f3bdc32ac434abc895091a151364", "Compromised: Honeypot 4"),
        ("0xc83be826c29defa7d9109c652713e005cade7d30", "Compromised: Honeypot 5"),
        ("0x522c6ec96b2d7a2547aaf0bdc18ca3edf58539d3", "Compromised: Honeypot 6"),
        ("0xa367539c6346c05cd696bb8e14e2a9c563d92ba3", "Compromised: Honeypot 7"),
        ("0x9e6c3de296e4a51f2b124472eb3e487c6cfc89a7", "Compromised: Honeypot 8"),
        ("0x8b9773e03e987bed942d1f9695fe6895395ca386", "Babyama Honeypot Token"),
        ("0xe3e8a9056b757d6ed2b0f4a2526aeb420c82707a", "Compromised: Honeypot 11"),
        ("0x944774d4521da53a3a0c72e081b9e9e98a7bee31", "Compromised: Honeypot 12"),
        ("0x2a6602da1c6516e0266f173d4cbf0996563b6847", "Compromised: Honeypot 13"),
        ("0x34c6211621f2763c60eb007dc2ae91090a2d22f6", "Honeypot Token (BELLE)"),
        ("0x45dac6c8776e5eb1548d3cdcf0c5f6959e410c3a", "MommyMilkers Honeypot Token"),
        ("0xe3b359c15c55821be80d56130acb9f071bb393ec", "Compromised: Honeypot 9"),
        ("0xf80f6fa4ccb6550c9dc58d58d51fb0928f9b323c", "BELLE Honeypot Rug Pull"),
    ]
}

def test_address(address, name, expected_type):
    """Test a single address"""
    print(f"\n{'='*80}")
    print(f"Testing: {name}")
    print(f"Address: {address}")
    print(f"Expected: {expected_type}")
    print(f"{'='*80}")
    
    try:
        # Test /score endpoint
        response = requests.get(f"{API_URL}/score/{address}", timeout=30)
        data = response.json()
        
        score = data.get('score', 50)
        prediction = data.get('prediction', 'UNKNOWN')
        is_honeypot = data.get('is_honeypot', False)
        whitelisted = data.get('whitelisted', False)
        is_contract = data.get('is_contract', False)
        
        # Determine result
        if expected_type == "LEGITIMATE":
            if whitelisted:
                result = "[PASS] Whitelisted"
                color = "green"
            elif score <= 30 and prediction == "SAFE":
                result = "[PASS] Detected as Safe"
                color = "green"
            else:
                result = f"[FAIL] Score: {score}, Prediction: {prediction}"
                color = "red"
                
        elif expected_type == "SYSTEM_CONTRACT":
            if not is_contract or score <= 40:
                result = "[PASS] Correctly identified as non-token contract"
                color = "green"
            else:
                result = f"[WARN] Flagged as risky (Score: {score})"
                color = "yellow"
                
        elif expected_type == "HONEYPOT":
            if is_honeypot or score >= 70:
                result = "[PASS] Correctly detected as honeypot/malicious"
                color = "green"
            else:
                result = f"[FAIL] Missed honeypot (Score: {score}, is_honeypot: {is_honeypot})"
                color = "red"
        else:
            result = "[UNKNOWN]"
            color = "gray"
        
        print(f"\n{result}")
        print(f"Score: {score}/100")
        print(f"Prediction: {prediction}")
        print(f"Is Honeypot: {is_honeypot}")
        print(f"Whitelisted: {whitelisted}")
        
        if data.get('contract_analysis'):
            findings_count = len(data['contract_analysis'].get('findings', []))
            print(f"Contract Findings: {findings_count}")
        
        return {
            'address': address,
            'name': name,
            'expected': expected_type,
            'score': score,
            'prediction': prediction,
            'is_honeypot': is_honeypot,
            'whitelisted': whitelisted,
            'result': result,
            'color': color
        }
        
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return {
            'address': address,
            'name': name,
            'expected': expected_type,
            'error': str(e),
            'result': f"[ERROR] {str(e)}",
            'color': 'red'
        }

def main():
    print("""
================================================================================
                   ADDRESS CLASSIFICATION TEST SUITE                         
                                                                              
 Testing legitimate tokens, system contracts, and known honeypots           
================================================================================
    """)
    
    results = {
        'legitimate_tokens': [],
        'system_contracts': [],
        'honeypots': []
    }
    
    # Test legitimate tokens
    print("\n\n" + "="*80)
    print("TESTING LEGITIMATE TOKENS (Should be SAFE/WHITELISTED)")
    print("="*80)
    for address, name in TEST_ADDRESSES['legitimate_tokens']:
        result = test_address(address, name, "LEGITIMATE")
        results['legitimate_tokens'].append(result)
        time.sleep(0.5)  # Rate limiting
    
    # Test system contracts
    print("\n\n" + "="*80)
    print("TESTING SYSTEM CONTRACTS (Should be low risk or not tradeable)")
    print("="*80)
    for address, name in TEST_ADDRESSES['system_contracts']:
        result = test_address(address, name, "SYSTEM_CONTRACT")
        results['system_contracts'].append(result)
        time.sleep(0.5)
    
    # Test honeypots
    print("\n\n" + "="*80)
    print("TESTING KNOWN HONEYPOTS (Should be detected as FRAUD/HONEYPOT)")
    print("="*80)
    for address, name in TEST_ADDRESSES['honeypots']:
        result = test_address(address, name, "HONEYPOT")
        results['honeypots'].append(result)
        time.sleep(0.5)
    
    # Generate summary
    print("\n\n" + "="*80)
    print("SUMMARY REPORT")
    print("="*80)
    
    for category, items in results.items():
        passed = sum(1 for r in items if '[PASS]' in r['result'])
        total = len(items)
        percentage = (passed / total * 100) if total > 0 else 0
        
        print(f"\n{category.replace('_', ' ').title()}: {passed}/{total} ({percentage:.1f}%)")
        
        # Show failures
        failures = [r for r in items if '[FAIL]' in r['result']]
        if failures:
            print("\n  Failures:")
            for f in failures:
                print(f"    - {f['name']}: {f['result']}")
    
    # Overall stats
    total_passed = sum(sum(1 for r in items if '[PASS]' in r['result']) for items in results.values())
    total_tests = sum(len(items) for items in results.values())
    overall_percentage = (total_passed / total_tests * 100) if total_tests > 0 else 0
    
    print(f"\n{'='*80}")
    print(f"OVERALL: {total_passed}/{total_tests} tests passed ({overall_percentage:.1f}%)")
    print(f"{'='*80}\n")
    
    # Save detailed results
    with open('test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print("Detailed results saved to test_results.json")

if __name__ == "__main__":
    main()
