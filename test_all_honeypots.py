"""
Test all known honeypot addresses to validate detection accuracy.
Source: https://medium.com/@gerhard.wagner/the-phenomena-of-smart-contract-honeypots-755c1f943f7b
"""

import requests
import json
import time
from datetime import datetime

# Known honeypot addresses from Etherscan and research papers
HONEYPOTS = [
    {
        'name': 'Compromised: Honeypot',
        'address': '0x2f30ff3428d62748a1d993f2cc6c9b55df40b4d7',
        'source': 'https://medium.com/@gerhard.wagner/the-phenomena-of-smart-contract-honeypots-755c1f943f7b'
    },
    {
        'name': 'Compromised: Honeypot 2',
        'address': '0x80e4f014c98320eab524ae16b0aaf1603f4dc01d',
        'source': 'https://medium.com/@gerhard.wagner/the-phenomena-of-smart-contract-honeypots-755c1f943f7b'
    },
    {
        'name': 'Compromised: Honeypot 3',
        'address': '0x31b9eb2bb4bd06b56132282c82d0437d77d2339e',
        'source': 'https://medium.com/@gerhard.wagner/the-phenomena-of-smart-contract-honeypots-755c1f943f7b'
    },
    {
        'name': 'Compromised: Honeypot 4',
        'address': '0xfc6e926ffc17f3bdc32ac434abc895091a151364',
        'source': 'Etherscan'
    },
    {
        'name': 'Compromised: Honeypot 5',
        'address': '0xc83be826c29defa7d9109c652713e005cade7d30',
        'source': 'Etherscan'
    },
    {
        'name': 'Compromised: Honeypot 6',
        'address': '0x522c6ec96b2d7a2547aaf0bdc18ca3edf58539d3',
        'source': 'Etherscan'
    },
    {
        'name': 'Compromised: Honeypot 7',
        'address': '0xa367539c6346c05cd696bb8e14e2a9c563d92ba3',
        'source': 'https://medium.com/@gerhard.wagner/the-phenomena-of-smart-contract-honeypots-755c1f943f7b'
    },
    {
        'name': 'Compromised: Honeypot 8',
        'address': '0x9e6c3de296e4a51f2b124472eb3e487c6cfc89a7',
        'source': 'https://medium.com/@gerhard.wagner/the-phenomena-of-smart-contract-honeypots-755c1f943f7b'
    },
    {
        'name': 'Babyama Honeypot Token',
        'address': '0x8b9773e03e987bed942d1f9695fe6895395ca386',
        'source': 'User Report'
    },
    {
        'name': 'Compromised: Honeypot 11',
        'address': '0xe3e8a9056b757d6ed2b0f4a2526aeb420c82707a',
        'source': 'https://medium.com/@gerhard.wagner/the-phenomena-of-smart-contract-honeypots-755c1f943f7b'
    },
    {
        'name': 'Compromised: Honeypot 12',
        'address': '0x944774d4521da53a3a0c72e081b9e9e98a7bee31',
        'source': 'https://medium.com/@gerhard.wagner/the-phenomena-of-smart-contract-honeypots-755c1f943f7b'
    },
    {
        'name': 'Compromised: Honeypot 13',
        'address': '0x2a6602da1c6516e0266f173d4cbf0996563b6847',
        'source': 'https://medium.com/@gerhard.wagner/the-phenomena-of-smart-contract-honeypots-755c1f943f7b'
    },
    {
        'name': 'Honeypot Token (BELLE)',
        'address': '0x34c6211621f2763c60eb007dc2ae91090a2d22f6',
        'source': 'Known BELLE Token'
    },
    {
        'name': 'MommyMilkers Honeypot Token',
        'address': '0x45dac6c8776e5eb1548d3cdcf0c5f6959e410c3a',
        'source': 'Community Report'
    },
    {
        'name': 'Compromised: Honeypot 9',
        'address': '0xe3b359c15c55821be80d56130acb9f071bb393ec',
        'source': 'https://medium.com/@gerhard.wagner/the-phenomena-of-smart-contract-honeypots-755c1f943f7b'
    },
    {
        'name': 'BELLE Honeypot Rug Pull',
        'address': '0xf80f6fa4ccb6550c9dc58d58d51fb0928f9b323c',
        'source': 'Known Rug Pull'
    }
]

BASE_URL = 'http://localhost:5000'

def test_address(address_info):
    """Test a single address for honeypot detection."""
    address = address_info['address']
    name = address_info['name']
    
    print(f"\n{'='*80}")
    print(f"Testing: {name}")
    print(f"Address: {address}")
    print(f"Source: {address_info['source']}")
    print('='*80)
    
    result = {
        'name': name,
        'address': address,
        'timestamp': datetime.now().isoformat()
    }
    
    # Test 1: Overall Risk Score
    try:
        print("\n[1] Overall Risk Score (ML + GoPlus + Contract Analysis)...")
        response = requests.get(f"{BASE_URL}/score/{address}", timeout=120)
        
        if response.status_code == 200:
            data = response.json()
            result['score'] = data.get('score', 0)
            result['prediction'] = data.get('prediction', 'UNKNOWN')
            result['is_honeypot'] = data.get('is_honeypot', False)
            result['goplus_flags'] = data.get('goplus_flags', [])
            
            # Contract analysis findings
            contract_analysis = data.get('contract_analysis', {})
            if contract_analysis.get('has_source'):
                findings = contract_analysis.get('findings', [])
                result['contract_findings_count'] = len(findings)
                result['contract_risk'] = contract_analysis.get('summary', {})
            
            print(f"   Score: {data.get('score')}/100 - {data.get('prediction')}")
            print(f"   Is Honeypot (GoPlus): {data.get('is_honeypot')}")
            if data.get('goplus_flags'):
                print(f"   GoPlus Flags: {', '.join(data.get('goplus_flags'))}")
            
    except requests.exceptions.Timeout:
        print(f"   ⚠ Timeout (>120s)")
        result['score_error'] = 'timeout'
    except Exception as e:
        print(f"   ✗ Error: {e}")
        result['score_error'] = str(e)
    
    # Test 2: Runtime Honeypot Simulation
    try:
        print("\n[2] Runtime Simulation (Buy/Sell Test)...")
        response = requests.get(f"{BASE_URL}/simulate/{address}", timeout=180)
        
        if response.status_code == 200:
            data = response.json()
            result['simulation'] = {
                'is_honeypot': data.get('is_honeypot'),
                'confidence': data.get('confidence', 0),
                'pattern': data.get('pattern', 'UNKNOWN'),
                'reason': data.get('reason', '')
            }
            
            # Buy/Sell test results
            if data.get('buy_test'):
                buy_success = data['buy_test'].get('success', False)
                result['simulation']['buy_success'] = buy_success
                
            if data.get('sell_test'):
                sell_success = data['sell_test'].get('success', False)
                result['simulation']['sell_success'] = sell_success
            
            print(f"   Is Honeypot: {data.get('is_honeypot')} ({data.get('confidence')}% confidence)")
            print(f"   Pattern: {data.get('pattern')}")
            print(f"   Reason: {data.get('reason')}")
            
            if data.get('malicious_code'):
                print(f"   Malicious Code Patterns: {len(data['malicious_code'])}")
                result['simulation']['malicious_patterns'] = len(data['malicious_code'])
                
        elif response.status_code == 503:
            print(f"   ⚠ Ganache not running - simulation unavailable")
            result['simulation_error'] = 'ganache_not_running'
        else:
            print(f"   ✗ HTTP {response.status_code}")
            result['simulation_error'] = f"http_{response.status_code}"
            
    except requests.exceptions.Timeout:
        print(f"   ⚠ Timeout (>180s)")
        result['simulation_error'] = 'timeout'
    except Exception as e:
        print(f"   ✗ Error: {e}")
        result['simulation_error'] = str(e)
    
    # Summary
    print("\n" + "-"*80)
    print("SUMMARY:")
    
    detected = False
    detection_methods = []
    
    if result.get('is_honeypot'):
        detected = True
        detection_methods.append("GoPlus API")
    
    if result.get('simulation', {}).get('is_honeypot'):
        detected = True
        detection_methods.append("Runtime Simulation")
    
    if result.get('contract_findings_count', 0) > 0:
        detected = True
        detection_methods.append(f"Source Code ({result['contract_findings_count']} patterns)")
    
    if detected:
        print(f"✓ DETECTED as HONEYPOT via: {', '.join(detection_methods)}")
        result['detection_result'] = 'DETECTED'
    else:
        print(f"✗ NOT DETECTED (False Negative)")
        result['detection_result'] = 'MISSED'
    
    print("-"*80)
    
    return result


def main():
    """Run tests on all honeypot addresses."""
    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                  WEB3 RISK GUARD - HONEYPOT DETECTION TEST                  ║
║                                                                              ║
║  Testing {len(HONEYPOTS)} known honeypot addresses                                        ║
║  Source: Etherscan + Academic Research                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Check backend is running
    try:
        requests.get(f"{BASE_URL}/", timeout=5)
    except:
        print("❌ ERROR: Backend not running on localhost:5000")
        print("   Run: python backend/api.py")
        return
    
    results = []
    start_time = time.time()
    
    for i, honeypot in enumerate(HONEYPOTS, 1):
        print(f"\n\n[{i}/{len(HONEYPOTS)}] Processing {honeypot['name']}...")
        result = test_address(honeypot)
        results.append(result)
        
        # Rate limiting (don't spam APIs)
        if i < len(HONEYPOTS):
            print("\nWaiting 3 seconds before next test...")
            time.sleep(3)
    
    # Final Statistics
    elapsed = time.time() - start_time
    detected = sum(1 for r in results if r.get('detection_result') == 'DETECTED')
    missed = sum(1 for r in results if r.get('detection_result') == 'MISSED')
    
    print(f"\n\n{'='*80}")
    print("FINAL RESULTS")
    print('='*80)
    print(f"Total Tested: {len(results)}")
    print(f"Detected: {detected} ({detected/len(results)*100:.1f}%)")
    print(f"Missed: {missed} ({missed/len(results)*100:.1f}%)")
    print(f"Time Elapsed: {elapsed:.1f}s")
    print('='*80)
    
    # Detection breakdown by method
    goplus_detections = sum(1 for r in results if r.get('is_honeypot'))
    simulation_detections = sum(1 for r in results if r.get('simulation', {}).get('is_honeypot'))
    source_detections = sum(1 for r in results if r.get('contract_findings_count', 0) > 0)
    
    print("\nDetection Method Breakdown:")
    print(f"  GoPlus API: {goplus_detections}/{len(results)} ({goplus_detections/len(results)*100:.1f}%)")
    print(f"  Runtime Simulation: {simulation_detections}/{len(results)} ({simulation_detections/len(results)*100:.1f}%)")
    print(f"  Source Code Analysis: {source_detections}/{len(results)} ({source_detections/len(results)*100:.1f}%)")
    
    # Save detailed results
    output_file = f'honeypot_test_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    with open(output_file, 'w') as f:
        json.dump({
            'test_date': datetime.now().isoformat(),
            'total_tested': len(results),
            'detected': detected,
            'missed': missed,
            'detection_rate': detected/len(results)*100,
            'results': results
        }, f, indent=2)
    
    print(f"\n✓ Detailed results saved to: {output_file}")
    
    # Show missed honeypots
    if missed > 0:
        print(f"\n⚠ MISSED HONEYPOTS ({missed}):")
        for r in results:
            if r.get('detection_result') == 'MISSED':
                print(f"  - {r['name']} ({r['address']})")


if __name__ == "__main__":
    main()
