import sys
sys.path.insert(0, 'd:\\University\\FYP\\backend')

import requests

# Test BELLE contract directly
address = '0x34C6211621f2763c60Eb007dC2aE91090A2d22f6'

print(f"Testing {address} (BELLE Token)\n")

# Get source from Etherscan
params = {
    'module': 'contract',
    'action': 'getsourcecode',
    'address': address,
    'apikey': 'Z9VWEZXXYKBWJQXAPF3BUC6DMS7Z8VUMGE',
    'chainid': 1
}
response = requests.get('https://api.etherscan.io/v2/api', params=params, timeout=15)
data = response.json()

if data.get('status') == '1' and data.get('result'):
    result = data['result'][0]
    source = result.get('SourceCode')
    
    print(f"Contract Name: {result.get('ContractName')}")
    print(f"Verified: {bool(source)}")
    print(f"Source Length: {len(source)} chars")
    print(f"Compiler: {result.get('CompilerVersion')}\n")
    
    # Check for patterns
    import re
    patterns_to_test = [
        (r'require\s*\(\s*_blacklisted\s*\[', 'Reverse blacklist (require _blacklisted['),
        (r'_\w+Factory\s*\([^)]*from[^)]*to', 'Suspicious hook (_xxxFactory)'),
        (r'mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*private\s*_blacklisted', 'Blacklist mapping'),
    ]
    
    print("Pattern Matches:")
    for pattern, desc in patterns_to_test:
        matches = re.findall(pattern, source)
        print(f"  {'✓' if matches else '✗'} {desc}: {len(matches)} matches")
        if matches:
            # Find line numbers
            lines = source.split('\n')
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    print(f"      Line {i}: {line.strip()[:80]}")
else:
    print(f"Error fetching source: {data}")
