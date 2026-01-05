import requests
import json

# Test with PEPE token
address = '0x6982508145454Ce325dDbE47a25d4ec3d2311933'

print(f'Testing improved analysis for {address}...')
response = requests.get(f'http://localhost:5000/score/{address}')
result = response.json()

if 'contract_analysis' in result:
    ca = result['contract_analysis']
    print(f'\n=== {ca.get("contract_name", "Contract")} Analysis ===')
    print(f'Risk Level: {ca.get("risk_level")}')
    print(f'Total Findings: {ca.get("summary", {}).get("total_findings", 0)}')
    
    if ca.get('findings'):
        print('\n--- Findings with Confidence Scores ---')
        for f in ca['findings']:
            conf = f.get('confidence', 'N/A')
            print(f'\n{f["severity"].upper()} - {f["category"]} (Line {f["line_number"]})')
            print(f'Confidence: {conf}%')
            print(f'Pattern: {f["pattern"]}')
            print(f'Match: {f["matched_code"][:80]}...')
else:
    print('No contract analysis available')

# Test with WBTC (should be cleaner now)
print('\n\n=================================================')
print('Testing WBTC (legitimate token)...')
wbtc_address = '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599'
response = requests.get(f'http://localhost:5000/score/{wbtc_address}')
result = response.json()

if 'contract_analysis' in result:
    ca = result['contract_analysis']
    print(f'\n=== {ca.get("contract_name", "Contract")} Analysis ===')
    print(f'Risk Level: {ca.get("risk_level")}')
    print(f'Total Findings: {ca.get("summary", {}).get("total_findings", 0)}')
    
    if ca.get('findings'):
        print('\n--- Findings with Confidence Scores ---')
        for f in ca['findings']:
            conf = f.get('confidence', 'N/A')
            print(f'\n{f["severity"].upper()} - {f["category"]} (Line {f["line_number"]})')
            print(f'Confidence: {conf}%')
            print(f'Pattern: {f["pattern"]}')
            print(f'Match: {f["matched_code"][:80]}...')
    else:
        print('✅ No suspicious patterns detected!')
else:
    print('No contract analysis available')
