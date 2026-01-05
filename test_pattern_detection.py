"""
Test pattern detection with mock malicious Solidity code
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from api import analyze_solidity_code

# Mock malicious Solidity contract with multiple red flags
malicious_contract = """
pragma solidity ^0.8.0;

contract MaliciousToken {
    string public name = "Fake Token";
    string public symbol = "SCAM";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000 * 10**18;
    
    address private _owner;
    address private _admin;
    mapping(address => uint256) private _balances;
    mapping(address => bool) private _blacklisted;
    bool public tradingEnabled = false;
    uint256 public maxSellPercent = 1;
    
    modifier onlyOwner() {
        require(msg.sender == _owner, "Not owner");
        _;
    }
    
    constructor() {
        _owner = msg.sender;
        _balances[_owner] = totalSupply;
    }
    
    // MALICIOUS: Owner can set anyone's balance
    function setBalance(address account, uint256 amount) external onlyOwner {
        _balances[account] = amount;
    }
    
    // MALICIOUS: Owner can blacklist addresses
    function blacklist(address account) external onlyOwner {
        _blacklisted[account] = true;
    }
    
    // MALICIOUS: Transfer restrictions (honeypot pattern)
    function transfer(address to, uint256 amount) external returns (bool) {
        require(tradingEnabled || msg.sender == _owner, "Trading not enabled");
        require(!_blacklisted[msg.sender], "Blacklisted");
        require(amount <= _balances[msg.sender] * maxSellPercent / 100, "Exceeds max sell");
        
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        return true;
    }
    
    // MALICIOUS: Owner can enable/disable trading
    function setTradingEnabled(bool enabled) external onlyOwner {
        tradingEnabled = enabled;
    }
    
    // MALICIOUS: Rug pull function
    function emergencyWithdraw() external onlyOwner {
        payable(_owner).transfer(address(this).balance);
    }
}
"""

print("=" * 80)
print("TESTING PATTERN DETECTION ON MALICIOUS CONTRACT")
print("=" * 80)

print("\nAnalyzing mock malicious contract...")
findings = analyze_solidity_code(malicious_contract, "MaliciousToken")

print(f"\nTotal Findings: {len(findings)}")

if findings:
    print("\n" + "=" * 80)
    print("DETECTED MALICIOUS PATTERNS:")
    print("=" * 80)
    
    for i, finding in enumerate(findings, 1):
        print(f"\n{i}. [{finding['severity'].upper()}] {finding['category']}")
        print(f"   Description: {finding['description']}")
        print(f"   Line {finding['line_number']}")
        print(f"   Code: {finding['matched_code'][:120]}")
        if len(finding['context']) > 0:
            print(f"   Context: {finding['context'][:200]}")
    
    # Count by severity
    critical = sum(1 for f in findings if f['severity'] == 'critical')
    high = sum(1 for f in findings if f['severity'] == 'high')
    medium = sum(1 for f in findings if f['severity'] == 'medium')
    low = sum(1 for f in findings if f['severity'] == 'low')
    
    print("\n" + "=" * 80)
    print("SUMMARY:")
    print("=" * 80)
    print(f"  Critical: {critical}")
    print(f"  High: {high}")
    print(f"  Medium: {medium}")
    print(f"  Low: {low}")
    print(f"  TOTAL: {len(findings)}")
    
    if critical > 0 or high > 0:
        print(f"\n🚨 VERDICT: DANGEROUS CONTRACT - DO NOT INTERACT!")
    elif medium > 0:
        print(f"\n⚠️  VERDICT: SUSPICIOUS - Exercise caution")
    else:
        print(f"\n✓ VERDICT: No critical issues detected")
else:
    print("\n✗ No patterns detected (this would be a bug - the contract is clearly malicious!)")

print("\n" + "=" * 80)
