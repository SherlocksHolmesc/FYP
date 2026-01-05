# Smart Contract Source Code Analysis - Testing Guide

## Overview

The system now analyzes **actual verified Solidity source code** from Etherscan for malicious patterns.

## What's New

### ✅ Real Smart Contract Analysis

- Fetches verified contract source from Etherscan API
- Parses Solidity code for 10 malicious pattern categories
- Returns actual code snippets with line numbers
- Works for any verified contract on Ethereum mainnet

### 🔍 Detected Patterns

1. **Honeypot Transfer Block** (Critical)

   - `require(from == owner())` - Only owner can transfer
   - `if(to == uniswapV2Pair) require(...)` - Blocks selling to DEX

2. **Balance Manipulation** (Critical)

   - `function setBalance(...)` - Direct balance writes
   - `_balances[addr] = amount` - Owner can change balances

3. **Hidden Owner** (High)

   - `address private _owner` - Obfuscated ownership
   - `mapping(address => bool) private _admins` - Hidden admins

4. **Reclaim Ownership** (High)

   - `function unlock()` - Can reclaim after renouncement
   - `_previousOwner = _owner` - Stores old owner

5. **Max Sell Restriction** (High)

   - `uint maxSellPercent` - Limits sell amount
   - `require(amount <= maxSell...)` - Can't sell full balance

6. **Pausable Transfers** (Medium)

   - `bool paused` - Owner can freeze all transfers
   - `modifier whenNotPaused` - Pausable pattern

7. **Trading Disabled** (High)

   - `bool tradingEnabled = false` - Trading starts off
   - `require(tradingEnabled)` - May never be enabled

8. **High Tax** (Medium)

   - `uint sellTax = 99` - Detects tax variables
   - `taxAmount = amount * 99 / 100` - High tax calculations

9. **Blacklist Function** (Medium)

   - `mapping(address => bool) blacklist` - Can block addresses
   - `function blacklist(address)` - Blacklisting capability

10. **Proxy Pattern** (Medium)
    - `delegatecall(...)` - Upgradeable contracts
    - `address implementation` - Proxy pattern

## Testing

### Test with Known Contracts

```powershell
# Start the backend API
cd backend
python api.py

# In another terminal, test various contracts:

# 1. Legitimate DeFi Protocol (should be clean or low risk)
Invoke-RestMethod "http://localhost:5000/score/0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984" | ConvertTo-Json -Depth 10
# Uniswap token contract

# 2. Known Honeypot (should show critical findings)
Invoke-RestMethod "http://localhost:5000/score/0xYourHoneypotAddress" | ConvertTo-Json -Depth 10

# 3. Check if contract is verified
Invoke-RestMethod "http://localhost:5000/score/0xSomeAddress" | Select-Object -ExpandProperty contract_analysis
```

### Response Structure

```json
{
  "address": "0x...",
  "score": 85,
  "prediction": "FRAUD",
  "goplus_flags": ["HONEYPOT", "Cannot Sell All"],
  "is_contract": true,
  "contract_analysis": {
    "has_source": true,
    "is_verified": true,
    "contract_name": "ScamToken",
    "compiler_version": "v0.8.19+commit.7dd6d404",
    "findings": [
      {
        "pattern": "honeypot_transfer_block",
        "category": "Honeypot Pattern",
        "severity": "critical",
        "description": "Transfer function has conditional restrictions...",
        "line_number": 247,
        "matched_code": "require(from == owner())",
        "context": "243 | function _transfer(...) {\n244 |   if(to == uniswapV2Pair) {\n>>> 247 |     require(from == owner(), \"Selling blocked\");\n248 |   }\n249 | }",
        "source": "ScamToken",
        "file_type": "solidity"
      }
    ],
    "summary": {
      "total_findings": 5,
      "critical": 2,
      "high": 2,
      "medium": 1
    },
    "risk_level": "CRITICAL"
  }
}
```

## Scanner.jsx Display

The Scanner now shows **two sections** for addresses:

### 1. Smart Contract Source Analysis (New!)

- **Displays**: Actual Solidity code from verified contracts
- **Location**: Above GoPlus flags
- **Shows**: Line numbers, code context, matched patterns
- **Badge**: CRITICAL/HIGH/MEDIUM risk level

### 2. GoPlus Risk Flags (Existing)

- **Displays**: Descriptive labels from GoPlus API
- **Location**: Below contract analysis
- **Shows**: Educational Solidity examples (NOT actual contract code)
- **Note**: Added subtitle explaining these are labels, not code

## Key Differences

| Feature      | Contract Analysis               | GoPlus Flags           |
| ------------ | ------------------------------- | ---------------------- |
| Source       | Etherscan verified source       | GoPlus database        |
| Content      | Actual Solidity code            | Descriptive labels     |
| Line Numbers | Real line numbers from contract | Example code only      |
| Availability | Verified contracts only         | All addresses          |
| Priority     | Highest (actual evidence)       | High (confirmed flags) |

## Fallback Behavior

1. **Verified Contract**: Shows contract analysis + GoPlus flags
2. **Unverified Contract**: Shows only GoPlus flags
3. **EOA (Wallet)**: Shows only ML analysis + GoPlus

## Example Output

### Critical Honeypot Detection

```
Smart Contract Source Analysis: CRITICAL

Critical: 2 | High: 1 | Medium: 0

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CRITICAL | Honeypot Pattern | Line 247

🔍 Actual Contract Code (Line 247):
    244 | function _transfer(address from, address to, uint256 amount) internal {
    245 |   if (to == uniswapV2Pair) {
>>> 247 |     require(from == owner(), "Only owner can sell");
    248 |   }
    249 |   super._transfer(from, to, amount);
    250 | }

⚠️ What this means:
Transfer function has conditional restrictions that may prevent selling

🛡️ Risk Assessment:
CRITICAL: This pattern is almost always malicious. Do NOT interact with this contract.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Limitations

1. **Requires Verification**: Contract must be verified on Etherscan
2. **Etherscan API Key**: Required for source code fetching
3. **Rate Limits**: Etherscan free tier has rate limits
4. **Complex Contracts**: Proxy patterns may need manual review

## Next Steps

1. Test with known honeypot contracts
2. Verify findings match actual contract behavior
3. Add more Solidity patterns as needed
4. Consider adding bytecode analysis for unverified contracts
