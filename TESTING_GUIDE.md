# Testing the Code Analyzer - Quick Guide

## ✅ System Status

- Backend API: Running on http://localhost:5000
- React Frontend: Running on http://localhost:5173
- Code Analyzer: Enhanced with Context-Aware Scoring + Pattern Learning

## 🧪 How to Test

### Using the Web Interface (http://localhost:5173)

1. **Navigate to the Scanner**

   - Click on "Scanner" in the navigation menu
   - You'll see the website security scanner interface

2. **Test a Legitimate Site**

   ```
   Enter URL: https://app.uniswap.org
   Click "Check Website"
   ```

   **What to observe:**

   - dApp Runtime Simulation runs FIRST (will show safe/malicious)
   - ML Model Analysis shows risk factors
   - **Source Code Analysis** shows filtered results
   - If simulation says SAFE → only CRITICAL/HIGH findings shown
   - Trusted domains get special treatment

3. **Test a Simple Site**

   ```
   Enter URL: https://example.com
   ```

   **What to observe:**

   - Should show CLEAN or very few findings
   - Context-aware filtering in action

4. **Check the Source Code Section**
   Look for:
   - **Pattern Combinations** - new feature showing suspicious combos
   - **Severity badges** (CRITICAL, HIGH, MEDIUM)
   - **Actual code snippets** with line numbers
   - **Context** (3 lines before/after the suspicious code)

## 🔍 What Was Enhanced

### Before Enhancement

- Legitimate sites like Uniswap flagged as HIGH risk
- Single `approve()` function triggered alerts
- No context awareness
- Many false positives

### After Enhancement

- ✅ **Context-Aware Scoring**
  - Checks if domain is trusted (TRUSTED_DEFI_DOMAINS list)
  - Integrates dApp simulation results
  - Filters findings based on simulation safety
- ✅ **Behavioral Pattern Learning**
  - Requires MULTIPLE suspicious patterns
  - Detects pattern combinations:
    - `approve()` + `obfuscation` + `external_call` = CRITICAL
    - `permit` + `obfuscation` = HIGH
    - Single `approve()` on trusted site = skipped
- ✅ **Maintained Educational Value**
  - Still shows actual code with line numbers
  - Still displays context (surrounding code)
  - Now also explains WHY patterns are suspicious

## 📊 Expected Results

### Legitimate DeFi Site (e.g., Uniswap)

```
dApp Simulation: ✅ SAFE (99% confidence)
ML Analysis: Risk factors identified
Source Code: CLEAN or minimal findings (filtered)
```

### Malicious Site (e.g., phishing)

```
dApp Simulation: ⚠️ MALICIOUS (99% confidence)
ML Analysis: Multiple risk factors
Source Code: CRITICAL - Pattern combinations detected
```

## 🎯 Key Features to Notice

1. **Integration Flow**

   - dApp simulation → ML analysis → Code analysis
   - Each layer feeds into the next
   - Simulation results influence code filtering

2. **Pattern Combinations Display**

   - Look for "PATTERN COMBINATION" in findings
   - Shows which patterns were detected together
   - Explains why the combination is suspicious

3. **Context Notes**
   - "Trusted domain verified safe by runtime simulation"
   - "Filtered by simulation (safe 99% confidence)"
   - "X suspicious pattern combination(s) detected"

## 🐛 Troubleshooting

If you don't see findings filtered:

- Check that dApp simulation completed successfully
- Verify the website has actual JavaScript code
- Some sites (like example.com) have minimal code

If you see encoding errors in PowerShell:

- Use the web interface instead (http://localhost:5173)
- The web UI handles all display correctly

## 📝 Testing Checklist

- [ ] Open http://localhost:5173
- [ ] Navigate to Scanner
- [ ] Test Uniswap: https://app.uniswap.org
- [ ] Observe dApp simulation runs first
- [ ] Check source code analysis shows filtered results
- [ ] Look for pattern combination detections
- [ ] Verify code snippets have line numbers
- [ ] Test another site: https://example.com
- [ ] Compare findings between different sites

## 🎉 Success Indicators

You'll know it's working when you see:

1. Legitimate sites show CLEAN or minimal findings
2. dApp simulation results influence code analysis
3. Pattern combinations detected (not just single functions)
4. Actual code displayed with line numbers and context
5. Notes explaining why decisions were made

Enjoy testing your enhanced code analyzer! 🚀
