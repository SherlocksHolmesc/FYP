# LECTURER DEMONSTRATION SCRIPT
# Focused on ACTIVE, VERIFIABLE examples with detailed explanations

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " WEB3 RISK GUARD - LECTURER DEMONSTRATION" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

Write-Host "This demonstration shows the system's multi-layered detection:" -ForegroundColor White
Write-Host "  - Multi-DEX simulation (6 exchanges)" -ForegroundColor Gray
Write-Host "  - Uniswap V2 and V3 support" -ForegroundColor Gray
Write-Host "  - Runtime behavior analysis" -ForegroundColor Gray
Write-Host "  - External API validation (GoPlus)" -ForegroundColor Gray
Write-Host "  - Pattern-based heuristics`n" -ForegroundColor Gray

# CONFIRMED ACTIVE HONEYPOTS
$confirmedHoneypots = @(
    @{
        name = "MommyMilkers"
        addr = "0x45dac6c8776e5eb1548d3cdcf0c5f6959e410c3a"
        type = "Classic Honeypot - Sell Restriction"
        why  = "Allows buying but prevents selling through hidden code restrictions"
    },
    @{
        name = "Babyama"
        addr = "0x8b9773e03e987bed942d1f9695fe6895395ca386"
        type = "GoPlus Flagged Scam"
        why  = "Flagged by external security API as known malicious contract"
    }
)

# LEGITIMATE TOKENS FOR COMPARISON
$legitimateTokens = @(
    @{
        name = "0x0 AI"
        addr = "0x5a3e6a77ba2f983ec0d371ea3b475f8bc0811ad5"
        type = "Whitelisted Safe Token"
        why  = "Pre-verified legitimate project, automatically trusted"
    },
    @{
        name = "COCORO"
        addr = "0xa93d86Af16fe83F064E3C0e2F3d129F7B7b002b0"
        type = "Tradeable V2 Token"
        why  = "Successfully completes buy/sell simulation on Uniswap V2"
    },
    @{
        name = "HELLBOY"
        addr = "0x2C9a54039d029D9c91D47B5AEc39D35b46850346"
        type = "Uniswap V3 Token"
        why  = "Demonstrates V3 support with multi-fee-tier detection"
    }
)

# PAUSED/RESTRICTED TOKENS (edge cases)
$edgeCases = @(
    @{
        name = "Smart MFG (Frozen)"
        addr = "0x6982508145454Ce325dDbE47a25d4ec3d2311933"
        type = "Trading Paused - NOT a honeypot"
        why  = "Contract frozen by owner (legitimate use case)"
    }
)

$stats = @{
    honeypots_detected = 0
    honeypots_total    = $confirmedHoneypots.Count
    safe_correct       = 0
    safe_total         = $legitimateTokens.Count
    edge_correct       = 0
    edge_total         = $edgeCases.Count
}

# TEST 1: MALICIOUS TOKENS
Write-Host "`n=== PART 1: DETECTING MALICIOUS CONTRACTS ===" -ForegroundColor Red
Write-Host "Testing known active honeypots...`n" -ForegroundColor Red

foreach ($token in $confirmedHoneypots) {
    $index = $confirmedHoneypots.IndexOf($token) + 1
    
    Write-Host "[$index/$($confirmedHoneypots.Count)] TESTING: $($token.name)" -ForegroundColor Yellow
    Write-Host "  Type: $($token.type)" -ForegroundColor DarkYellow
    Write-Host "  Address: $($token.addr)" -ForegroundColor Gray
    Write-Host "  Why malicious: $($token.why)" -ForegroundColor DarkGray
    Write-Host "`n  Running simulation..." -ForegroundColor Cyan
    
    try {
        $result = Invoke-RestMethod "http://localhost:5000/simulate/$($token.addr)" -TimeoutSec 120
        
        Write-Host "  Detection: " -NoNewline
        if ($result.is_honeypot) {
            Write-Host "HONEYPOT DETECTED" -ForegroundColor Black -BackgroundColor Red
            Write-Host "  Confidence: $($result.confidence)%" -ForegroundColor Cyan
            Write-Host "  Method: $($result.pattern)" -ForegroundColor Magenta
            Write-Host "  Reason: $($result.reason)" -ForegroundColor DarkCyan
            Write-Host "  Result: SUCCESS - Correctly identified threat`n" -ForegroundColor Green
            $stats.honeypots_detected++
        }
        else {
            Write-Host "SAFE (INCORRECT)" -ForegroundColor Yellow
            Write-Host "  Pattern: $($result.pattern)" -ForegroundColor Gray
            Write-Host "  Result: MISSED - False negative`n" -ForegroundColor Red
        }
        
    }
    catch {
        Write-Host "  ERROR: $_`n" -ForegroundColor Red
    }
    
    Start-Sleep -Seconds 1
}

# TEST 2: LEGITIMATE TOKENS
Write-Host "`n=== PART 2: VALIDATING SAFE TOKENS ===" -ForegroundColor Green
Write-Host "Ensuring no false positives on legitimate projects...`n" -ForegroundColor Green

foreach ($token in $legitimateTokens) {
    $index = $legitimateTokens.IndexOf($token) + 1
    
    Write-Host "[$index/$($legitimateTokens.Count)] TESTING: $($token.name)" -ForegroundColor Yellow
    Write-Host "  Type: $($token.type)" -ForegroundColor DarkGreen
    Write-Host "  Address: $($token.addr)" -ForegroundColor Gray
    Write-Host "  Expected: $($token.why)" -ForegroundColor DarkGray
    Write-Host "`n  Running simulation..." -ForegroundColor Cyan
    
    try {
        $result = Invoke-RestMethod "http://localhost:5000/simulate/$($token.addr)" -TimeoutSec 120
        
        Write-Host "  Detection: " -NoNewline
        if (-not $result.is_honeypot) {
            Write-Host "SAFE" -ForegroundColor Black -BackgroundColor Green
            Write-Host "  Confidence: $($result.confidence)%" -ForegroundColor Cyan
            Write-Host "  Pattern: $($result.pattern)" -ForegroundColor Magenta
            Write-Host "  DEXes Checked: $($result.dexes_checked -join ', ')" -ForegroundColor DarkCyan
            Write-Host "  Result: SUCCESS - No false positive`n" -ForegroundColor Green
            $stats.safe_correct++
        }
        else {
            Write-Host "HONEYPOT (INCORRECT)" -ForegroundColor Red
            Write-Host "  Result: FALSE POSITIVE`n" -ForegroundColor Red
        }
        
    }
    catch {
        Write-Host "  ERROR: $_`n" -ForegroundColor Red
    }
    
    Start-Sleep -Seconds 1
}

# TEST 3: EDGE CASES
Write-Host "`n=== PART 3: HANDLING EDGE CASES ===" -ForegroundColor Magenta
Write-Host "Testing system's ability to distinguish paused tokens from honeypots...`n" -ForegroundColor Magenta

foreach ($token in $edgeCases) {
    $index = $edgeCases.IndexOf($token) + 1
    
    Write-Host "[$index/$($edgeCases.Count)] TESTING: $($token.name)" -ForegroundColor Yellow
    Write-Host "  Type: $($token.type)" -ForegroundColor DarkMagenta
    Write-Host "  Address: $($token.addr)" -ForegroundColor Gray
    Write-Host "  Expected: $($token.why)" -ForegroundColor DarkGray
    Write-Host "`n  Running simulation..." -ForegroundColor Cyan
    
    try {
        $result = Invoke-RestMethod "http://localhost:5000/simulate/$($token.addr)" -TimeoutSec 120
        
        Write-Host "  Detection: " -NoNewline
        if (-not $result.is_honeypot) {
            Write-Host "SAFE" -ForegroundColor Black -BackgroundColor Green
            Write-Host "  Confidence: $($result.confidence)%" -ForegroundColor Cyan
            Write-Host "  Pattern: $($result.pattern)" -ForegroundColor Magenta
            Write-Host "  Result: SUCCESS - Correctly distinguished from honeypot`n" -ForegroundColor Green
            $stats.edge_correct++
        }
        else {
            Write-Host "HONEYPOT (INCORRECT)" -ForegroundColor Red
            Write-Host "  Result: MISCLASSIFIED`n" -ForegroundColor Red
        }
        
    }
    catch {
        Write-Host "  ERROR: $_`n" -ForegroundColor Red
    }
    
    Start-Sleep -Seconds 1
}

# FINAL REPORT
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " DEMONSTRATION SUMMARY FOR EVALUATION" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

Write-Host "1. THREAT DETECTION CAPABILITY" -ForegroundColor Red
Write-Host "   Confirmed Honeypots: $($stats.honeypots_detected)/$($stats.honeypots_total) detected" -ForegroundColor White
$hp_rate = if ($stats.honeypots_total -gt 0) { [math]::Round(($stats.honeypots_detected / $stats.honeypots_total) * 100, 2) } else { 0 }
Write-Host "   Detection Rate: $hp_rate%" -ForegroundColor $(if ($hp_rate -ge 80) { 'Green' }elseif ($hp_rate -ge 50) { 'Yellow' }else { 'Red' })
Write-Host ""

Write-Host "2. FALSE POSITIVE PREVENTION" -ForegroundColor Green
Write-Host "   Legitimate Tokens: $($stats.safe_correct)/$($stats.safe_total) correctly marked safe" -ForegroundColor White
$safe_rate = if ($stats.safe_total -gt 0) { [math]::Round(($stats.safe_correct / $stats.safe_total) * 100, 2) } else { 0 }
Write-Host "   Accuracy: $safe_rate%" -ForegroundColor $(if ($safe_rate -ge 90) { 'Green' }elseif ($safe_rate -ge 70) { 'Yellow' }else { 'Red' })
Write-Host ""

Write-Host "3. EDGE CASE HANDLING" -ForegroundColor Magenta
Write-Host "   Complex Cases: $($stats.edge_correct)/$($stats.edge_total) correctly classified" -ForegroundColor White
$edge_rate = if ($stats.edge_total -gt 0) { [math]::Round(($stats.edge_correct / $stats.edge_total) * 100, 2) } else { 0 }
Write-Host "   Accuracy: $edge_rate%" -ForegroundColor $(if ($edge_rate -ge 80) { 'Green' }elseif ($edge_rate -ge 50) { 'Yellow' }else { 'Red' })
Write-Host ""

$total_tests = $stats.honeypots_total + $stats.safe_total + $stats.edge_total
$total_correct = $stats.honeypots_detected + $stats.safe_correct + $stats.edge_correct
$overall_accuracy = if ($total_tests -gt 0) { [math]::Round(($total_correct / $total_tests) * 100, 2) } else { 0 }

Write-Host "OVERALL SYSTEM PERFORMANCE" -ForegroundColor Cyan
Write-Host "   Total Tests: $total_tests" -ForegroundColor White
Write-Host "   Correct Classifications: $total_correct" -ForegroundColor White
Write-Host "   Overall Accuracy: $overall_accuracy%" -ForegroundColor Yellow
Write-Host ""

if ($overall_accuracy -ge 85) {
    Write-Host "   EVALUATION: EXCELLENT" -ForegroundColor Green -BackgroundColor Black
    Write-Host "   System demonstrates strong real-world applicability" -ForegroundColor Green
}
elseif ($overall_accuracy -ge 70) {
    Write-Host "   EVALUATION: GOOD" -ForegroundColor Yellow
    Write-Host "   System performs well with documented limitations" -ForegroundColor Yellow
}
elseif ($overall_accuracy -ge 50) {
    Write-Host "   EVALUATION: ACCEPTABLE" -ForegroundColor DarkYellow
    Write-Host "   System shows promise with room for improvement" -ForegroundColor DarkYellow
}
else {
    Write-Host "   EVALUATION: DEVELOPING" -ForegroundColor Red
    Write-Host "   System demonstrates concept with current dataset limitations" -ForegroundColor Red
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " KEY TECHNICAL ACHIEVEMENTS" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

Write-Host "  Multi-DEX Support:" -ForegroundColor White
Write-Host "    - 6 DEXes (Uniswap V2/V3, Sushiswap, Shibaswap, Fraxswap, Defiswap)" -ForegroundColor Gray
Write-Host ""
Write-Host "  Detection Methods:" -ForegroundColor White
Write-Host "    - Runtime buy/sell simulation" -ForegroundColor Gray
Write-Host "    - External API validation (GoPlus)" -ForegroundColor Gray
Write-Host "    - Pattern-based heuristics" -ForegroundColor Gray
Write-Host "    - Smart contract source analysis" -ForegroundColor Gray
Write-Host ""
Write-Host "  V3 Innovation:" -ForegroundColor White
Write-Host "    - Multi-fee-tier support (0.05%, 0.3%, 1%)" -ForegroundColor Gray
Write-Host "    - Proper V3 router ABI integration" -ForegroundColor Gray
Write-Host ""
Write-Host "  Edge Case Handling:" -ForegroundColor White
Write-Host "    - Distinguishes paused tokens from honeypots" -ForegroundColor Gray
Write-Host "    - Handles frozen contracts correctly" -ForegroundColor Gray
Write-Host "    - Whitelist for known safe tokens" -ForegroundColor Gray

Write-Host "`n============================================`n" -ForegroundColor Cyan
