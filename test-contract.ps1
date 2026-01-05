#!/usr/bin/env powershell
# Quick Test Script for Smart Contract Analysis

Write-Host "================================" -ForegroundColor Cyan
Write-Host "Smart Contract Analysis Test" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Uniswap Token (Should be clean or low findings)
Write-Host "[1/3] Testing Uniswap Token (Legitimate Contract)..." -ForegroundColor Yellow
Write-Host "Address: 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984" -ForegroundColor Gray
Write-Host ""

try {
    $result = Invoke-RestMethod "http://localhost:5000/score/0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984" -TimeoutSec 30
    
    Write-Host "✓ API Response received" -ForegroundColor Green
    Write-Host "  Score: $($result.score)" -ForegroundColor White
    Write-Host "  Prediction: $($result.prediction)" -ForegroundColor White
    
    if ($result.contract_analysis) {
        Write-Host "  Contract Analysis: $($result.contract_analysis.risk_level)" -ForegroundColor White
        Write-Host "  Has Source: $($result.contract_analysis.has_source)" -ForegroundColor White
        Write-Host "  Contract Name: $($result.contract_analysis.contract_name)" -ForegroundColor White
        Write-Host "  Findings: $($result.contract_analysis.summary.total_findings)" -ForegroundColor White
        
        if ($result.contract_analysis.findings -and $result.contract_analysis.findings.Count -gt 0) {
            Write-Host ""
            Write-Host "  Sample Finding:" -ForegroundColor Cyan
            $finding = $result.contract_analysis.findings[0]
            Write-Host "    - Category: $($finding.category)" -ForegroundColor Gray
            Write-Host "    - Severity: $($finding.severity)" -ForegroundColor Gray
            Write-Host "    - Line: $($finding.line_number)" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "  ⚠ No contract_analysis in response" -ForegroundColor Yellow
    }
    
}
catch {
    Write-Host "✗ Error: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.Message -like "*Unable to connect*") {
        Write-Host ""
        Write-Host "Make sure the backend API is running:" -ForegroundColor Yellow
        Write-Host "  cd backend" -ForegroundColor Gray
        Write-Host "  python api.py" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Test 2: Check if contract has verified source
Write-Host "[2/3] Checking Contract Source Availability..." -ForegroundColor Yellow
Write-Host ""

try {
    $debugResult = Invoke-RestMethod "http://localhost:5000/debug/0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984" -TimeoutSec 30
    Write-Host "✓ Debug endpoint working" -ForegroundColor Green
}
catch {
    Write-Host "✗ Debug endpoint failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Test 3: Open Scanner in browser
Write-Host "[3/3] How to View in Scanner UI:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Make sure the landing page is running:" -ForegroundColor White
Write-Host "   cd web" -ForegroundColor Gray
Write-Host "   npm run dev" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Open browser to: http://localhost:5173/scanner" -ForegroundColor White
Write-Host ""
Write-Host "3. Paste this address:" -ForegroundColor White
Write-Host "   0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984" -ForegroundColor Cyan
Write-Host ""
Write-Host "4. Look for 'Smart Contract Source Analysis' section" -ForegroundColor White
Write-Host "   (appears above GoPlus Risk Flags)" -ForegroundColor Gray
Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Additional test addresses
Write-Host "Other Addresses to Test:" -ForegroundColor Yellow
Write-Host ""
Write-Host "• USDT (Tether): 0xdAC17F958D2ee523a2206206994597C13D831ec7" -ForegroundColor Gray
Write-Host "• USDC (Circle): 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" -ForegroundColor Gray
Write-Host "• DAI (MakerDAO): 0x6B175474E89094C44Da98b954EedeAC495271d0F" -ForegroundColor Gray
Write-Host ""
Write-Host "Note: Only VERIFIED contracts on Etherscan will show source analysis" -ForegroundColor Yellow
Write-Host ""
