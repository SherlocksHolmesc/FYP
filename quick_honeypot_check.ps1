# Quick check of known honeypots
$addresses = @(
    @{name="Babyama (GoPlus cross-ref test)"; addr="0x8b9773e03e987bed942d1f9695fe6895395ca386"},
    @{name="MommyMilkers"; addr="0x45dac6c8776e5eb1548d3cdcf0c5f6959e410c3a"},
    @{name="Compromised 2"; addr="0x80e4f014c98320eab524ae16b0aaf1603f4dc01d"}
)

Write-Host "`n╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       QUICK HONEYPOT DETECTION CHECK                    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

foreach ($item in $addresses) {
    Write-Host "`n[$($item.name)]" -ForegroundColor Yellow
    Write-Host "Address: $($item.addr)" -ForegroundColor Gray
    
    try {
        $response = Invoke-RestMethod "http://localhost:5000/simulate/$($item.addr)" -TimeoutSec 120
        
        $status = if ($response.is_honeypot) { "[DETECTED]" } else { "[MISSED]" }
        $color = if ($response.is_honeypot) { "Green" } else { "Red" }
        
        Write-Host "  $status " -ForegroundColor $color -NoNewline
        Write-Host "(" -NoNewline
        Write-Host $response.confidence -NoNewline
        Write-Host "% confidence)" -ForegroundColor Gray
        Write-Host "  Pattern: $($response.pattern)" -ForegroundColor Gray
        Write-Host "  Reason: $($response.reason)" -ForegroundColor Gray
        
        if ($response.buy_test) {
            $buyStatus = if ($response.buy_test.success) { "PASS" } else { "FAIL" }
            Write-Host "  Buy Test: $buyStatus" -ForegroundColor Gray
        }
        
        if ($response.sell_test) {
            $sellStatus = if ($response.sell_test.success) { "PASS" } else { "FAIL" }
            Write-Host "  Sell Test: $sellStatus" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "  ERROR: $_" -ForegroundColor Red
    }
    
    Start-Sleep -Seconds 2
}

Write-Host "`n[Test complete!]`n" -ForegroundColor Cyan
