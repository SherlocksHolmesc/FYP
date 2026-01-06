# Test Code Analyzer Enhancements
Write-Host "`nTesting Code Analyzer with Context-Aware Scoring" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

# Test 1: Without simulation context
Write-Host "`nTest 1: Analyzing example.com (NO simulation context)" -ForegroundColor Yellow
Write-Host "-" * 60
$result1 = Invoke-RestMethod "http://localhost:5000/analyze-browser?url=https://example.com" -TimeoutSec 60
Write-Host "Risk Level: $($result1.risk_level)" -ForegroundColor $(if($result1.risk_level -eq 'CLEAN'){'Green'}else{'Red'})
Write-Host "Scripts Analyzed: $($result1.scripts_analyzed)"
Write-Host "Total Findings: $($result1.summary.total_findings)"
Write-Host "  Critical: $($result1.summary.critical)"
Write-Host "  High: $($result1.summary.high)"
Write-Host "  Medium: $($result1.summary.medium)"

# Test 2: With simulation context (safe)
Write-Host "`nTest 2: Analyzing example.com (WITH safe simulation)" -ForegroundColor Yellow
Write-Host "-" * 60
$result2 = Invoke-RestMethod "http://localhost:5000/analyze-browser?url=https://example.com&simulation_is_safe=true&simulation_confidence=95" -TimeoutSec 60
Write-Host "Risk Level: $($result2.risk_level)" -ForegroundColor $(if($result2.risk_level -eq 'CLEAN'){'Green'}else{'Red'})
Write-Host "Scripts Analyzed: $($result2.scripts_analyzed)"
Write-Host "Total Findings: $($result2.summary.total_findings)"
Write-Host "  Critical: $($result2.summary.critical)"
Write-Host "  High: $($result2.summary.high)"
Write-Host "  Medium: $($result2.summary.medium)"
if($result2.simulation_context) {
    Write-Host "Simulation Context: $($result2.simulation_context)" -ForegroundColor Cyan
}
if($result2.note) {
    Write-Host "Note: $($result2.note)" -ForegroundColor Green
}

# Show the difference
Write-Host "`nComparison:" -ForegroundColor Magenta
Write-Host "  WITHOUT simulation: $($result1.summary.total_findings) findings"
Write-Host "  WITH simulation:    $($result2.summary.total_findings) findings"
Write-Host "  Reduction:          $($result1.summary.total_findings - $result2.summary.total_findings) findings filtered"

# Test 3: Show actual finding details
if($result1.findings.Count -gt 0) {
    Write-Host "`nSample Finding (from Test 1):" -ForegroundColor Yellow
    $finding = $result1.findings[0]
    Write-Host "  Pattern: $($finding.pattern)"
    Write-Host "  Category: $($finding.category)"
    Write-Host "  Severity: $($finding.severity)"
    Write-Host "  Description: $($finding.description)"
    Write-Host "  Source: $($finding.source)"
    Write-Host "  Line: $($finding.line_number)"
}

Write-Host "`nTest completed!" -ForegroundColor Green
