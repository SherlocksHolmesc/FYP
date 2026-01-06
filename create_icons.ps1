# Quick script to create placeholder shield icons for Web3 Risk Guard
# You can replace these with proper icons later

Write-Host "Creating placeholder extension icons..." -ForegroundColor Cyan

# Create a simple SVG shield icon
$svgContent = @"
<svg width="128" height="128" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#22c55e;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#06b6d4;stop-opacity:1" />
    </linearGradient>
  </defs>
  <rect width="128" height="128" fill="#0a0b14" rx="24"/>
  <path d="M 64 20 L 90 35 L 90 65 Q 90 95 64 108 Q 38 95 38 65 L 38 35 Z" 
        fill="url(#grad)" stroke="#ffffff" stroke-width="2"/>
  <text x="64" y="75" font-family="Arial" font-size="48" font-weight="bold" 
        fill="#0a0b14" text-anchor="middle">W3</text>
</svg>
"@

# Save SVG to temp file
$svgPath = "$env:TEMP\w3rg_icon.svg"
$svgContent | Out-File -FilePath $svgPath -Encoding UTF8

Write-Host "`nSVG icon created at: $svgPath" -ForegroundColor Green
Write-Host "`nTo create PNG icons, you have 3 options:" -ForegroundColor Yellow
Write-Host ""
Write-Host "Option 1 (Easiest): Use an online converter" -ForegroundColor Cyan
Write-Host "  1. Visit: https://svgtopng.com or https://cloudconvert.com/svg-to-png"
Write-Host "  2. Upload: $svgPath"
Write-Host "  3. Download as:"
Write-Host "     - icon16.png (16x16)"
Write-Host "     - icon48.png (48x48)"
Write-Host "     - icon128.png (128x128)"
Write-Host "  4. Save all 3 files to: $PWD"
Write-Host ""
Write-Host "Option 2: Use Inkscape (if installed)" -ForegroundColor Cyan
Write-Host "  inkscape -w 128 -h 128 $svgPath -o icon128.png"
Write-Host "  inkscape -w 48 -h 48 $svgPath -o icon48.png"
Write-Host "  inkscape -w 16 -h 16 $svgPath -o icon16.png"
Write-Host ""
Write-Host "Option 3: Download ready-made shield icon" -ForegroundColor Cyan
Write-Host "  Visit: https://www.flaticon.com/search?word=shield%20security"
Write-Host "  Download PNG in 3 sizes (16, 48, 128)"
Write-Host ""
Write-Host "After creating icons, reload the extension in chrome://extensions" -ForegroundColor Green
