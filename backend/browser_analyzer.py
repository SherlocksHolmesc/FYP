"""
Browser-based Code Analyzer for Wallet Drainer Detection
=========================================================

Uses Playwright (real Chromium browser) to:
1. Actually load the website like a real user
2. Execute JavaScript and render the page
3. Bypass basic bot detection
4. Extract ALL JavaScript code (including dynamically loaded)

This works on sites that block simple HTTP requests!
"""

import asyncio
import re
import time
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("[WARN] Playwright not installed. Run: pip install playwright && playwright install chromium")

# Import patterns from main analyzer
from code_analyzer import DRAINER_PATTERNS, TRUSTED_DEFI_DOMAINS, is_trusted_domain

async def fetch_with_browser(url, timeout=30000):
    """
    Fetch website using a real Chromium browser.
    This bypasses most bot detection and executes JavaScript.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return {'error': 'Playwright not installed', 'url': url}
    
    if not url.startswith('http'):
        url = 'https://' + url
    
    result = {
        'url': url,
        'html': None,
        'scripts': [],
        'inline_scripts': [],
        'external_scripts': [],
        'error': None,
        'method': 'browser'
    }
    
    try:
        async with async_playwright() as p:
            # Launch browser with stealth settings
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                ]
            )
            
            # Create context with realistic settings
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                locale='en-US',
                timezone_id='America/New_York',
            )
            
            page = await context.new_page()
            
            # Collect all scripts loaded
            all_scripts = []
            
            # Intercept script responses
            async def handle_response(response):
                if 'javascript' in response.headers.get('content-type', ''):
                    try:
                        content = await response.text()
                        all_scripts.append({
                            'url': response.url,
                            'content': content[:100000],  # Limit size
                            'type': 'external'
                        })
                    except:
                        pass
            
            page.on('response', handle_response)
            
            # Navigate to page
            try:
                await page.goto(url, timeout=timeout, wait_until='networkidle')
            except Exception as e:
                # Try with just domcontentloaded if networkidle times out
                try:
                    await page.goto(url, timeout=timeout, wait_until='domcontentloaded')
                except:
                    result['error'] = f'Failed to load page: {str(e)[:100]}'
                    await browser.close()
                    return result
            
            # Wait a bit for any delayed scripts
            await asyncio.sleep(2)
            
            # Get final HTML
            result['html'] = await page.content()
            result['final_url'] = page.url
            
            # Extract inline scripts from rendered HTML
            inline_scripts = await page.evaluate('''() => {
                const scripts = document.querySelectorAll('script');
                return Array.from(scripts).map((s, i) => ({
                    index: i,
                    content: s.innerHTML || null,
                    src: s.src || null,
                    type: s.type || 'text/javascript'
                })).filter(s => s.content && s.content.length > 0);
            }''')
            
            result['inline_scripts'] = [
                {'index': s['index'], 'content': s['content'], 'length': len(s['content'])}
                for s in inline_scripts if s['content']
            ]
            
            # Add external scripts we intercepted
            result['external_scripts'] = [
                {'src': s['url'], 'content': s['content'], 'length': len(s['content'])}
                for s in all_scripts
            ]
            
            await browser.close()
            return result
            
    except Exception as e:
        result['error'] = str(e)[:200]
        return result


def analyze_code_for_drainers(code, source_name='inline', is_trusted=False):
    """
    Analyze JavaScript code for drainer patterns.
    """
    if not code:
        return []
    
    findings = []
    lines = code.split('\n')
    
    for pattern_name, pattern_info in DRAINER_PATTERNS.items():
        # Skip legitimate patterns on trusted domains
        if is_trusted and pattern_info.get('legit_use', False):
            continue
        
        # On trusted domains, only report critical issues
        if is_trusted and pattern_info['severity'] not in ['critical', 'high']:
            continue
            
        try:
            regex = re.compile(pattern_info['pattern'], re.IGNORECASE | re.MULTILINE)
            
            for match in regex.finditer(code):
                line_start = code[:match.start()].count('\n') + 1
                
                # Get context
                start_line = max(0, line_start - 3)
                end_line = min(len(lines), line_start + 3)
                
                context_lines = []
                for i in range(start_line, end_line):
                    if i < len(lines):
                        prefix = '>>> ' if i == line_start - 1 else '    '
                        context_lines.append(f"{prefix}{i+1:4d} | {lines[i][:200]}")
                
                matched_text = match.group(0)[:200]
                
                finding = {
                    'pattern': pattern_name,
                    'category': pattern_info['category'],
                    'severity': pattern_info['severity'],
                    'description': pattern_info['description'],
                    'line_number': line_start,
                    'matched_code': matched_text,
                    'context': '\n'.join(context_lines),
                    'source': source_name,
                    'legit_use': pattern_info.get('legit_use', False)
                }
                
                is_duplicate = any(
                    f['pattern'] == pattern_name and f['line_number'] == line_start 
                    for f in findings
                )
                if not is_duplicate:
                    findings.append(finding)
                    
        except re.error:
            continue
    
    return findings


async def analyze_website_browser(url, simulation_result=None):
    """
    Main function to analyze a website using browser rendering.
    
    Args:
        url: Website URL to analyze
        simulation_result: Optional dApp simulation result for context-aware scoring
    """
    print(f"[BROWSER ANALYZER] Loading: {url}")
    
    trusted = is_trusted_domain(url)
    if trusted:
        print(f"[BROWSER ANALYZER] Trusted domain - reducing false positives")
    
    # Context-Aware: Check simulation result FIRST
    simulation_is_safe = False
    if simulation_result:
        is_malicious = simulation_result.get('is_malicious', False)
        confidence = simulation_result.get('confidence', 0)
        simulation_is_safe = (not is_malicious) and (confidence >= 85)
    
    result = {
        'url': url,
        'analyzed_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'success',
        'method': 'browser',
        'is_trusted_domain': trusted,
        'findings': [],
        'summary': {
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        },
        'scripts_analyzed': 0,
        'error': None
    }
    
    # Context-Aware: If both trusted AND simulation says safe, skip detailed analysis
    if trusted and simulation_is_safe:
        result['risk_level'] = 'CLEAN'
        result['note'] = 'Trusted domain verified safe by runtime simulation - skipping code analysis'
        print(f"[BROWSER ANALYZER] Skipping analysis - trusted domain + safe simulation")
        return result
    
    # Fetch with browser
    website_data = await fetch_with_browser(url)
    
    if website_data.get('error'):
        result['status'] = 'error'
        result['error'] = website_data['error']
        return result
    
    all_findings = []
    
    # Analyze inline scripts
    for script in website_data.get('inline_scripts', []):
        if script.get('content'):
            findings = analyze_code_for_drainers(
                script['content'], 
                f"inline_script_{script.get('index', 0)}",
                is_trusted=trusted
            )
            all_findings.extend(findings)
            result['scripts_analyzed'] += 1
    
    # Analyze external scripts
    for script in website_data.get('external_scripts', []):
        if script.get('content'):
            findings = analyze_code_for_drainers(
                script['content'],
                script.get('src', 'external')[:100],
                is_trusted=trusted
            )
            all_findings.extend(findings)
            result['scripts_analyzed'] += 1
    
    # Analyze HTML
    if website_data.get('html'):
        html_findings = analyze_code_for_drainers(
            website_data['html'],
            'html_document',
            is_trusted=False
        )
        html_findings = [f for f in html_findings if f['severity'] == 'critical']
        all_findings.extend(html_findings)
    
    # BEHAVIORAL PATTERN LEARNING: Import and use the function from code_analyzer
    from code_analyzer import detect_pattern_combinations
    combination_findings = detect_pattern_combinations(all_findings)
    all_findings.extend(combination_findings)
    result['pattern_combinations'] = len(combination_findings)
    
    # Context-Aware Filtering: Check simulation result
    simulation_is_safe = False
    if simulation_result:
        is_malicious = simulation_result.get('is_malicious', False)
        confidence = simulation_result.get('confidence', 0)
        simulation_is_safe = (not is_malicious) and (confidence >= 85)
        
        if simulation_is_safe:
            print(f"[BROWSER ANALYZER] Simulation marked SAFE ({confidence}% confidence) - filtering to critical/high only")
            # Only keep critical and high severity findings
            all_findings = [f for f in all_findings if f['severity'] in ['critical', 'high']]
            result['simulation_context'] = f'Filtered by simulation (safe {confidence}% confidence)'
    
    # Sort by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    all_findings.sort(key=lambda x: severity_order.get(x['severity'], 5))
    
    result['findings'] = all_findings[:30]
    
    # Summary
    for finding in all_findings:
        sev = finding['severity']
        if sev in result['summary']:
            result['summary'][sev] += 1
    result['summary']['total_findings'] = len(all_findings)
    
    # Risk level with context awareness
    if trusted and simulation_is_safe:
        result['risk_level'] = 'CLEAN'
        result['note'] = 'Trusted domain verified safe by runtime simulation'
    elif trusted:
        result['risk_level'] = 'CRITICAL' if result['summary']['critical'] > 0 else 'CLEAN'
        if result['risk_level'] == 'CLEAN':
            result['note'] = 'Trusted domain - normal DeFi patterns not flagged'
    elif simulation_is_safe:
        # Simulation says safe, downgrade risk
        if result['summary']['critical'] > 0:
            result['risk_level'] = 'HIGH'  # Downgrade from CRITICAL
            result['note'] = 'Simulation marked safe but code patterns detected - manual review suggested'
        else:
            result['risk_level'] = 'CLEAN'
            result['note'] = 'Verified safe by runtime simulation'
    else:
        if result['summary']['critical'] > 0 or len(combination_findings) > 0:
            result['risk_level'] = 'CRITICAL'
        elif result['summary']['high'] > 0:
            result['risk_level'] = 'HIGH'
        elif result['summary']['medium'] > 0:
            result['risk_level'] = 'MEDIUM'
        else:
            result['risk_level'] = 'CLEAN'
    
    if len(combination_findings) > 0:
        combo_note = f"{len(combination_findings)} suspicious pattern combination(s) detected"
        if 'note' in result:
            result['note'] += f" | {combo_note}"
        else:
            result['note'] = combo_note
    
    print(f"[BROWSER ANALYZER] Risk: {result['risk_level']} | Scripts: {result['scripts_analyzed']} | Findings: {len(all_findings)} | Combinations: {len(combination_findings)}")
    
    return result


def analyze_website_sync(url, simulation_result=None):
    """Synchronous wrapper for the async function."""
    # Use a new event loop to avoid conflicts with Flask/other async frameworks
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(analyze_website_browser(url, simulation_result))
        finally:
            loop.close()
    except RuntimeError as e:
        print(f"[BROWSER ANALYZER] Event loop error: {e}")
        # If event loop is already running, create a new one in a thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(lambda: asyncio.run(analyze_website_browser(url, simulation_result)))
            return future.result(timeout=90)
    except Exception as e:
        print(f"[BROWSER ANALYZER] Error: {e}")
        return {
            'url': url,
            'error': str(e),
            'status': 'error',
            'method': 'browser',
            'findings': [],
            'summary': {'total_findings': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'scripts_analyzed': 0,
            'risk_level': 'ERROR'
        }


# Test
if __name__ == '__main__':
    import sys
    
    test_url = sys.argv[1] if len(sys.argv) > 1 else 'https://app.uniswap.org'
    
    print(f"\n{'='*60}")
    print(f"Browser-based Analysis: {test_url}")
    print('='*60)
    
    result = analyze_website_sync(test_url)
    
    print(f"\nRisk Level: {result['risk_level']}")
    print(f"Method: {result['method']}")
    print(f"Scripts Analyzed: {result['scripts_analyzed']}")
    print(f"Total Findings: {result['summary']['total_findings']}")
    print(f"  Critical: {result['summary']['critical']}")
    print(f"  High: {result['summary']['high']}")
    
    if result.get('error'):
        print(f"\nError: {result['error']}")
    
    if result['findings']:
        print(f"\nTop Findings:")
        for f in result['findings'][:5]:
            print(f"  [{f['severity'].upper()}] {f['category']} - Line {f['line_number']}")
