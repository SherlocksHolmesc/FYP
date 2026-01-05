"""
Domain Reputation Analysis
==========================
Check domain age, WHOIS data, SSL certificate age, and hosting provider.
Scam sites typically have:
- Brand new domains (< 30 days)
- Hidden WHOIS info
- Self-signed or very new SSL certificates
- Hosted on cheap/free hosting (Cloudflare, NameCheap)
"""

import whois
import ssl
import socket
from datetime import datetime, timedelta
from urllib.parse import urlparse
import requests

def analyze_domain_reputation(url):
    """
    Analyze domain reputation indicators.
    Returns risk score 0-100 (higher = more risky)
    """
    result = {
        'domain': '',
        'risk_score': 0,
        'findings': [],
        'indicators': {
            'domain_age_days': None,
            'whois_hidden': False,
            'ssl_age_days': None,
            'is_new_domain': False,
            'registrar': None,
            'hosting_provider': None
        }
    }
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.replace('www.', '')
        result['domain'] = domain
        
        risk_points = 0
        
        # 1. WHOIS Lookup - Domain Age
        try:
            w = whois.whois(domain)
            
            # Domain age
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age = (datetime.now() - creation_date).days
                result['indicators']['domain_age_days'] = age
                
                if age < 30:
                    risk_points += 40
                    result['findings'].append({
                        'severity': 'CRITICAL',
                        'pattern': 'Very New Domain',
                        'description': f'Domain registered only {age} days ago. Scam sites use fresh domains.',
                        'evidence': f'Created: {creation_date.strftime("%Y-%m-%d")}'
                    })
                    result['indicators']['is_new_domain'] = True
                elif age < 180:
                    risk_points += 20
                    result['findings'].append({
                        'severity': 'HIGH',
                        'pattern': 'Recent Domain',
                        'description': f'Domain only {age} days old. Be cautious.',
                        'evidence': f'Created: {creation_date.strftime("%Y-%m-%d")}'
                    })
            
            # WHOIS Privacy
            if w.registrar and 'privacy' in w.registrar.lower():
                risk_points += 15
                result['indicators']['whois_hidden'] = True
                result['findings'].append({
                    'severity': 'MEDIUM',
                    'pattern': 'WHOIS Privacy Enabled',
                    'description': 'Owner information hidden. Common in scam sites.',
                    'evidence': f'Registrar: {w.registrar}'
                })
            
            result['indicators']['registrar'] = w.registrar
            
        except Exception as e:
            risk_points += 25
            result['findings'].append({
                'severity': 'HIGH',
                'pattern': 'WHOIS Lookup Failed',
                'description': 'Cannot verify domain registration. Suspicious.',
                'evidence': str(e)
            })
        
        # 2. SSL Certificate Age
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    ssl_age = (datetime.now() - not_before).days
                    result['indicators']['ssl_age_days'] = ssl_age
                    
                    if ssl_age < 7:
                        risk_points += 30
                        result['findings'].append({
                            'severity': 'CRITICAL',
                            'pattern': 'Brand New SSL Certificate',
                            'description': f'SSL certificate only {ssl_age} days old. Scam indicator.',
                            'evidence': f'Issued: {not_before.strftime("%Y-%m-%d")}'
                        })
                    elif ssl_age < 30:
                        risk_points += 15
                        result['findings'].append({
                            'severity': 'MEDIUM',
                            'pattern': 'Recent SSL Certificate',
                            'description': f'SSL certificate {ssl_age} days old.',
                            'evidence': f'Issued: {not_before.strftime("%Y-%m-%d")}'
                        })
        except Exception as e:
            print(f"[WARN] SSL check failed for {domain}: {e}")
        
        # 3. Check hosting provider (via IP lookup)
        try:
            ip = socket.gethostbyname(domain)
            # Check if using common cheap hosting
            cheap_hosting_indicators = ['cloudflare', 'namecheap', 'hostgator', 'godaddy']
            
            # Simple reverse DNS check
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                result['indicators']['hosting_provider'] = hostname
                
                if any(provider in hostname.lower() for provider in cheap_hosting_indicators):
                    risk_points += 10
                    result['findings'].append({
                        'severity': 'LOW',
                        'pattern': 'Budget Hosting Provider',
                        'description': 'Hosted on cheap/free hosting. Common in scams.',
                        'evidence': f'Host: {hostname}'
                    })
            except:
                pass
        except Exception as e:
            print(f"[WARN] Hosting check failed for {domain}: {e}")
        
        result['risk_score'] = min(100, risk_points)
        
        # Overall verdict
        if result['risk_score'] >= 60:
            result['verdict'] = 'HIGH RISK - Likely Scam'
        elif result['risk_score'] >= 40:
            result['verdict'] = 'SUSPICIOUS - Exercise Caution'
        elif result['risk_score'] >= 20:
            result['verdict'] = 'MEDIUM RISK - Verify Before Trust'
        else:
            result['verdict'] = 'LOW RISK'
        
        return result
        
    except Exception as e:
        print(f"[ERROR] Domain reputation analysis failed: {e}")
        result['error'] = str(e)
        return result


if __name__ == '__main__':
    # Test on known scam sites
    test_urls = [
        'https://www.belenkasale.com/',
        'https://uniswap.org/',
        'https://opensea.io/'
    ]
    
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"Testing: {url}")
        print('='*60)
        
        result = analyze_domain_reputation(url)
        
        print(f"\nDomain: {result['domain']}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Verdict: {result['verdict']}")
        
        if result['indicators']['domain_age_days']:
            print(f"Domain Age: {result['indicators']['domain_age_days']} days")
        if result['indicators']['ssl_age_days']:
            print(f"SSL Age: {result['indicators']['ssl_age_days']} days")
        
        print(f"\nFindings ({len(result['findings'])}):")
        for finding in result['findings']:
            print(f"  [{finding['severity']}] {finding['pattern']}")
            print(f"      {finding['description']}")
            print(f"      Evidence: {finding['evidence']}")
