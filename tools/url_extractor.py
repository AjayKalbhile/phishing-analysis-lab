#!/usr/bin/env python3
"""
url_extractor.py — Extract and analyze URLs from phishing emails
Deobfuscates, normalizes, and categorizes embedded links
"""

import sys
import re
import json
import hashlib
import requests
from urllib.parse import urlparse, unquote
from email import policy
from email.parser import BytesParser

class PhishingURLExtractor:
    def __init__(self, eml_path):
        self.eml_path = eml_path
        self.msg = self._parse_email()
        self.urls = []
        self.iocs = {'urls': [], 'domains': [], 'ips': [], 'hashes': {}}
        
    def _parse_email(self):
        with open(self.eml_path, 'rb') as f:
            return BytesParser(policy=policy.default).parse(f)
    
    def extract_urls_from_html(self):
        """Extract URLs from HTML content and <a> tags"""
        html_content = ''
        
        # Get HTML parts
        if self.msg.get_content_type() == 'text/html':
            html_content = self.msg.get_content()
        else:
            for part in self.msg.walk():
                if part.get_content_type() == 'text/html':
                    html_content = part.get_content()
                    break
        
        if not html_content:
            return
        
        # Extract href attributes
        href_pattern = re.compile(r'<a[^>]*href=[\'"]?(https?://[^\'">\s]+)', re.IGNORECASE)
        hrefs = href_pattern.findall(html_content)
        
        # Extract all http/https links
        url_pattern = re.compile(r'https?://[^\s<>\'"]+')
        all_urls = url_pattern.findall(html_content)
        
        # Check for obfuscation
        for url in set(all_urls + hrefs):
            decoded_url = unquote(url)
            display_text = self._get_link_text(html_content, url)
            
            self.urls.append({
                'raw_url': url,
                'decoded': decoded_url,
                'display_text': display_text,
                'domain': urlparse(decoded_url).netloc,
                'path': urlparse(decoded_url).path,
                'suspicious': self._is_suspicious(url, display_text)
            })
    
    def extract_urls_from_plaintext(self):
        """Extract URLs from plain text body"""
        text_content = ''
        
        if self.msg.get_content_type() == 'text/plain':
            text_content = self.msg.get_content()
        else:
            for part in self.msg.walk():
                if part.get_content_type() == 'text/plain':
                    text_content = part.get_content()
                    break
        
        if not text_content:
            return
        
        url_pattern = re.compile(r'https?://[^\s<>\'"]+')
        for url in url_pattern.findall(text_content):
            decoded_url = unquote(url)
            self.urls.append({
                'raw_url': url,
                'decoded': decoded_url,
                'display_text': 'N/A (plaintext)',
                'domain': urlparse(decoded_url).netloc,
                'path': urlparse(decoded_url).path,
                'suspicious': self._is_suspicious(url, '')
            })
    
    def _get_link_text(self, html, url):
        """Extract display text of a link"""
        pattern = re.compile(
            r'<a[^>]*href=[\'"]?' + re.escape(url) + r'[\'"]?[^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL
        )
        match = pattern.search(html)
        return match.group(1).strip() if match else url
    
    def _is_suspicious(self, url, display_text):
        """Check for common phishing obfuscation techniques"""
        indicators = []
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
        if any(s in domain for s in shorteners):
            indicators.append('URL_SHORTENER')
        
        # Check for IP address instead of domain
        ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        if ip_pattern.match(domain.split(':')[0]):
            indicators.append('IP_ADDRESS_USED')
        
        # Check for display text mismatch
        if display_text != url and display_text != 'N/A (plaintext)':
            # Extract domains
            display_domain = urlparse(display_text).netloc.lower()
            if display_domain and display_domain != domain:
                indicators.append(f'DISPLAY_TEXT_MISMATCH: "{display_domain}" vs "{domain}"')
        
        # Check for excessive subdomains
        if domain.count('.') > 3:
            indicators.append('EXCESSIVE_SUBDOMAINS')
        
        # Check for common phishing keywords
        phishing_terms = ['login', 'verify', 'update', 'confirm', 'account', 'secure', 
                         'signin', 'password', 'credential', 'bank', 'payment']
        for term in phishing_terms:
            if term in domain or term in parsed.path.lower():
                indicators.append(f'PHISHING_KEYWORD: "{term}"')
                break
        
        # Check for HTTPS but suspicious domain
        if parsed.scheme == 'https':
            # Check for homograph attacks (lookalike characters)
            if self._has_homograph_attack(domain):
                indicators.append('HOMOGRAPH_ATTACK')
        
        return indicators
    
    def _has_homograph_attack(self, domain):
        """Detect homograph attacks using lookalike characters"""
        # Common homograph replacements
        lookalikes = {
            '0': 'o', '1': 'l', 'rn': 'm', 'vv': 'w',
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
            'х': 'x', 'і': 'i', 'ј': 'j'
        }
        
        known_domains = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix']
        for known in known_domains:
            if known in domain:
                return False  # Legitimate domain
        
        # Check if it resembles a known brand
        for known in known_domains:
            if known in domain.replace('0', 'o').replace('1', 'l').replace('rn', 'm'):
                if known not in domain:
                    return True
        
        return False
    
    def extract_iocs(self):
        """Extract IOCs from the email"""
        # Process all URLs
        for url_info in self.urls:
            parsed = urlparse(url_info['decoded'])
            domain = parsed.netloc
            self.iocs['urls'].append(url_info['decoded'])
            self.iocs['domains'].append(domain)
            
            # Extract IPs from URLs
            ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', domain)
            if ip_match:
                self.iocs['ips'].append(ip_match.group(0))
        
        # Compute hashes of the raw email
        with open(self.eml_path, 'rb') as f:
            data = f.read()
            self.iocs['hashes']['md5'] = hashlib.md5(data).hexdigest()
            self.iocs['hashes']['sha1'] = hashlib.sha1(data).hexdigest()
            self.iocs['hashes']['sha256'] = hashlib.sha256(data).hexdigest()
        
        # Remove duplicates
        self.iocs['domains'] = list(set(self.iocs['domains']))
        self.iocs['ips'] = list(set(self.iocs['ips']))
        self.iocs['urls'] = list(set(self.iocs['urls']))
        
    def query_virustotal(self, api_key):
        """Query VirusTotal for URL reputation (optional)"""
        if not api_key:
            print("[-] No VirusTotal API key provided. Skipping...")
            return
        
        print("[*] Querying VirusTotal...")
        for domain in self.iocs['domains'][:5]:  # Limit to 5 queries
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": api_key}
            try:
                resp = requests.get(url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    malicious = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                    print(f"    {domain}: {malicious} malicious detections")
                    self.iocs['vt_results'] = self.iocs.get('vt_results', {})
                    self.iocs['vt_results'][domain] = malicious
            except Exception as e:
                print(f"    [!] Error querying {domain}: {e}")
    
    def run(self, vt_api_key=None):
        """Run full URL/IOC extraction"""
        print("\n" + "="*60)
        print(" URL & IOC EXTRACTION")
        print("="*60)
        
        self.extract_urls_from_html()
        self.extract_urls_from_plaintext()
        self.extract_iocs()
        
        print(f"\n[+] Total unique URLs found: {len(self.iocs['urls'])}")
        print(f"[+] Unique domains: {len(self.iocs['domains'])}")
        print(f"[+] IPs found: {len(self.iocs['ips'])}")
        print(f"[+] Email hash (SHA256): {self.iocs['hashes']['sha256'][:16]}...")
        
        print("\n--- Suspicious URLs ---")
        for url_info in self.urls:
            if url_info['suspicious']:
                print(f"[!] {url_info['decoded'][:80]}")
                for ind in url_info['suspicious']:
                    print(f"    └─ {ind}")
        
        if vt_api_key:
            self.query_virustotal(vt_api_key)
        
        return self.iocs

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <email.eml> [virustotal_api_key]")
        sys.exit(1)
    
    api_key = sys.argv[2] if len(sys.argv) > 2 else None
    extractor = PhishingURLExtractor(sys.argv[1])
    iocs = extractor.run(api_key)
    
    output_file = sys.argv[1].replace('.eml', '_iocs.json')
    with open(output_file, 'w') as f:
        json.dump(iocs, f, indent=2)
    print(f"\n[+] IOCs saved to {output_file}")
