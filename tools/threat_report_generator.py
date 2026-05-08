#!/usr/bin/env python3
"""
— Generate professional phishing analysis reports
Maps findings to MITRE ATT&CK framework
SELF-CONTAINED — no external imports needed
"""

import sys
import os
import re
import json
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse, unquote
from datetime import datetime

# ====== EMAIL HEADER ANALYZER (built-in) ======
class EmailHeaderAnalyzer:
    def __init__(self, eml_path):
        self.eml_path = eml_path
        self.msg = self._parse_email()
        self.results = {}
        
    def _parse_email(self):
        with open(self.eml_path, 'rb') as f:
            return BytesParser(policy=policy.default).parse(f)
    
    def extract_basic_headers(self):
        self.results['from'] = self.msg.get('From', 'N/A')
        self.results['to'] = self.msg.get('To', 'N/A')
        self.results['subject'] = self.msg.get('Subject', 'N/A')
        self.results['date'] = self.msg.get('Date', 'N/A')
        self.results['message_id'] = self.msg.get('Message-ID', 'N/A')
        print(f"[+] From: {self.results['from']}")
        print(f"[+] To: {self.results['to']}")
        print(f"[+] Subject: {self.results['subject']}")
        
    def extract_received_chain(self):
        received_headers = self.msg.get_all('Received', [])
        chain = []
        for header in received_headers:
            ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', header)
            ip = ip_match.group(0) if ip_match else 'Unknown'
            host_match = re.search(r'from\s+([^\s]+)', header, re.IGNORECASE)
            host = host_match.group(1) if host_match else 'Unknown'
            chain.append({'host': host, 'ip': ip, 'raw': header[:200]})
        self.results['received_chain'] = chain
        print(f"[+] Received chain ({len(chain)} hops):")
        for hop in chain:
            print(f"    └─ {hop['host']} ({hop['ip']})")
        
    def check_authentication(self):
        auth_results = self.msg.get('Authentication-Results', 'N/A')
        self.results['authentication'] = auth_results
        if 'spf=pass' in auth_results.lower():
            print("[+] SPF: PASS")
        elif 'spf=fail' in auth_results.lower():
            print("[!] SPF: FAIL (Spoofing indicator)")
        else:
            print("[-] SPF: Not present")
        if 'dkim=pass' in auth_results.lower():
            print("[+] DKIM: PASS")
        elif 'dkim=fail' in auth_results.lower():
            print("[!] DKIM: FAIL (Tampering indicator)")
        else:
            print("[-] DKIM: Not present")
        if 'dmarc=pass' in auth_results.lower():
            print("[+] DMARC: PASS")
        elif 'dmarc=fail' in auth_results.lower():
            print("[!] DMARC: FAIL (Domain spoofing)")
        else:
            print("[-] DMARC: Not present")
    
    def detect_spoofing(self):
        from_header = self.results.get('from', '')
        name_vs_email = re.search(r'"(.+?)".*<(.+?)>', from_header)
        if name_vs_email:
            display_name = name_vs_email.group(1)
            email_addr = name_vs_email.group(2)
            domain = email_addr.split('@')[-1] if '@' in email_addr else ''
            trusted_domains = ['paypal.com', 'amazon.com', 'google.com', 'microsoft.com', 'apple.com', 'netflix.com']
            for trusted in trusted_domains:
                if trusted in domain and domain != trusted:
                    print(f"[!] SPOOFING: Claims to be {trusted} but uses {domain}")
                    self.results['spoofing_detected'] = True
                    return
        print("[-] No obvious display name spoofing detected")
        self.results['spoofing_detected'] = False
    
    def run(self):
        print("\n" + "="*60)
        print(" PHISHING EMAIL HEADER ANALYSIS")
        print("="*60)
        self.extract_basic_headers()
        print("-"*60)
        self.extract_received_chain()
        print("-"*60)
        self.check_authentication()
        print("-"*60)
        self.detect_spoofing()
        print("="*60)
        return self.results


# ====== URL & IOC EXTRACTOR (built-in) ======
class PhishingURLExtractor:
    def __init__(self, eml_path):
        self.eml_path = eml_path
        self.msg = self._parse_email()
        self.urls = []
        self.iocs = {'urls': [], 'domains': [], 'ips': [], 'hashes': {}}
        
    def _parse_email(self):
        with open(self.eml_path, 'rb') as f:
            return BytesParser(policy=policy.default).parse(f)
    
    def extract_urls(self):
        html_content = ''
        text_content = ''
        
        for part in self.msg.walk():
            if part.get_content_type() == 'text/html':
                html_content = part.get_content()
            elif part.get_content_type() == 'text/plain':
                text_content = part.get_content()
        
        # Extract from HTML
        if html_content:
            href_pattern = re.compile(r'<a[^>]*href=[\'"]?(https?://[^\'">\s]+)', re.IGNORECASE)
            hrefs = href_pattern.findall(html_content)
            url_pattern = re.compile(r'https?://[^\s<>\'"]+')
            all_urls = url_pattern.findall(html_content)
            
            for url in set(all_urls + hrefs):
                decoded_url = unquote(url)
                self.urls.append({
                    'raw_url': url,
                    'decoded': decoded_url,
                    'domain': urlparse(decoded_url).netloc,
                    'path': urlparse(decoded_url).path,
                    'suspicious': self._is_suspicious(decoded_url)
                })
        
        # Extract from plaintext
        if text_content:
            url_pattern = re.compile(r'https?://[^\s<>\'"]+')
            for url in url_pattern.findall(text_content):
                decoded_url = unquote(url)
                self.urls.append({
                    'raw_url': url,
                    'decoded': decoded_url,
                    'domain': urlparse(decoded_url).netloc,
                    'path': urlparse(decoded_url).path,
                    'suspicious': self._is_suspicious(decoded_url)
                })
    
    def _is_suspicious(self, url):
        indicators = []
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
        if any(s in domain for s in shorteners):
            indicators.append('URL_SHORTENER')
        
        ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        if ip_pattern.match(domain.split(':')[0]):
            indicators.append('IP_ADDRESS_USED')
        
        if domain.count('.') > 3:
            indicators.append('EXCESSIVE_SUBDOMAINS')
        
        phishing_terms = ['login', 'verify', 'update', 'confirm', 'account', 'secure',
                         'signin', 'password', 'credential', 'bank', 'payment']
        for term in phishing_terms:
            if term in domain or term in parsed.path.lower():
                indicators.append(f'PHISHING_KEYWORD: "{term}"')
                break
        
        # Homograph check
        known_domains = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'facebook', 'instagram']
        for known in known_domains:
            if known not in domain:
                # Check if it's a homograph (e.g., amaz0n instead of amazon)
                normalized = domain
                for char in normalized:
                    if char.isdigit() and char in '0123456789':
                        for kd in known_domains:
                            if kd not in normalized:
                                test_domain = normalized.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('4', 'a').replace('5', 's')
                                if kd in test_domain and kd not in normalized:
                                    indicators.append(f'HOMOGRAPH_ATTACK (looks like "{kd}")')
                                    break
                        break
                break
        
        return indicators
    
    def extract_iocs(self):
        for url_info in self.urls:
            parsed = urlparse(url_info['decoded'])
            domain = parsed.netloc
            self.iocs['urls'].append(url_info['decoded'])
            self.iocs['domains'].append(domain)
            ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', domain)
            if ip_match:
                self.iocs['ips'].append(ip_match.group(0))
        
        # Also get IPs from received chain (from header analyzer output would be passed separately)
        
        self.iocs['domains'] = list(set(self.iocs['domains']))
        self.iocs['ips'] = list(set(self.iocs['ips']))
        self.iocs['urls'] = list(set(self.iocs['urls']))
        
        # Compute email hashes
        import hashlib
        with open(self.eml_path, 'rb') as f:
            data = f.read()
            self.iocs['hashes']['md5'] = hashlib.md5(data).hexdigest()
            self.iocs['hashes']['sha1'] = hashlib.sha1(data).hexdigest()
            self.iocs['hashes']['sha256'] = hashlib.sha256(data).hexdigest()
    
    def run(self):
        print("\n" + "="*60)
        print(" URL & IOC EXTRACTION")
        print("="*60)
        self.extract_urls()
        self.extract_iocs()
        
        print(f"\n[+] Total unique URLs found: {len(self.iocs['urls'])}")
        print(f"[+] Unique domains: {len(self.iocs['domains'])}")
        print(f"[+] IPs found: {len(self.iocs['ips'])}")
        print(f"[+] Email hash (SHA256): {self.iocs['hashes']['sha256'][:16]}...")
        
        print("\n--- Suspicious URLs ---")
        suspicious_found = False
        for url_info in self.urls:
            if url_info['suspicious']:
                suspicious_found = True
                print(f"[!] {url_info['decoded'][:80]}")
                for ind in url_info['suspicious']:
                    print(f"    └─ {ind}")
        
        if not suspicious_found:
            print("    No suspicious indicators found.")
        
        print("="*60)
        return self.iocs


# ====== THREAT REPORT GENERATOR ======
class ThreatReportGenerator:
    def __init__(self, eml_path):
        self.eml_path = eml_path
        self.header_results = {}
        self.ioc_results = {}
        self.report = {}
        
    def analyze(self):
        print("[*] Analyzing email headers...")
        header_analyzer = EmailHeaderAnalyzer(self.eml_path)
        self.header_results = header_analyzer.run()
        
        print("\n[*] Extracting URLs and IOCs...")
        url_extractor = PhishingURLExtractor(self.eml_path)
        self.ioc_results = url_extractor.run()
    
    def map_mitre_techniques(self):
        techniques = []
        
        # T1566.001 — Spearphishing Attachment
        techniques.append({
            'id': 'T1566.001',
            'name': 'Spearphishing Attachment',
            'description': 'Adversary sent a phishing email with malicious content',
            'detected': len(self.ioc_results.get('urls', [])) > 0
        })
        
        # T1566.002 — Spearphishing Link
        if len(self.ioc_results.get('urls', [])) > 0:
            techniques.append({
                'id': 'T1566.002',
                'name': 'Spearphishing Link',
                'description': f'Email contains {len(self.ioc_results["urls"])} embedded URLs'
            })
        
        # Spoofing check
        auth = self.header_results.get('authentication', '')
        if 'fail' in auth.lower():
            techniques.append({
                'id': 'T1566.003',
                'name': 'Spearphishing via Service (Email Spoofing)',
                'description': 'Email authentication failure detected (SPF/DKIM/DMARC)'
            })
        
        self.report['mitre_techniques'] = techniques
    
    def calculate_risk_score(self):
        score = 0
        reasons = []
        
        auth = self.header_results.get('authentication', '')
        if 'spf=fail' in auth.lower():
            score += 25
            reasons.append('SPF authentication failed (+25)')
        if 'dkim=fail' in auth.lower():
            score += 20
            reasons.append('DKIM authentication failed (+20)')
        if 'dmarc=fail' in auth.lower():
            score += 20
            reasons.append('DMARC authentication failed (+20)')
        
        url_count = len(self.ioc_results.get('urls', []))
        if url_count > 0:
            score += min(url_count * 10, 30)
            reasons.append(f'{url_count} URLs found (+{min(url_count * 10, 30)})')
        
        if self.header_results.get('spoofing_detected', False):
            score += 20
            reasons.append('Display name spoofing detected (+20)')
        
        score = min(score, 100)
        
        self.report['risk_score'] = {
            'score': score,
            'severity': 'CRITICAL' if score >= 75 else 'HIGH' if score >= 50 else 'MEDIUM' if score >= 25 else 'LOW',
            'reasons': reasons
        }
    
    def generate_report(self):
        self.analyze()
        self.map_mitre_techniques()
        self.calculate_risk_score()
        
        self.report['metadata'] = {
            'analysis_date': datetime.now().isoformat(),
            'sample_file': self.eml_path,
            'analyzer_version': '1.0.0'
        }
        
        self.report['summary'] = {
            'sender': self.header_results.get('from', 'N/A'),
            'recipient': self.header_results.get('to', 'N/A'),
            'subject': self.header_results.get('subject', 'N/A'),
            'date': self.header_results.get('date', 'N/A'),
            'total_urls': len(self.ioc_results.get('urls', [])),
            'domains_found': len(self.ioc_results.get('domains', [])),
            'ips_found': len(self.ioc_results.get('ips', [])),
            'file_hash': self.ioc_results.get('hashes', {}).get('sha256', 'N/A')
        }
        
        self.report['iocs'] = self.ioc_results
        
        return self.report
    
    def save_report(self, output_path=None):
        if not output_path:
            basename = os.path.basename(self.eml_path).replace('.eml', '_threat_report.json')
            output_path = os.path.join(os.path.dirname(self.eml_path) or '.', basename)
        
        with open(output_path, 'w') as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n[+] Threat report saved to {output_path}")
        return output_path


# ====== MAIN ======
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <email.eml>")
        print(f"Example: {sys.argv[0]} samples/urgent_invoice.eml")
        sys.exit(1)
    
    eml_path = sys.argv[1]
    
    if not os.path.exists(eml_path):
        print(f"[!] File not found: {eml_path}")
        sys.exit(1)
    
    generator = ThreatReportGenerator(eml_path)
    report = generator.generate_report()
    
    # Print summary
    print("\n" + "="*60)
    print(" THREAT REPORT SUMMARY")
    print("="*60)
    print(f"Subject: {report['summary']['subject']}")
    print(f"From: {report['summary']['sender']}")
    print(f"Risk Score: {report['risk_score']['score']}/100 ({report['risk_score']['severity']})")
    print(f"URLs Found: {report['summary']['total_urls']}")
    print(f"MITRE Techniques: {len(report['mitre_techniques'])} mapped")
    
    # Print MITRE techniques
    print("\n--- MITRE ATT&CK Techniques ---")
    for tech in report['mitre_techniques']:
        print(f"  [{tech['id']}] {tech['name']}")
        print(f"       {tech['description']}")
    
    # Save report
    generator.save_report()
