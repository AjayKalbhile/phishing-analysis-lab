#!/usr/bin/env python3
"""
header_analyzer.py — Analyze email headers for phishing indicators
Extracts SPF, DKIM, DMARC, authentication results, and routing info

Usage:
    python3 header_analyzer.py <email.eml>
    python3 header_analyzer.py samples/urgent_invoice.eml
"""

import sys
import re
import json
import argparse
from email import policy
from email.parser import BytesParser
from datetime import datetime


class EmailHeaderAnalyzer:
    def __init__(self, eml_path):
        self.eml_path = eml_path
        self.msg = self._parse_email()
        self.results = {}

    def _parse_email(self):
        with open(self.eml_path, 'rb') as f:
            return BytesParser(policy=policy.default).parse(f)

    def extract_basic_headers(self):
        """Extract fundamental email headers"""
        self.results['from']       = str(self.msg.get('From', 'N/A'))
        self.results['to']         = str(self.msg.get('To', 'N/A'))
        self.results['subject']    = str(self.msg.get('Subject', 'N/A'))
        self.results['date']       = str(self.msg.get('Date', 'N/A'))
        self.results['message_id'] = str(self.msg.get('Message-ID', 'N/A'))
        self.results['reply_to']   = str(self.msg.get('Reply-To', 'N/A'))
        self.results['return_path']= str(self.msg.get('Return-Path', 'N/A'))

        print(f"[+] From:        {self.results['from']}")
        print(f"[+] To:          {self.results['to']}")
        print(f"[+] Subject:     {self.results['subject']}")
        print(f"[+] Date:        {self.results['date']}")
        print(f"[+] Reply-To:    {self.results['reply_to']}")
        print(f"[+] Return-Path: {self.results['return_path']}")

    def extract_received_chain(self):
        """Analyze the Received chain to trace email routing"""
        received_headers = self.msg.get_all('Received', [])
        chain = []

        for header in received_headers:
            header_str = str(header)
            ip_match   = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', header_str)
            host_match = re.search(r'from\s+(\S+)', header_str, re.IGNORECASE)
            by_match   = re.search(r'by\s+(\S+)', header_str, re.IGNORECASE)

            chain.append({
                'host': host_match.group(1) if host_match else 'Unknown',
                'by':   by_match.group(1)   if by_match   else 'Unknown',
                'ip':   ip_match.group(0)   if ip_match   else 'Unknown',
                'raw':  header_str[:200]
            })

        self.results['received_chain'] = chain
        print(f"\n[+] Received chain ({len(chain)} hops):")
        for i, hop in enumerate(reversed(chain), 1):
            print(f"    Hop {i}: {hop['host']} ({hop['ip']}) → {hop['by']}")

        if chain:
            # The last Received header (first in list) = originating server
            originating = chain[-1]
            print(f"\n[!] Originating IP: {originating['ip']} from {originating['host']}")
            self.results['originating_ip'] = originating['ip']

    def check_authentication(self):
        """Check SPF, DKIM, DMARC authentication results"""
        auth_results = str(self.msg.get('Authentication-Results', 'N/A'))
        received_spf = str(self.msg.get('Received-SPF', 'N/A'))
        self.results['authentication'] = auth_results
        self.results['received_spf']   = received_spf

        auth_lower = auth_results.lower()

        # SPF
        if 'spf=pass' in auth_lower:
            print("[+] SPF:   PASS")
            self.results['spf'] = 'pass'
        elif 'spf=fail' in auth_lower:
            print("[!] SPF:   FAIL  ← Spoofing indicator")
            self.results['spf'] = 'fail'
        elif 'spf=softfail' in auth_lower:
            print("[~] SPF:   SOFTFAIL  ← Suspicious")
            self.results['spf'] = 'softfail'
        else:
            print("[-] SPF:   Not present or neutral")
            self.results['spf'] = 'none'

        # DKIM
        if 'dkim=pass' in auth_lower:
            print("[+] DKIM:  PASS")
            self.results['dkim'] = 'pass'
        elif 'dkim=fail' in auth_lower:
            print("[!] DKIM:  FAIL  ← Tampering/spoofing indicator")
            self.results['dkim'] = 'fail'
        else:
            print("[-] DKIM:  Not present")
            self.results['dkim'] = 'none'

        # DMARC
        if 'dmarc=pass' in auth_lower:
            print("[+] DMARC: PASS")
            self.results['dmarc'] = 'pass'
        elif 'dmarc=fail' in auth_lower:
            print("[!] DMARC: FAIL  ← Domain spoofing confirmed")
            self.results['dmarc'] = 'fail'
        else:
            print("[-] DMARC: Not present")
            self.results['dmarc'] = 'none'

    def detect_spoofing(self):
        """Check for display name deception and domain mismatch"""
        from_header  = self.results.get('from', '')
        return_path  = self.results.get('return_path', '')

        self.results['spoofing_detected'] = False

        # Extract From domain
        from_match = re.search(r'@([\w.\-]+)', from_header)
        rp_match   = re.search(r'@([\w.\-]+)', return_path)

        if from_match and rp_match:
            from_dom = from_match.group(1).lower()
            rp_dom   = rp_match.group(1).lower()
            if from_dom != rp_dom:
                print(f"[!] DOMAIN MISMATCH: From={from_dom} | Return-Path={rp_dom}")
                self.results['spoofing_detected'] = True
            else:
                print(f"[-] Domain match: {from_dom} ← OK")

        # Display name deception
        name_email = re.search(r'"(.+?)"\s*<(.+?)>', from_header)
        if name_email:
            display_name = name_email.group(1)
            email_addr   = name_email.group(2)
            domain       = email_addr.split('@')[-1].lower() if '@' in email_addr else ''

            trusted_domains = [
                'paypal.com', 'amazon.com', 'google.com', 'microsoft.com',
                'apple.com', 'netflix.com', 'facebook.com', 'linkedin.com'
            ]
            for trusted in trusted_domains:
                brand = trusted.split('.')[0]
                if brand.lower() in display_name.lower() and domain != trusted:
                    print(f"[!] DISPLAY NAME SPOOF: Claims '{display_name}' but domain is '{domain}'")
                    self.results['spoofing_detected'] = True
                    self.results['impersonated_brand'] = trusted
                    return

        print("[-] No display name spoofing detected")

    def check_homograph(self):
        """Check for homograph domain attacks (e.g., amaz0n instead of amazon)"""
        from_header = self.results.get('from', '')
        domain_match = re.search(r'@([\w.\-]+)', from_header)
        if not domain_match:
            return

        domain = domain_match.group(1).lower()
        brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple',
                  'netflix', 'facebook', 'instagram', 'linkedin', 'outlook']

        # Normalize domain by replacing common substitutions
        normalized = domain.replace('0','o').replace('1','l').replace('3','e').replace('4','a')

        for brand in brands:
            if brand not in domain and brand in normalized:
                print(f"[!] HOMOGRAPH ATTACK: '{domain}' looks like '{brand}.com'")
                self.results['homograph_detected'] = True
                self.results['homograph_brand'] = brand
                return

        self.results['homograph_detected'] = False

    def run(self):
        """Run full header analysis"""
        print("\n" + "═"*60)
        print("  PHISHING EMAIL HEADER ANALYSIS")
        print("  File: " + self.eml_path)
        print("═"*60)

        print("\n[BASIC HEADERS]")
        self.extract_basic_headers()

        print("\n[DELIVERY PATH / HOP TRACE]")
        self.extract_received_chain()

        print("\n[AUTHENTICATION RESULTS]")
        self.check_authentication()

        print("\n[SPOOFING DETECTION]")
        self.detect_spoofing()

        print("\n[HOMOGRAPH DETECTION]")
        self.check_homograph()

        # Final verdict
        fails = sum(1 for k in ['spf','dkim','dmarc'] if self.results.get(k) in ('fail','softfail','none'))
        spoof = self.results.get('spoofing_detected', False)
        homog = self.results.get('homograph_detected', False)

        print("\n" + "═"*60)
        if fails >= 2 or spoof or homog:
            print("  [!] VERDICT: HIGH RISK — Multiple phishing indicators detected")
        elif fails == 1:
            print("  [~] VERDICT: MEDIUM RISK — Authentication failure detected")
        else:
            print("  [✓] VERDICT: LOW RISK — No major indicators")
        print("═"*60 + "\n")

        return self.results


def main():
    parser = argparse.ArgumentParser(
        description='Phishing Email Header Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 header_analyzer.py samples/urgent_invoice.eml
  python3 header_analyzer.py --email samples/urgent_invoice.eml --output results.json
        """
    )
    parser.add_argument('email', nargs='?', help='Path to .eml file')
    parser.add_argument('--email', dest='email_flag', help='Path to .eml file (alternative)')
    parser.add_argument('--output', help='Save JSON results to this path')
    args = parser.parse_args()

    eml_path = args.email or args.email_flag
    if not eml_path:
        parser.print_help()
        sys.exit(1)

    analyzer = EmailHeaderAnalyzer(eml_path)
    results  = analyzer.run()

    output_path = args.output or eml_path.replace('.eml', '_analysis.json')
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[+] Results saved to {output_path}")


if __name__ == '__main__':
    main()
