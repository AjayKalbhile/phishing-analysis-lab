#!/usr/bin/env python3
"""
ioc_parser.py — Parse Indicators of Compromise (IOCs) from phishing emails
Extracts IPs, domains, URLs, file hashes, and email addresses

Usage:
    python3 ioc_parser.py <email.eml>
    python3 ioc_parser.py samples/urgent_invoice.eml
    python3 ioc_parser.py samples/urgent_invoice.eml --format json
    python3 ioc_parser.py samples/urgent_invoice.eml --format csv
"""

import sys
import os
import re
import json
import hashlib
import argparse
from urllib.parse import urlparse


class IOCParser:
    def __init__(self):
        self.iocs = {
            'ips':             [],
            'domains':         [],
            'urls':            [],
            'email_addresses': [],
            'hashes':          []
        }

    def parse_text(self, text):
        """Extract all IOCs from raw text"""
        # IPs — exclude private/loopback ranges
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        all_ips = ip_pattern.findall(text)
        self.iocs['ips'] = list(set([
            ip for ip in all_ips
            if all(0 <= int(o) <= 255 for o in ip.split('.'))
            and not ip.startswith(('10.', '127.', '192.168.', '172.'))
        ]))

        # URLs
        url_pattern = re.compile(r'h(?:xx|tt)ps?://[^\s<>"\']+')
        raw_urls = url_pattern.findall(text)
        # Also catch defanged hxxp
        clean_urls = [u.replace('hxxp', 'http').replace('hxxps', 'https') for u in raw_urls]
        self.iocs['urls'] = list(set(clean_urls))

        # Domains from URLs
        domain_pattern = re.compile(r'h(?:xx|tt)ps?://([^\s/?:#<>"\']+)')
        raw_domains = domain_pattern.findall(text)
        self.iocs['domains'] = list(set([
            d.replace('hxxp://', '').replace('http://', '').lstrip('www.')
            for d in raw_domains
        ]))

        # Email addresses
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
        self.iocs['email_addresses'] = list(set(email_pattern.findall(text)))

        return self.iocs

    def parse_file(self, filepath):
        """Parse IOCs from a file and compute its hash"""
        with open(filepath, 'rb') as f:
            content = f.read()
            text_content = content.decode('utf-8', errors='ignore')

            self.iocs['hashes'].append({
                'filename': os.path.basename(filepath),
                'sha256':   hashlib.sha256(content).hexdigest(),
                'md5':      hashlib.md5(content).hexdigest(),
                'sha1':     hashlib.sha1(content).hexdigest(),
                'size_bytes': len(content)
            })

            return self.parse_text(text_content)

    def to_json(self):
        """Return IOCs as formatted JSON string"""
        return json.dumps(self.iocs, indent=2)

    def to_csv(self):
        """Return IOCs as CSV string"""
        lines = ["type,value"]
        for ip    in self.iocs['ips']:             lines.append(f"ipv4,{ip}")
        for domain in self.iocs['domains']:         lines.append(f"domain,{domain}")
        for url   in self.iocs['urls']:             lines.append(f"url,{url}")
        for email in self.iocs['email_addresses']:  lines.append(f"email,{email}")
        for h     in self.iocs['hashes']:           lines.append(f"sha256,{h['sha256']}")
        return '\n'.join(lines)

    def generate_report(self):
        """Print a formatted summary to stdout"""
        lines = []
        lines.append("=" * 60)
        lines.append(" IOC EXTRACTION REPORT")
        lines.append("=" * 60)

        sections = [
            ('IP Addresses',    'ips'),
            ('Domains',         'domains'),
            ('URLs',            'urls'),
            ('Email Addresses', 'email_addresses'),
        ]
        for label, key in sections:
            items = self.iocs[key]
            lines.append(f"\n[+] {label} ({len(items)}):")
            for item in items:
                lines.append(f"    └─ {item[:100]}")
            if not items:
                lines.append("    (none found)")

        if self.iocs['hashes']:
            lines.append(f"\n[+] File Hashes ({len(self.iocs['hashes'])}):")
            for h in self.iocs['hashes']:
                lines.append(f"    └─ {h['filename']} ({h['size_bytes']} bytes)")
                lines.append(f"       SHA256: {h['sha256']}")
                lines.append(f"       MD5:    {h['md5']}")

        return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Phishing IOC Parser',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ioc_parser.py samples/urgent_invoice.eml
  python3 ioc_parser.py samples/urgent_invoice.eml --format json
  python3 ioc_parser.py samples/urgent_invoice.eml --format csv --output iocs.csv
        """
    )
    parser.add_argument('input',   help='Path to .eml file or text string')
    parser.add_argument('--format', choices=['summary', 'json', 'csv'], default='summary')
    parser.add_argument('--output', help='Save output to file')
    args = parser.parse_args()

    p = IOCParser()

    if os.path.isfile(args.input):
        p.parse_file(args.input)
    else:
        p.parse_text(args.input)

    if args.format == 'json':
        output = p.to_json()
    elif args.format == 'csv':
        output = p.to_csv()
    else:
        output = p.generate_report()

    print(output)

    # Auto-save JSON output alongside the input file
    if os.path.isfile(args.input) and not args.output:
        save_path = args.input.replace('.eml', '_iocs.json')
        with open(save_path, 'w') as f:
            json.dump(p.iocs, f, indent=2)
        print(f"\n[+] IOCs saved to {save_path}")
    elif args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"\n[+] Output saved to {args.output}")


if __name__ == '__main__':
    main()
