#!/usr/bin/env python3
"""
vt_lookup.py — Query VirusTotal API v3 for IOC reputation
Requires a free VirusTotal API key from https://www.virustotal.com/

Usage:
    python3 vt_lookup.py --domain evil.com
    python3 vt_lookup.py --ip 185.143.223.45
    python3 vt_lookup.py --hash a1b2c3...
    python3 vt_lookup.py --iocs samples/urgent_invoice_iocs.json
"""

import sys
import json
import time
import argparse
import requests


class VirusTotalLookup:
    def __init__(self, api_key):
        self.api_key  = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers  = {"x-apikey": api_key}
        self.results  = {}

    def _get(self, endpoint):
        """Generic GET request to VirusTotal API"""
        try:
            resp = requests.get(
                f"{self.base_url}/{endpoint}",
                headers=self.headers,
                timeout=15
            )
            if resp.status_code == 200:
                data  = resp.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious':  stats.get('malicious',  0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless':   stats.get('harmless',   0),
                    'undetected': stats.get('undetected', 0),
                    'status': 'found'
                }
            elif resp.status_code == 404:
                return {'status': 'not_found', 'malicious': 0}
            elif resp.status_code == 429:
                return {'status': 'rate_limited', 'malicious': 0}
            else:
                return {'status': f'http_{resp.status_code}', 'malicious': 0}
        except Exception as e:
            return {'status': f'error: {e}', 'malicious': 0}

    def check_ip(self, ip):
        """Check IP address reputation"""
        print(f"  [*] Checking IP: {ip}")
        result = self._get(f"ip_addresses/{ip}")
        self._print_result('ip', ip, result)
        self.results[f"ip:{ip}"] = result
        time.sleep(1)
        return result

    def check_domain(self, domain):
        """Check domain reputation"""
        print(f"  [*] Checking domain: {domain}")
        result = self._get(f"domains/{domain}")
        self._print_result('domain', domain, result)
        self.results[f"domain:{domain}"] = result
        time.sleep(1)
        return result

    def check_hash(self, file_hash):
        """Check file hash reputation"""
        print(f"  [*] Checking hash: {file_hash[:16]}...")
        result = self._get(f"files/{file_hash}")
        self._print_result('hash', file_hash[:20] + '...', result)
        self.results[f"hash:{file_hash}"] = result
        time.sleep(1)
        return result

    def check_url(self, url):
        """Submit URL for analysis and retrieve results"""
        print(f"  [*] Submitting URL: {url[:60]}")
        try:
            resp = requests.post(
                f"{self.base_url}/urls",
                headers=self.headers,
                data={'url': url},
                timeout=15
            )
            if resp.status_code == 200:
                analysis_id = resp.json().get('data', {}).get('id', '')
                print(f"  [*] Waiting 15s for analysis...")
                time.sleep(15)

                resp2 = requests.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=15
                )
                if resp2.status_code == 200:
                    stats = resp2.json().get('data', {}).get('attributes', {}).get('stats', {})
                    result = {
                        'malicious':  stats.get('malicious',  0),
                        'suspicious': stats.get('suspicious', 0),
                        'harmless':   stats.get('harmless',   0),
                        'undetected': stats.get('undetected', 0),
                        'status': 'found'
                    }
                    self._print_result('url', url[:50], result)
                    self.results[f"url:{url[:50]}"] = result
                    return result
        except Exception as e:
            result = {'status': f'error: {e}', 'malicious': 0}
            self.results[f"url:{url[:50]}"] = result
            return result

        return {'status': 'error', 'malicious': 0}

    def _print_result(self, ioc_type, value, result):
        """Print a colored result line"""
        mal = result.get('malicious', 0)
        sus = result.get('suspicious', 0)
        status = result.get('status', '')

        if status == 'not_found':
            flag = "[ ? ]"
            detail = "Not in VT database yet"
        elif status == 'rate_limited':
            flag = "[ - ]"
            detail = "Rate limited — wait 60s and retry"
        elif mal > 0:
            flag = "[!!!]"
            detail = f"MALICIOUS — {mal} engines flagged"
        elif sus > 0:
            flag = "[ ! ]"
            detail = f"Suspicious — {sus} engines flagged"
        else:
            flag = "[ ✓ ]"
            detail = "Clean (0 detections)"

        print(f"    {flag} {ioc_type.upper()}: {str(value)[:60]}")
        print(f"         {detail}")
        if 'malicious' in result and result.get('status') == 'found':
            total = result['malicious'] + result['suspicious'] + result['harmless'] + result['undetected']
            print(f"         {result['malicious']}/{total} engines flagged as malicious")

    def run_from_ioc_file(self, iocs_file, limit=5):
        """Run checks on all IOCs from a JSON file"""
        with open(iocs_file) as f:
            iocs = json.load(f)

        print(f"\n{'═'*60}")
        print("  VIRUSTOTAL INTELLIGENCE LOOKUP")
        print(f"{'═'*60}")

        if iocs.get('ips'):
            print(f"\n[IPs — {len(iocs['ips'])} found]")
            for ip in iocs['ips'][:limit]:
                self.check_ip(ip)

        if iocs.get('domains'):
            print(f"\n[Domains — {len(iocs['domains'])} found]")
            for domain in iocs['domains'][:limit]:
                self.check_domain(domain)

        if iocs.get('urls'):
            print(f"\n[URLs — checking up to 3]")
            for url in iocs['urls'][:3]:
                self.check_url(url)

        print(f"\n{'═'*60}")
        return self.results


def main():
    parser = argparse.ArgumentParser(
        description='VirusTotal IOC Lookup',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 vt_lookup.py --domain amaz0n-secure.net
  python3 vt_lookup.py --ip 185.143.223.45
  python3 vt_lookup.py --hash a1b2c3d4e5f6...
  python3 vt_lookup.py --iocs samples/urgent_invoice_iocs.json
        """
    )
    parser.add_argument('--domain',  help='Domain to check')
    parser.add_argument('--ip',      help='IP address to check')
    parser.add_argument('--hash',    help='File hash (SHA256/MD5) to check')
    parser.add_argument('--url',     help='URL to submit and check')
    parser.add_argument('--iocs',    help='Path to IOC JSON file (from ioc_parser.py)')
    parser.add_argument('--api-key', help='VirusTotal API key (or set VT_API_KEY env var)')
    parser.add_argument('--output',  help='Save results to JSON file')
    args = parser.parse_args()

    # Get API key
    import os
    api_key = args.api_key or os.environ.get('VT_API_KEY', '')
    if not api_key:
        print("[!] No API key provided.")
        print("    Set VT_API_KEY environment variable or use --api-key flag")
        print("    Get a free key at: https://www.virustotal.com/gui/join-us")
        sys.exit(1)

    vt = VirusTotalLookup(api_key)

    if args.domain:
        vt.check_domain(args.domain)
    elif args.ip:
        vt.check_ip(args.ip)
    elif args.hash:
        vt.check_hash(args.hash)
    elif args.url:
        vt.check_url(args.url)
    elif args.iocs:
        vt.run_from_ioc_file(args.iocs)
    else:
        parser.print_help()
        sys.exit(1)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(vt.results, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == '__main__':
    main()
