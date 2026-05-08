# Methodology 03 — Indicator of Compromise (IOC) Extraction

> **Goal:** Systematically extract, categorize, enrich, and format all IOCs from a phishing email for threat intelligence sharing, blocking, and detection rule creation.

**Tools:** Python `hashlib`, `re`, STIX 2.1 format, VirusTotal API, AlienVault OTX
**Time Required:** 20–45 minutes per sample
**Output:** Structured IOC list (JSON/CSV), STIX bundle, enriched threat intel report

---

## What Are IOCs?

An **Indicator of Compromise (IOC)** is a forensic artifact that indicates a system may have been involved in a security incident. In phishing analysis, IOCs are the evidence you extract to:

- Block the attack at your perimeter (IP/domain/URL blocklists)
- Detect if anyone else in your org was affected (log searches)
- Share intelligence with the broader security community (STIX/TAXII)
- Build detection rules (YARA, Sigma, Snort)

---

## IOC Categories

### Network IOCs

| Type | Example | Source in Email |
|:-----|:--------|:----------------|
| IPv4 Address | `198.51.100.45` | `Received:` headers, body URLs |
| Domain | `verify-now.com` | URL parsing, `From:`, `Reply-To:` |
| Full URL | `https://verify-now.com/login/?t=abc` | Email body, HTML href attributes |
| Email Address | `attacker@verify-now.com` | `From:`, `Reply-To:`, `Return-Path:` |

### File IOCs (if attachments present)

| Type | Example | How to Get It |
|:-----|:--------|:--------------|
| SHA-256 Hash | `a1b2c3d4...` | `sha256sum` on extracted attachment |
| MD5 Hash | `b2c3d4e5...` | `md5sum` on extracted attachment |
| SHA-1 Hash | `c3d4e5f6...` | `sha1sum` on extracted attachment |
| Filename | `Invoice_May2026.docm` | Email attachment metadata |
| File Type | `Microsoft Office Macro` | `file` command + magic bytes |

### Behavioral IOCs (from sandbox/dynamic analysis)

| Type | Example |
|:-----|:--------|
| Registry Key | `HKCU\Software\...\Run\malware_persist` |
| Process | `powershell.exe -enc <base64>` |
| Network Connection | `POST /collect/ → 185.234.72.18:443` |
| DNS Query | `c2-server.xyz A record` |
| Email Rule | Auto-forward to `attacker@gmail.com` |

---

## Step 1 — Automated IOC Extraction

Save as `tools/ioc_parser.py`:

```python
#!/usr/bin/env python3
"""
Phishing IOC Parser
Usage: python3 ioc_parser.py --email <sample.eml> [--format json|csv|stix]
"""
import email, re, sys, json, hashlib, os, argparse
from urllib.parse import urlparse
from datetime import datetime, timezone

class IocParser:
    
    def __init__(self, filepath):
        self.filepath = filepath
        self.iocs = {
            'ipv4':            set(),
            'domains':         set(),
            'urls':            set(),
            'email_addresses': set(),
            'attachments':     []
        }
        self.sample_name = os.path.basename(filepath)
    
    # ── Extraction ──────────────────────────────────────────────────────
    
    def extract_all(self):
        with open(self.filepath, errors='ignore') as f:
            msg = email.message_from_file(f)
        
        self._from_headers(msg)
        body = self._get_part(msg, 'text/plain')
        html = self._get_part(msg, 'text/html')
        
        if body: self._from_text(body)
        if html:  self._from_text(html)
        self._from_attachments(msg)
        
        # Convert sets to sorted lists
        return {k: sorted(v) if isinstance(v, set) else v for k, v in self.iocs.items()}
    
    def _get_part(self, msg, content_type):
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == content_type:
                    return part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            if msg.get_content_type() == content_type:
                return msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        return ''
    
    def _from_headers(self, msg):
        for header in ['From', 'Reply-To', 'Return-Path']:
            val = msg.get(header, '')
            self.iocs['email_addresses'].update(
                re.findall(r'[\w.+\-]+@[\w\-]+\.[\w.\-]+', val)
            )
    
    def _from_text(self, text):
        # URLs
        for url in re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>"\'\]\)]+', text):
            self.iocs['urls'].add(url)
            parsed = urlparse(url)
            if parsed.hostname:
                self.iocs['domains'].add(parsed.hostname.lstrip('www.'))
        
        # Raw IPv4 addresses
        for ip in re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text):
            if all(0 <= int(o) <= 255 for o in ip.split('.')):
                # Exclude private/loopback
                first = int(ip.split('.')[0])
                if first not in (10, 127, 169, 172, 192):
                    self.iocs['ipv4'].add(ip)
        
        # Email addresses
        self.iocs['email_addresses'].update(
            re.findall(r'[\w.+\-]+@[\w\-]+\.[\w.\-]+', text)
        )
    
    def _from_attachments(self, msg):
        for part in msg.walk():
            filename = part.get_filename()
            if not filename:
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            
            sha256 = hashlib.sha256(payload).hexdigest()
            md5    = hashlib.md5(payload).hexdigest()
            sha1   = hashlib.sha1(payload).hexdigest()
            
            self.iocs['attachments'].append({
                'filename': filename,
                'size_bytes': len(payload),
                'mime_type': part.get_content_type(),
                'sha256': sha256,
                'md5':    md5,
                'sha1':   sha1
            })
    
    # ── Output Formats ───────────────────────────────────────────────────
    
    def to_json(self):
        data = self.extract_all()
        data['metadata'] = {
            'source_file': self.sample_name,
            'extracted_at': datetime.now(timezone.utc).isoformat(),
            'total_iocs': sum(len(v) if isinstance(v, list) else 0 for v in data.values())
        }
        return json.dumps(data, indent=2)
    
    def to_csv(self):
        data = self.extract_all()
        lines = ["type,value"]
        for ip    in data.get('ipv4', []):            lines.append(f"ipv4,{ip}")
        for domain in data.get('domains', []):        lines.append(f"domain,{domain}")
        for url   in data.get('urls', []):            lines.append(f"url,{url}")
        for email_addr in data.get('email_addresses', []): lines.append(f"email,{email_addr}")
        for att   in data.get('attachments', []):     lines.append(f"sha256,{att['sha256']}")
        return '\n'.join(lines)
    
    def to_stix(self):
        """Generate STIX 2.1 bundle"""
        import uuid
        data = self.extract_all()
        bundle_id = str(uuid.uuid4())
        objects = []
        
        for domain in data.get('domains', []):
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": f"Phishing domain: {domain}",
                "pattern": f"[domain-name:value = '{domain}']",
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "labels": ["phishing", "malicious-activity"]
            })
        
        for url in data.get('urls', []):
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": f"Phishing URL",
                "pattern": f"[url:value = '{url}']",
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "labels": ["phishing", "credential-harvesting"]
            })
        
        for att in data.get('attachments', []):
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "name": f"Malicious attachment: {att['filename']}",
                "pattern": f"[file:hashes.'SHA-256' = '{att['sha256']}']",
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "labels": ["phishing", "malicious-file"]
            })
        
        bundle = {"type": "bundle", "id": f"bundle--{bundle_id}", "objects": objects}
        return json.dumps(bundle, indent=2)
    
    def print_summary(self):
        data = self.extract_all()
        print(f"\n{'═'*55}")
        print(f"  IOC EXTRACTION RESULTS — {self.sample_name}")
        print(f"{'═'*55}")
        
        sections = [
            ('Network — IPv4 Addresses', 'ipv4'),
            ('Network — Domains',        'domains'),
            ('Network — Full URLs',      'urls'),
            ('Network — Email Addresses','email_addresses'),
        ]
        for label, key in sections:
            items = data.get(key, [])
            print(f"\n[{label}]  ({len(items)} found)")
            for item in items:
                print(f"  • {item}")
        
        atts = data.get('attachments', [])
        if atts:
            print(f"\n[File — Attachments]  ({len(atts)} found)")
            for att in atts:
                print(f"  • {att['filename']}  ({att['size_bytes']} bytes)")
                print(f"    SHA256: {att['sha256']}")
                print(f"    MD5:    {att['md5']}")
        
        print(f"\n{'═'*55}\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Phishing IOC Extractor')
    parser.add_argument('--email',  required=True, help='Path to .eml file')
    parser.add_argument('--format', choices=['summary','json','csv','stix'],
                        default='summary', help='Output format')
    args = parser.parse_args()
    
    p = IocParser(args.email)
    
    if args.format == 'summary':   p.print_summary()
    elif args.format == 'json':    print(p.to_json())
    elif args.format == 'csv':     print(p.to_csv())
    elif args.format == 'stix':    print(p.to_stix())
```

---

## Step 2 — Hash Attachments Manually

```bash
python3 << 'EOF'
import email, hashlib

with open('samples/Sample_001.eml') as f:
    msg = email.message_from_file(f)

print("=== ATTACHMENT HASHES ===\n")
found = False
for part in msg.walk():
    filename = part.get_filename()
    payload  = part.get_payload(decode=True)
    if filename and payload:
        found = True
        print(f"File:    {filename}")
        print(f"  Size:   {len(payload):,} bytes")
        print(f"  SHA256: {hashlib.sha256(payload).hexdigest()}")
        print(f"  MD5:    {hashlib.md5(payload).hexdigest()}")
        print(f"  SHA1:   {hashlib.sha1(payload).hexdigest()}")
        # Save for further analysis
        with open(f"/tmp/{filename}", 'wb') as out:
            out.write(payload)
        print(f"  Saved:  /tmp/{filename}\n")

if not found:
    print("  No attachments found in this email.")
EOF
```

---

## Step 3 — Threat Intel Enrichment

### VirusTotal API Lookup

```bash
VT_KEY="your_api_key_here"

# Domain lookup
domain="verify-now.com"
curl -s "https://www.virustotal.com/api/v3/domains/${domain}" \
  -H "x-apikey: ${VT_KEY}" | python3 -c "
import json, sys
d = json.load(sys.stdin)
stats = d.get('data',{}).get('attributes',{}).get('last_analysis_stats',{})
print(f'Domain: {sys.argv[0] if False else \"$domain\"}')
print(f'  Malicious:  {stats.get(\"malicious\",0)}')
print(f'  Suspicious: {stats.get(\"suspicious\",0)}')
print(f'  Harmless:   {stats.get(\"harmless\",0)}')
print(f'  Undetected: {stats.get(\"undetected\",0)}')
"

# IP lookup
ip="185.234.72.18"
curl -s "https://www.virustotal.com/api/v3/ip_addresses/${ip}" \
  -H "x-apikey: ${VT_KEY}" | python3 -m json.tool | grep -A5 "last_analysis_stats"

# File hash lookup
hash="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
curl -s "https://www.virustotal.com/api/v3/files/${hash}" \
  -H "x-apikey: ${VT_KEY}" | python3 -m json.tool | grep -A5 "last_analysis_stats"
```

### AlienVault OTX Lookup

```bash
OTX_KEY="your_otx_key_here"
domain="verify-now.com"

curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general" \
  -H "X-OTX-API-KEY: ${OTX_KEY}" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'Pulse count: {d.get(\"pulse_info\",{}).get(\"count\",0)}')
print(f'Reputation:  {d.get(\"reputation\",0)}')
"
```

### AbuseIPDB Lookup

```bash
ABUSE_KEY="your_abuseipdb_key_here"
ip="185.234.72.18"

curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90" \
  -H "Key: ${ABUSE_KEY}" -H "Accept: application/json" | python3 -c "
import json, sys
d = json.load(sys.stdin)['data']
print(f'Abuse Score:   {d[\"abuseConfidenceScore\"]}%')
print(f'Total Reports: {d[\"totalReports\"]}')
print(f'Country:       {d[\"countryCode\"]}')
print(f'Domain:        {d.get(\"domain\",\"N/A\")}')
"
```

---

## Step 4 — IOC Extraction Checklist

- [ ] Extracted all URLs from email body (plain text + HTML)
- [ ] Extracted all domains from URLs and mail headers
- [ ] Extracted all IPv4 addresses from `Received:` chain and body
- [ ] Extracted all email addresses from `From:`, `Reply-To:`, `Return-Path:`
- [ ] Hashed all attachments (SHA-256, MD5, SHA-1)
- [ ] Saved attachments to `/tmp/` for further analysis
- [ ] Looked up all domains + IPs on VirusTotal
- [ ] Checked AlienVault OTX for existing pulses
- [ ] Checked AbuseIPDB for IP reputation
- [ ] Exported IOCs as JSON for report
- [ ] Exported IOCs as STIX 2.1 bundle for sharing
- [ ] Submitted new IOCs to VirusTotal / OTX

---

## References

- [STIX 2.1 Specification — OASIS](https://oasis-open.github.io/cti-documentation/stix/intro)
- [VirusTotal API v3 Documentation](https://developers.virustotal.com/reference/overview)
- [AlienVault OTX API](https://otx.alienvault.com/api)
- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [YARA Documentation](https://yara.readthedocs.io/)
