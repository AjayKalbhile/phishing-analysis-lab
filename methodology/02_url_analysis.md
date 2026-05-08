# Methodology 02 — URL Extraction & Obfuscation Analysis

> **Goal:** Extract all URLs from phishing emails, detect obfuscation techniques, trace redirect chains, and score each URL's risk level.

**Tools:** Python `re`, `BeautifulSoup`, `requests`, `whois`, `urlscan.io`
**Time Required:** 20–40 minutes per sample
**Output:** Structured URL list with obfuscation flags, domain metadata, redirect chains, VT scores

---

## Why URLs Matter in Phishing

The URL is the weapon. Every credential-harvesting phishing email contains at least one malicious URL designed to:

1. Look legitimate at a glance (homograph, subdomain spoofing)
2. Bypass email security filters (URL shorteners, legitimate redirectors)
3. Lead the victim to a credential harvest page, malware download, or drive-by exploit

Your job is to **extract**, **deobfuscate**, **trace**, and **score** every URL in the email.

---

## Step 1 — Extract All URLs from the Email Body

### Method A: Regex extraction from plain text body

```bash
python3 << 'EOF'
import email, re

with open('samples/Sample_001.eml') as f:
    msg = email.message_from_file(f)

body = ""
if msg.is_multipart():
    for part in msg.walk():
        if part.get_content_type() == 'text/plain':
            body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            break
else:
    body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>"\'\]\)]+'
urls = re.findall(url_pattern, body)

print(f"Found {len(urls)} URLs in plain text body:\n")
for i, url in enumerate(urls, 1):
    print(f"  {i:3}. {url}")
EOF
```

### Method B: Extract from HTML body (anchor tags + image sources)

```bash
python3 << 'EOF'
import email
from bs4 import BeautifulSoup

with open('samples/Sample_001.eml') as f:
    msg = email.message_from_file(f)

html_body = ""
if msg.is_multipart():
    for part in msg.walk():
        if part.get_content_type() == 'text/html':
            html_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            break

if html_body:
    soup = BeautifulSoup(html_body, 'html.parser')
    
    print("=== HYPERLINKS ===")
    for a in soup.find_all('a', href=True):
        display_text = a.get_text(strip=True)[:50]
        href = a['href']
        mismatch = ""
        if display_text.startswith('http') and display_text != href:
            mismatch = "  ← MISMATCH WARNING"
        print(f"  Text: '{display_text}'\n  URL:  {href}{mismatch}\n")
    
    print("=== TRACKING PIXELS / IMAGES ===")
    for img in soup.find_all('img', src=True):
        print(f"  {img['src']}")
else:
    print("No HTML body found.")
EOF
```

### Method C: Check headers for unsubscribe / tracking URLs

```bash
grep -iE "(List-Unsubscribe|X-Track|Return-Receipt)" samples/Sample_001.eml
```

---

## Step 2 — Detect URL Obfuscation Techniques

### Technique 1: URL Shorteners

Shorteners hide the real destination from both the user and security tools.

```bash
python3 << 'EOF'
import re

SHORTENERS = {
    "bit.ly", "t.co", "ow.ly", "tinyurl.com", "tiny.cc", "buff.ly",
    "shorturl.at", "is.gd", "cutt.ly", "rebrand.ly", "s.id",
    "v.gd", "rb.gy", "tiny.one", "bl.ink", "urlr.me"
}

with open('samples/Sample_001.eml') as f:
    content = f.read()

urls = re.findall(r'https?://[^\s"<>]+', content)
for url in urls:
    domain = url.split('/')[2].lower()
    if domain in SHORTENERS:
        print(f"[!] URL SHORTENER DETECTED: {url}")
        print(f"    → Expand using: curl -sI '{url}' | grep -i location")
EOF
```

### Technique 2: IDN Homograph Attacks

Attackers use Unicode characters that look identical to ASCII letters (e.g., `аpple.com` uses Cyrillic `а`).

```bash
python3 << 'EOF'
import re, unicodedata

with open('samples/Sample_001.eml') as f:
    content = f.read()

urls = re.findall(r'https?://[^\s"<>]+', content)
brands = ['paypal', 'google', 'microsoft', 'amazon', 'apple',
          'netflix', 'facebook', 'instagram', 'linkedin', 'dropbox',
          'office365', 'outlook', 'onedrive', 'sharepoint']

for url in urls:
    domain = url.split('/')[2].lower()
    
    # Check for non-ASCII characters
    for char in domain:
        if ord(char) > 127:
            name = unicodedata.name(char, 'unknown')
            print(f"[!] NON-ASCII CHARACTER: '{char}' ({name}) in {url}")
    
    # Check for brand name with extra characters (e.g., paypa1, paypa-l)
    for brand in brands:
        if brand in domain.replace('-','').replace('.','').replace('0','o').replace('1','l'):
            if not domain.endswith(f"{brand}.com") and not domain.endswith(f"www.{brand}.com"):
                print(f"[?] BRAND SQUATTING: '{domain}' impersonates '{brand}'")
                print(f"    URL: {url}")
EOF
```

### Technique 3: Raw IP Address in URL

```bash
python3 << 'EOF'
import re, ipaddress

with open('samples/Sample_001.eml') as f:
    content = f.read()

urls = re.findall(r'https?://[^\s"<>]+', content)
for url in urls:
    domain = url.split('/')[2].split(':')[0]  # Remove port if present
    
    # Standard dotted-decimal IP
    try:
        ipaddress.ip_address(domain)
        print(f"[!] RAW IP IN URL: {url}")
        continue
    except ValueError:
        pass
    
    # Decimal-encoded IP (e.g., http://3232235777 = 192.168.1.1)
    if re.match(r'^\d{8,10}$', domain):
        ip_int = int(domain)
        decoded = f"{(ip_int >> 24) & 255}.{(ip_int >> 16) & 255}.{(ip_int >> 8) & 255}.{ip_int & 255}"
        print(f"[!] DECIMAL ENCODED IP: {domain} = {decoded} in {url}")
    
    # Hex IP (e.g., 0xC0A80101)
    if re.match(r'^0x[0-9a-fA-F]+$', domain):
        ip_int = int(domain, 16)
        decoded = f"{(ip_int >> 24) & 255}.{(ip_int >> 16) & 255}.{(ip_int >> 8) & 255}.{ip_int & 255}"
        print(f"[!] HEX ENCODED IP: {domain} = {decoded} in {url}")
EOF
```

### Technique 4: @ Symbol Injection

In a URL, everything before `@` is treated as credentials (username:password). Browsers ignore it, navigating to the real domain after the `@`.

```
https://legitimate.com@evil-phishing.com/login
              ^                ^
        Ignored by browser   Actual destination
```

```bash
grep -oP 'https?://[^\s"<>]+@[^\s"<>]+' samples/Sample_001.eml | while read url; do
    real_domain=$(echo "$url" | awk -F'@' '{print $2}' | cut -d'/' -f1)
    echo "[!] @ INJECTION: Real destination = $real_domain"
    echo "    Full URL: $url"
done
```

### Technique 5: Open Redirect Abuse

Legitimate sites with open redirect vulnerabilities are used as launchers. Email security sees `google.com` and allows it.

```bash
# Common open redirect parameters
grep -oP 'https?://[^\s"<>]+' samples/Sample_001.eml | \
  grep -iP '(redirect|url|dest|return|next|goto|link|out|redir)=[^\s&"<>]+'
```

---

## Step 3 — Domain Intelligence

For each unique domain found:

```bash
python3 << 'EOF'
import re, socket, subprocess

with open('samples/Sample_001.eml') as f:
    content = f.read()

domains = set(re.findall(r'https?://([^/\s"<>:]+)', content))

for domain in domains:
    print(f"\n{'─'*50}")
    print(f"Domain: {domain}")
    
    # DNS resolution
    try:
        ip = socket.gethostbyname(domain)
        print(f"  IP:    {ip}")
    except:
        print("  IP:    [RESOLUTION FAILED]")
    
    # Quick WHOIS age check
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            if any(k in line.lower() for k in ['creat', 'registered', 'reg date']):
                print(f"  WHOIS: {line.strip()}")
                break
    except:
        print("  WHOIS: [FAILED]")
EOF
```

**What to check:**
- **Domain age** — Domains less than 30 days old are highly suspicious
- **Registrar** — NameCheap, Epik, and certain offshore registrars are commonly used for phishing
- **Registrant country** — Mismatches between brand origin and registrant country
- **SSL certificate** — Let's Encrypt certificates are free and used by phishers; presence alone ≠ legitimacy

---

## Step 4 — Redirect Chain Analysis

Never click a phishing URL directly. Trace it safely:

```bash
# Follow all redirects and show each hop (no form submission)
python3 << 'EOF'
import requests

TARGET_URL = "https://bit.ly/3xK9mN2"  # Replace with your extracted URL

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
}

try:
    session = requests.Session()
    resp = session.get(TARGET_URL, headers=headers, allow_redirects=True, timeout=15)
    
    print(f"Redirect chain for: {TARGET_URL}")
    print(f"{'─'*60}")
    
    if resp.history:
        for i, r in enumerate(resp.history, 1):
            print(f"  Step {i}: {r.status_code} → {r.url}")
    
    print(f"  Final: {resp.status_code} → {resp.url}")
    print(f"  Page title: {resp.text.split('<title>')[1].split('</title>')[0] if '<title>' in resp.text else 'N/A'}")
    
    # Phishing landing page indicators
    suspicious_keywords = ['login', 'verify', 'password', 'credential', 'secure', 'account',
                           'sign-in', 'signin', 'authenticate', 'confirm']
    found = [kw for kw in suspicious_keywords if kw in resp.url.lower() or kw in resp.text.lower()[:500]]
    if found:
        print(f"\n  [!] SUSPICIOUS: Landing page contains keywords: {found}")
        
except requests.exceptions.SSLError:
    print("  [!] SSL certificate error — self-signed or invalid cert (suspicious)")
except Exception as e:
    print(f"  Error: {e}")
EOF
```

> **Safety note:** Always run URL analysis in an isolated VM or container, never on a production machine. Consider using `urlscan.io` or VirusTotal's sandbox for full page rendering.

---

## Step 5 — URL Risk Scoring

Score each URL based on observed indicators:

```python
def score_url(url, domain_age_days=None, vt_detections=0, auth_fail=False):
    score = 0
    flags = []
    
    domain = url.split('/')[2].lower()
    
    # Structural indicators
    if any(s in domain for s in ['bit.ly','tinyurl','ow.ly']):
        score += 20; flags.append("URL shortener")
    if '@' in url:
        score += 30; flags.append("@ injection")
    if any(c > '~' for c in domain):
        score += 35; flags.append("Non-ASCII / homograph")
    if any(p in url.lower() for p in ['/login','/verify','/secure','/account','/password']):
        score += 15; flags.append("Credential-harvest path")
    
    # Domain intelligence
    if domain_age_days is not None and domain_age_days < 30:
        score += 25; flags.append(f"New domain ({domain_age_days} days old)")
    
    # Threat intel
    if vt_detections >= 5:
        score += 40; flags.append(f"VT detections: {vt_detections}")
    
    # Auth context
    if auth_fail:
        score += 20; flags.append("Email auth failed (SPF/DKIM/DMARC)")
    
    severity = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    return {"score": min(score, 100), "severity": severity, "flags": flags}
```

---

## Step 6 — URL Analysis Checklist

For every extracted URL, confirm:

- [ ] Is the domain a known shortener? (expand it)
- [ ] Are there any non-ASCII characters in the domain? (homograph check)
- [ ] Does the domain contain a brand name as a subdomain? (`paypal.verify-now.com`)
- [ ] Is there an IP address instead of a domain name?
- [ ] Does the URL contain an `@` symbol?
- [ ] Does the path suggest credential harvesting? (`/login/`, `/verify/`, `/secure/`)
- [ ] Is the domain less than 30 days old?
- [ ] Does the redirect chain pass through a legitimate site?
- [ ] Does the landing page serve a login form?
- [ ] Is the domain on any known phishing blacklist?

---

## References

- [URLScan.io](https://urlscan.io) — Safe URL analysis and page screenshots
- [VirusTotal URL API](https://developers.virustotal.com/reference/scan-url)
- [PhishTank](https://phishtank.org) — Community phishing URL database
- [OpenPhish](https://openphish.com) — Automated phishing feed
- [IDN Homograph Attack — Wikipedia](https://en.wikipedia.org/wiki/IDN_homograph_attack)
- [WHOIS Lookup](https://lookup.icann.org)
