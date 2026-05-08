# Methodology 01 — Email Header Reconnaissance & Analysis

> **Goal:** Extract, parse, and analyze email headers to determine authenticity, trace the delivery path, and identify spoofing indicators.

**Tools:** Python `email` library, `dnspython`, `grep`, `awk`
**Time Required:** 15–30 minutes per sample
**Output:** Authentication verdicts (SPF/DKIM/DMARC), originating IP, hop trace

---

## What Are Email Headers?

Every email carries hidden metadata called **headers** — a chain of routing stamps added by each mail server the email passes through. Headers tell you:

- **Who actually sent the email** (often different from the display name)
- **Which servers it passed through** (the delivery path)
- **Whether authentication checks passed or failed** (SPF, DKIM, DMARC)
- **Where to look for the real origin** (originating IP)

In phishing analysis, headers are your **ground truth** — they cannot be faked end-to-end because receiving mail servers add their own stamps.

---

## Step 1 — Extract Raw Headers from .eml File

```bash
# View all headers
grep -E "^[A-Za-z-]+:" sample.eml | head -40

# Extract with Python (structured output)
python3 << 'EOF'
import email, sys

with open('samples/Sample_001.eml') as f:
    msg = email.message_from_file(f)

critical_headers = [
    'Message-ID', 'From', 'Reply-To', 'Return-Path',
    'Subject', 'Date', 'To', 'DKIM-Signature',
    'Authentication-Results', 'Received-SPF'
]

print("=== CRITICAL HEADERS ===")
for h in critical_headers:
    val = msg.get(h, '[NOT PRESENT]')
    print(f"  {h:<30}: {val[:100]}")
EOF
```

### Key Headers and What They Mean

| Header | Purpose | Phishing Indicator |
|:-------|:--------|:------------------|
| `From` | Display name + sender address | Can be freely forged |
| `Return-Path` | Where bounces go — used for SPF | Often differs from `From` in phishing |
| `Reply-To` | Where replies go | Attacker sets this to their own address |
| `Message-ID` | Unique email identifier | Malformed or suspicious domains in ID |
| `Received` | Added by each mail server (hop stamps) | Reveals true origin |
| `Authentication-Results` | MTA's auth verdict | Most important header for analysis |
| `DKIM-Signature` | Cryptographic email signature | Missing or failing = red flag |

---

## Step 2 — Trace the Delivery Path (Hop Analysis)

The `Received:` headers form a chain — read them **bottom to top** (oldest first) to trace the email's journey.

```bash
# Extract all Received headers in order
python3 << 'EOF'
import email, re

with open('samples/Sample_001.eml') as f:
    msg = email.message_from_file(f)

received = msg.get_all('Received', [])
print(f"Total hops: {len(received)}\n")
print(f"{'Hop':<5} {'From IP/Host':<35} {'By Host':<35} Timestamp")
print("─" * 100)

for i, hop in enumerate(reversed(received), 1):
    hop_clean = ' '.join(hop.split())
    from_m = re.search(r'from\s+(\S+)', hop_clean, re.I)
    by_m   = re.search(r'by\s+(\S+)', hop_clean, re.I)
    time_m = re.search(r';\s*(.+)$', hop_clean)
    
    from_v = from_m.group(1) if from_m else '?'
    by_v   = by_m.group(1)   if by_m   else '?'
    time_v = time_m.group(1).strip()[:30] if time_m else '?'
    
    print(f"  {i:<4} {from_v:<35} {by_v:<35} {time_v}")

print("\n[!] Hop 1 (bottom) = ORIGINATING SERVER — this is the true sender")
EOF
```

### What to Look For

- **Hop 1 (originating):** Does the sending IP belong to the claimed organization?
- **Unexpected relays:** Is email routing through countries with no connection to the sender?
- **Timestamp gaps:** Large gaps between hops can indicate queuing by spam infrastructure
- **IP lookup:** Check originating IP against `https://ipinfo.io/<IP>` or `whois`

```bash
# Look up originating IP
whois 198.51.100.45
curl -s https://ipinfo.io/198.51.100.45/json | python3 -m json.tool
```

---

## Step 3 — SPF (Sender Policy Framework) Analysis

**What SPF does:** The receiving server checks whether the sending IP is listed as authorized in the sender domain's DNS TXT record.

```bash
# Find the envelope sender domain (from Return-Path)
grep "^Return-Path:" samples/Sample_001.eml

# Look up that domain's SPF record
dig +short TXT verify-now.com | grep "v=spf1"

# Python DNS lookup
python3 << 'EOF'
import dns.resolver

domain = "verify-now.com"
try:
    answers = dns.resolver.resolve(domain, 'TXT')
    for r in answers:
        txt = r.to_text().strip('"')
        if 'v=spf1' in txt:
            print(f"SPF Record: {txt}")
except Exception as e:
    print(f"No SPF record found: {e}")
EOF
```

### SPF Result Codes

| Result | Meaning | Action |
|:-------|:--------|:-------|
| `pass` | IP is authorized | Likely legitimate |
| `fail` (`-all`) | IP is NOT authorized | High confidence phishing |
| `softfail` (`~all`) | IP not authorized but policy is lenient | Suspicious — treat as phishing indicator |
| `neutral` (`?all`) | No policy declared | Inconclusive |
| `temperror` | DNS lookup failed temporarily | Retry |
| `permerror` | SPF record is malformed | Possible evasion attempt |

> **Rule of thumb:** `softfail` or `fail` combined with a mismatch between `From` and `Return-Path` domains = high-confidence phishing indicator.

---

## Step 4 — DKIM (DomainKeys Identified Mail) Analysis

**What DKIM does:** The sending server cryptographically signs the email. The receiving server retrieves the public key via DNS and validates the signature, confirming the email body was not tampered with in transit.

```bash
# Extract DKIM signature details
python3 << 'EOF'
import email, re

with open('samples/Sample_001.eml') as f:
    msg = email.message_from_file(f)

dkim = msg.get('DKIM-Signature', '[NOT PRESENT]')
if dkim == '[NOT PRESENT]':
    print("[!] NO DKIM SIGNATURE — unsigned email, high risk")
else:
    print(f"DKIM-Signature found:")
    s = re.search(r'\bs=([^;]+)', dkim)
    d = re.search(r'\bd=([^;]+)', dkim)
    if s and d:
        selector = s.group(1).strip()
        domain   = d.group(1).strip()
        print(f"  Selector: {selector}")
        print(f"  Domain:   {domain}")
        print(f"  DNS key:  {selector}._domainkey.{domain}")
EOF

# Retrieve the DKIM public key from DNS
dig +short TXT s2026._domainkey.verify-now.com
```

### DKIM Result Interpretation

| Result | Meaning |
|:-------|:--------|
| `pass` | Signature valid — body and signed headers were not modified |
| `fail` | Signature invalid — message was tampered with OR wrong key used |
| `neutral` | No signature present |
| `permerror` | Signature format is broken |

> **Red flag:** If the `d=` domain in the DKIM signature differs from the `From:` header domain, the email was signed by a third party — a common indicator of phishing infrastructure.

---

## Step 5 — DMARC Analysis

**What DMARC does:** DMARC ties SPF and DKIM together with a policy. It requires **alignment** — the domain in the `From:` header must match the domain used in SPF or DKIM checks. The policy tells receivers what to do when alignment fails.

```bash
# Look up DMARC policy for the From: domain
dig +short TXT _dmarc.paypal.com

# Python lookup
python3 << 'EOF'
import dns.resolver

domain = "_dmarc.paypal.com"
try:
    answers = dns.resolver.resolve(domain, 'TXT')
    for r in answers:
        record = r.to_text().strip('"')
        if 'v=DMARC1' in record:
            print(f"DMARC Record: {record}")
            if 'p=none' in record:
                print("  [!] Policy: NONE — no enforcement, spoofed emails reach inbox")
            elif 'p=quarantine' in record:
                print("  [~] Policy: QUARANTINE — spoofed emails go to spam")
            elif 'p=reject' in record:
                print("  [✓] Policy: REJECT — spoofed emails are blocked at SMTP")
except Exception as e:
    print(f"No DMARC record: {e}")
EOF
```

### DMARC Policy Levels

| Policy | What Happens to Spoofed Email | Phishing Risk |
|:-------|:------------------------------|:--------------|
| `p=none` | Delivered to inbox — no enforcement | **CRITICAL** — spoofing succeeds |
| `p=quarantine` | Sent to spam folder | Medium — some spoofing gets through |
| `p=reject` | Rejected at SMTP level, never delivered | **LOW** — effective prevention |

### The Complete Auth Picture

```
Authentication-Results: mx.target-org.com;
  spf=softfail (sender IP 198.51.100.45 not authorized) verify-now.com;
  dkim=fail (signature did not verify) header.d=verify-now.com;
  dmarc=fail (header.from=paypal-security.verify-now.com) action=none
```

**Parsing this:**
- SPF softfail: Sending IP not authorized
- DKIM fail: Signature invalid
- DMARC fail: From domain doesn't align with paypal.com
- action=none: Victim domain has `p=none` — email was **delivered anyway**

---

## Step 6 — Automated Header Analysis Script

Save and run `tools/header_analyzer.py`:

```python
#!/usr/bin/env python3
"""
Phishing Header Analyzer
Usage: python3 header_analyzer.py --email <sample.eml>
"""
import email, sys, re, argparse
import dns.resolver

def check_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for r in answers:
            t = r.to_text().strip('"')
            if 'v=DMARC1' in t:
                return t
    except:
        return "No DMARC record"
    return "No DMARC record"

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for r in answers:
            t = r.to_text().strip('"')
            if 'v=spf1' in t:
                return t
    except:
        return "No SPF record"
    return "No SPF record"

def analyze(filepath):
    with open(filepath) as f:
        msg = email.message_from_file(f)

    print("\n" + "═"*60)
    print("  PHISHING EMAIL HEADER ANALYZER")
    print("═"*60)

    # Critical headers
    headers = {h: msg.get(h, '[NOT PRESENT]') for h in
               ['Message-ID','From','Reply-To','Return-Path','Subject','Date']}
    print("\n[HEADERS]")
    for k, v in headers.items():
        print(f"  {k:<15}: {str(v)[:80]}")

    # Domain mismatch
    from_match   = re.search(r'@([\w.-]+)', headers['From'])
    return_match = re.search(r'@([\w.-]+)', headers['Return-Path'])
    if from_match and return_match:
        f_dom = from_match.group(1)
        r_dom = return_match.group(1)
        match = f_dom.lower() == r_dom.lower()
        print(f"\n[DOMAIN CHECK]")
        print(f"  From domain:        {f_dom}")
        print(f"  Return-Path domain: {r_dom}")
        print(f"  Match:              {'YES' if match else 'NO  ← SPOOFING RISK'}")

    # SPF check
    if return_match:
        spf = check_spf(return_match.group(1))
        print(f"\n[SPF RECORD]\n  {spf}")

    # DMARC check
    if from_match:
        dmarc = check_dmarc(from_match.group(1))
        print(f"\n[DMARC RECORD]\n  {dmarc}")

    # Auth results
    auth = msg.get('Authentication-Results', '')
    if auth:
        print("\n[AUTH VERDICT]")
        for check in ['spf', 'dkim', 'dmarc']:
            m = re.search(f'{check}\\s*=\\s*(\\w+)', auth.lower())
            if m:
                verdict = m.group(1)
                flag = '✓' if verdict == 'pass' else '✗'
                print(f"  {flag} {check.upper():<8}: {verdict}")

    # Hop trace
    received = msg.get_all('Received', [])
    print(f"\n[HOP TRACE]  {len(received)} hops detected")
    for i, hop in enumerate(reversed(received), 1):
        hop_clean = ' '.join(hop.split())[:120]
        print(f"  Hop {i}: {hop_clean}")

    print("\n" + "═"*60 + "\n")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--email', required=True, help='Path to .eml file')
    args = parser.parse_args()
    analyze(args.email)
```

---

## Step 7 — Header Analysis Checklist

Work through this for every sample:

- [ ] `From` display name matches a known brand but email domain is generic
- [ ] `From` domain differs from `Return-Path` domain
- [ ] `Reply-To` points to a different domain than `From`
- [ ] SPF result is `fail` or `softfail`
- [ ] DKIM signature absent or `fail`
- [ ] DMARC result is `fail` — especially if sender's policy is `p=reject`
- [ ] Originating IP (Hop 1) is in an unexpected country or ASN
- [ ] `Message-ID` domain differs from `From` domain
- [ ] Timestamps show unusual sending hours (early morning UTC = EU attacker, etc.)
- [ ] `Received` chain contains unexpected relay servers

---

## References

- [RFC 7208 — Sender Policy Framework (SPF)](https://tools.ietf.org/html/rfc7208)
- [RFC 6376 — DomainKeys Identified Mail (DKIM)](https://tools.ietf.org/html/rfc6376)
- [RFC 7489 — Domain-based Message Authentication (DMARC)](https://tools.ietf.org/html/rfc7489)
- [DMARC.org — Deployment Guide](https://dmarc.org/overview/)
- [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
