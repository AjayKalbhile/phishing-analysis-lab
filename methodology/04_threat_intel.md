# Methodology 04 — Threat Intelligence & Remediation

> **Goal:** Enrich extracted IOCs with external threat intelligence, correlate findings to known threat actors, and execute a structured incident response playbook following the NIST SP 800-61 lifecycle.

**Framework:** NIST SP 800-61 Rev. 2 (Preparation → Detection → Containment → Eradication → Recovery → Post-Incident)
**Tools:** VirusTotal, AlienVault OTX, AbuseIPDB, PhishTank, Gophish, DMARC tools
**Time Required:** 30–60 minutes per incident

---

## 4.1 The Incident Response Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│   PREPARATION → DETECTION → CONTAINMENT → ERADICATION           │
│                    ↑               ↓            ↓               │
│                    └───────── RECOVERY ←────────┘               │
│                                   ↓                             │
│                          POST-INCIDENT REVIEW                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 1 — Preparation

Before an incident occurs, these controls must be in place:

| Control | What It Does | Priority |
|:--------|:------------|:---------|
| **DMARC `p=reject`** | Blocks spoofed emails from reaching users | P0 — Critical |
| **Email gateway filtering** | Scans attachments and URLs before delivery | P0 — Critical |
| **URL time-of-click scanning** | Re-checks URLs when user clicks (not just on receipt) | P1 — High |
| **Attachment sandboxing** | Detonates attachments in an isolated environment | P1 — High |
| **Phishing simulation** | Trains users with simulated campaigns (Gophish) | P2 — Medium |
| **"Report Phishing" button** | One-click user reporting in Outlook/Gmail | P2 — Medium |

---

## Phase 2 — Detection & Triage

When a suspicious email is reported:

```bash
# Quick triage script — run on reported .eml
python3 << 'EOF'
import email, re, sys

with open('samples/Sample_001.eml') as f:
    msg = email.message_from_file(f)

print("=== QUICK TRIAGE ===")

# Auth results
auth = msg.get('Authentication-Results', '')
results = re.findall(r'(spf|dkim|dmarc)\s*=\s*(\w+)', auth.lower())
fail_count = sum(1 for _, v in results if v in ('fail','softfail','none'))
print(f"\nAuth Failures: {fail_count}/3")
for check, result in results:
    flag = "✗" if result in ('fail','softfail') else "✓"
    print(f"  {flag} {check.upper()}: {result}")

# Domain mismatch
from_hdr = msg.get('From', '')
return_path = msg.get('Return-Path', '')
from_dom = re.search(r'@([\w.-]+)', from_hdr)
rp_dom   = re.search(r'@([\w.-]+)', return_path)
if from_dom and rp_dom:
    match = from_dom.group(1).lower() == rp_dom.group(1).lower()
    print(f"\nDomain Match: {'YES' if match else 'NO ← SPOOFING DETECTED'}")

# URLs
body_text = ""
for part in msg.walk():
    if part.get_content_type() in ('text/plain', 'text/html'):
        try:
            body_text += part.get_payload(decode=True).decode('utf-8', errors='ignore')
        except: pass
urls = re.findall(r'https?://[^\s"<>]+', body_text)
print(f"\nURLs found: {len(urls)}")
for url in urls[:5]:
    print(f"  → {url[:100]}")

# Attachments
atts = [p.get_filename() for p in msg.walk() if p.get_filename()]
print(f"\nAttachments: {len(atts)}")
for att in atts:
    print(f"  → {att}")

# Risk score
score = (fail_count * 25) + (30 if not match and from_dom and rp_dom else 0) + (min(len(urls),3) * 5)
print(f"\nRisk Score:  {min(score,100)}/100")
print(f"Verdict:     {'MALICIOUS — ESCALATE' if score >= 50 else 'SUSPICIOUS — INVESTIGATE' if score >= 25 else 'LOW RISK'}")
EOF
```

---

## Phase 3 — Containment (First Hour)

### Priority Actions

| # | Action | Tool / Command | Owner |
|:--|:-------|:--------------|:------|
| 1 | **Isolate affected user account** | Disable AD account or force logout | SOC |
| 2 | **Block sender domain at email gateway** | Add to envelope-from blocklist | Email Security |
| 3 | **Block malicious IPs/domains** | DNS sinkhole / firewall rule | Network Security |
| 4 | **Delete email from all inboxes** | Exchange search-and-delete / GAM | IT Ops |
| 5 | **Reset compromised credentials** | AD password reset + MFA re-enroll | IT Ops |

### Delete Phishing Email from All Mailboxes

**Microsoft 365 (Exchange Online PowerShell):**
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Search across all mailboxes and delete
$msgId = "<202605071423.ABCDEF@mx.spoofed-sender.xyz>"
Get-Mailbox -ResultSize Unlimited | 
  Search-Mailbox -SearchQuery "MessageId:$msgId" -DeleteContent -Force

# Verify deletion
Get-Mailbox -ResultSize Unlimited |
  Search-Mailbox -SearchQuery "MessageId:$msgId" -EstimateResultOnly
```

**Google Workspace (GAM):**
```bash
# Install GAM: https://github.com/GAM-team/GAM
gam all users delete messages query \
  "subject:'Your account has been limited' after:2026/05/07"
```

### Block Malicious Domains (Linux)

```bash
# DNS sinkhole (dnsmasq / Pi-hole)
cat >> /etc/hosts << 'EOF'
127.0.0.1  verify-now.com
127.0.0.1  paypal-security.verify-now.com
127.0.0.1  evil-sender.net
EOF

# Firewall block (iptables)
iptables -A OUTPUT -d 185.234.72.18 -j DROP
iptables -A INPUT  -s 185.234.72.18 -j DROP
ip6tables -A OUTPUT -d ::1 -j DROP  # IPv6 if applicable

# Make persistent
iptables-save > /etc/iptables/rules.v4
```

---

## Phase 4 — Email Authentication Hardening (DMARC Deployment)

### Step-by-Step DMARC Progressive Deployment

**Step 1 — Monitor (Week 1-2): No blocking, just data collection**

```dns
_dmarc.yourdomain.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com; ruf=mailto:dmarc-failure@yourdomain.com; fo=1"
```

**Step 2 — Quarantine (Week 3-4): Suspicious emails go to spam for 25% of traffic**

```dns
_dmarc.yourdomain.com.  TXT  "v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@yourdomain.com"
```

**Step 3 — Enforce (Week 5+): Full rejection after confirming no legitimate email is spoofing**

```dns
_dmarc.yourdomain.com.  TXT  "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@yourdomain.com; ruf=mailto:dmarc-failure@yourdomain.com"
```

**Verify your DMARC configuration:**
```bash
dig +short TXT _dmarc.yourdomain.com
# Also check: https://mxtoolbox.com/dmarc.aspx
```

### Complete SPF Record Example

```dns
# Allow only Microsoft 365 as your authorized sender
yourdomain.com.  TXT  "v=spf1 include:spf.protection.outlook.com -all"

# If using multiple services (M365 + Mailchimp + Zendesk)
yourdomain.com.  TXT  "v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net include:mail.zendesk.com -all"
```

> **Important:** `-all` = hard fail (best security). `~all` = soft fail (permissive). Always prefer `-all`.

---

## Phase 5 — Detection Engineering

### YARA Rule for Phishing Attachment

```yara
rule Phishing_PayPal_Campaign_May2026 {
    meta:
        description = "Detects PayPal phishing campaign attachments - May 2026"
        author      = "Phishing Analysis Lab"
        date        = "2026-05-08"
        reference   = "PTR-20260508-0001"
        severity    = "HIGH"
    
    strings:
        $domain1  = "verify-now.com"           wide ascii nocase
        $domain2  = "paypal-security"          wide ascii nocase
        $phrase1  = "Your account has been limited" wide ascii nocase
        $phrase2  = "Suspicious activity detected"  wide ascii nocase
        $url1     = "/login/?token="           wide ascii nocase
    
    condition:
        2 of them
}
```

### Snort / Suricata IDS Rule

```snort
# Block outbound connections to phishing domain
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
    msg:"PHISHING PayPal Campaign May2026 - C2 Connection";
    content:"Host: paypal-security.verify-now.com";
    http_header;
    classtype:trojan-activity;
    sid:9000001;
    rev:1;
)

# Detect credential submission
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"PHISHING Credential POST to Known Phishing Domain";
    content:"POST"; http_method;
    content:"/login/"; http_uri;
    content:"email="; http_client_body;
    content:"password="; http_client_body;
    sid:9000002;
    rev:1;
)
```

### Sigma Rule (for SIEM)

```yaml
title: Suspicious Email Forwarding Rule Created
id: fec8a6e0-4421-4abc-9def-0123456789ab
status: experimental
description: >
  Detects creation of inbox forwarding rules which may indicate 
  post-phishing mailbox compromise.
author: Phishing Analysis Lab
date: 2026-05-08
tags:
  - attack.t1114.003
  - attack.collection
logsource:
  product: office365
  service: exchange
detection:
  selection:
    Operation: "New-InboxRule"
  filter_suspicious_domain:
    ForwardTo|re: '@[a-z0-9.-]{4,}\.(xyz|top|click|work|ru|tk|ml|ga|cf)$'
  condition: selection and filter_suspicious_domain
falsepositives:
  - Legitimate forwarding rules set by users
level: high
```

### Splunk Detection Query

```spl
index=email earliest=-7d
| search "Authentication-Results"
| rex field=_raw "spf=(?P<spf_result>\w+)"
| rex field=_raw "dkim=(?P<dkim_result>\w+)"
| rex field=_raw "dmarc=(?P<dmarc_result>\w+)"
| eval auth_failures = mvcount(mvfilter(match(mvappend(spf_result,dkim_result,dmarc_result),"fail|softfail")))
| where auth_failures >= 2
| eval severity = case(auth_failures >= 3, "CRITICAL", auth_failures == 2, "HIGH", 1==1, "MEDIUM")
| stats count by From, Subject, severity, spf_result, dkim_result, dmarc_result
| sort - count
```

---

## Phase 6 — Eradication & Recovery

### Credential Compromise Checklist

```bash
# 1. Force immediate password reset
net user jsmith /domain /passwordreq:yes
# Or in M365:
Set-MsolUserPassword -UserPrincipalName jsmith@company.com -ForceChangePassword $true

# 2. Revoke all active sessions (M365)
# PowerShell:
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser -SearchString "jsmith").ObjectId

# 3. Check for auto-forwarding rules (common attacker persistence)
Get-InboxRule -Mailbox jsmith | Where-Object {$_.ForwardTo -ne $null}

# 4. Check OAuth app grants (attacker may have authorized a persistent app)
Get-AzureADUserAppRoleAssignment -ObjectId (Get-AzureADUser -SearchString "jsmith").ObjectId

# 5. Check recent sign-in locations
Get-AzureADAuditSignInLogs -Filter "userPrincipalName eq 'jsmith@company.com'" | 
  Select-Object CreatedDateTime, IpAddress, Location, Status | 
  Sort-Object CreatedDateTime -Descending | 
  Select-Object -First 20
```

### User Reinstatement Process

1. Confirm password has been reset (16+ chars, not previously used)
2. Force MFA re-enrollment (revoke existing token)
3. Review all mail forwarding rules — delete any not set by user
4. Review all OAuth app consents — revoke suspicious ones
5. Check recent login locations — flag any unexpected geo-logins
6. Run EDR/AV scan on user's endpoint
7. Re-enable user account and communicate next steps to user

---

## Phase 7 — Post-Incident Metrics

Track these metrics after every phishing incident:

| Metric | Target | Formula |
|:-------|:-------|:--------|
| **MTTD** (Mean Time to Detect) | < 15 min | Time from email sent → SOC alerted |
| **MTTR** (Mean Time to Respond) | < 1 hour | Time from alert → containment complete |
| **Phishing Click Rate** | < 3% | (Users who clicked) / (Total recipients) × 100 |
| **Report Rate** | > 70% | (Users who reported) / (Total recipients) × 100 |
| **DMARC Coverage** | 100% | (Domains with p=reject) / (Total domains) × 100 |

---

## Incident Response Playbook Quick Reference

```
PHISHING REPORTED
       │
       ▼
  [TRIAGE — 5 min]
  Run header_analyzer.py
  Check auth results
  Is it confirmed malicious?
       │
    YES│              NO
       ▼              └──→ Mark as FP, close ticket
  [CONTAIN — 15 min]
  • Block sender domain
  • Delete from all inboxes
  • Identify all recipients
       │
       ▼
  [ASSESS — 30 min]
  Did anyone click?
  Did anyone submit creds?
       │
    YES│              NO
       ▼              └──→ Block IOCs, close
  [ERADICATE — 1 hr]
  • Reset credentials
  • Revoke sessions
  • Remove mail rules
  • Isolate endpoint if malware
       │
       ▼
  [RECOVER — 2 hr]
  • Reinstate user
  • Monitor for reattack
  • Update detections
       │
       ▼
  [POST-INCIDENT — 24 hr]
  • Root cause analysis
  • Lessons learned
  • Update playbook
  • Awareness training
```

---

## References

- [NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [CISA — Phishing Guidance](https://www.cisa.gov/phishing)
- [DMARC.org — Deployment Guide](https://dmarc.org/overview/)
- [Gophish — Open-Source Phishing Simulation](https://getgophish.com/)
- [Microsoft — Investigate & Respond to Phishing](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/investigate-malicious-email-that-was-delivered)
