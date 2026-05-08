# Methodology 05 — MITRE ATT&CK TTP Mapping

> **Goal:** Map every observed phishing behavior to a specific MITRE ATT&CK technique, build the full kill chain, create detection rules per tactic, and export an ATT&CK Navigator layer for visualization.

**Framework:** MITRE ATT&CK Enterprise v14
**Reference:** [https://attack.mitre.org](https://attack.mitre.org)
**Time Required:** 30–45 minutes per sample
**Output:** Completed TTP table, kill chain diagram, ATT&CK Navigator layer JSON

---

## Why Map to MITRE ATT&CK?

MITRE ATT&CK is the industry standard language for describing adversary behavior. Mapping your findings to ATT&CK lets you:

- **Communicate clearly** with other analysts, IR teams, and management
- **Identify detection gaps** — which techniques do you have no coverage for?
- **Build better detections** — each ATT&CK technique has associated data sources
- **Share intelligence** — STIX bundles use ATT&CK technique IDs
- **Measure your defenses** — ATT&CK Navigator shows coverage visually

---

## The Full Phishing Kill Chain

```
RECONNAISSANCE
  └── T1598.003  Phishing for Information (gathering target email addresses)

RESOURCE DEVELOPMENT
  ├── T1583.001  Acquire Domain (register verify-now.com)
  ├── T1583.003  Virtual Private Server (host phishing page)
  └── T1587.001  Develop Capabilities (build credential harvest clone)

INITIAL ACCESS  ← Where the phishing email sits
  ├── T1566.001  Spearphishing Attachment
  └── T1566.002  Spearphishing Link  ← THIS CAMPAIGN

EXECUTION  ← User clicks the link / opens attachment
  └── T1204.001  Malicious Link (user-initiated click)

CREDENTIAL ACCESS  ← Victim submits credentials to fake page
  └── T1056.003  Web Portal Capture (fake login form)

DEFENSE EVASION  ← How attacker avoids detection
  ├── T1036.003  Masquerading (display name = "PayPal Security")
  └── T1027.001  Obfuscated Files (URL shortener to hide destination)

COMMAND & CONTROL  ← How stolen data gets back to attacker
  └── T1071.001  Web Protocols (credentials POST'd over HTTPS)

EXFILTRATION  ← Data leaves the environment
  └── T1041     Exfiltration Over C2 Channel

COLLECTION  ← If mailbox is accessed post-compromise
  └── T1114.003  Email Forwarding Rule

IMPACT  ← Final outcome for the victim
  ├── T1531     Account Access Removal (victim locked out)
  └── T1486     Data Encrypted for Impact (if ransomware follows)
```

---

## Complete TTP Reference Table

### Initial Access

| Technique ID | Name | Observed In | Indicators | Detection |
|:-------------|:-----|:-----------|:-----------|:----------|
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | All phishing campaigns | Email with malicious content | Email gateway + SPF/DKIM/DMARC |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Macro-based campaigns | `.docm`, `.xlsm`, `.pdf` attachments with macros | Sandbox analysis, AV |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link | **This campaign** | URL in body → credential harvest page | URL reputation, click-time scanning |
| [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | Spearphishing via Service | LinkedIn/Teams phishing | Message from social platform | Platform abuse monitoring |
| [T1566.004](https://attack.mitre.org/techniques/T1566/004/) | Spearphishing Voice | Vishing + email combo attacks | Follow-up phone call to email | Call logging + user awareness |

### Reconnaissance

| Technique ID | Name | Description | Detection |
|:-------------|:-----|:-----------|:----------|
| [T1598](https://attack.mitre.org/techniques/T1598/) | Phishing for Information | Credential harvesting as primary goal | Look for fake survey/form links |
| [T1598.003](https://attack.mitre.org/techniques/T1598/003/) | Spearphishing Link (recon) | Fake login pages to gather credentials | URL analysis + landing page detection |
| [T1589.001](https://attack.mitre.org/techniques/T1589/001/) | Gather Victim Identity Info | Harvesting email addresses pre-attack | Monitor email enumeration attempts |

### Execution

| Technique ID | Name | Triggered By | Detection |
|:-------------|:-----|:------------|:----------|
| [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Malicious Link | User clicks URL in phishing email | Proxy logs, DNS logs |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File | User opens attachment | Process creation logs (Sysmon EID 1) |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Macro drops encoded PS payload | PowerShell script block logging |
| [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Visual Basic | VBA macro in Office document | Sysmon, AMSI logging |

### Credential Access

| Technique ID | Name | Description | Detection |
|:-------------|:-----|:-----------|:----------|
| [T1056.003](https://attack.mitre.org/techniques/T1056/003/) | Web Portal Capture | **Fake login page captures username + password** | Impossible travel, geo-anomalies |
| [T1110.004](https://attack.mitre.org/techniques/T1110/004/) | Credential Stuffing | Using stolen creds on other services | Repeated login failures across services |
| [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | Credentials from Browser | Post-compromise browser credential theft | EDR process monitoring |

### Defense Evasion

| Technique ID | Name | Phishing Usage | Detection |
|:-------------|:-----|:--------------|:----------|
| [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Masquerading | Display name = "PayPal Security" | DMARC alignment check |
| [T1027.001](https://attack.mitre.org/techniques/T1027/001/) | Binary Padding | Attachment with padding to evade hash matching | Fuzzy hashing (ssdeep) |
| [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Encrypted/Encoded File | Base64 PowerShell in macros | AMSI + script block logging |
| [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files | Payload decodes itself at runtime | Memory scanning, behavioral EDR |

### Collection

| Technique ID | Name | When Observed | Detection |
|:-------------|:-----|:-------------|:----------|
| [T1114.001](https://attack.mitre.org/techniques/T1114/001/) | Local Email Collection | After endpoint compromise | DLP, file access logging |
| [T1114.002](https://attack.mitre.org/techniques/T1114/002/) | Remote Email Collection | Attacker uses stolen creds to access mailbox via IMAP | Anomalous IMAP login from new IP |
| [T1114.003](https://attack.mitre.org/techniques/T1114/003/) | Email Forwarding Rule | **Attacker creates auto-forward to Gmail** | Alert on new inbox rules |

### Command & Control

| Technique ID | Name | Phishing Usage | Detection |
|:-------------|:-----|:--------------|:----------|
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols (HTTP/S) | Credentials POST'd to C2 over HTTPS | TLS inspection, DLP |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS | DNS tunneling for covert C2 | DNS analytics, long subdomain queries |
| [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | Asymmetric Cryptography | HTTPS to hide C2 traffic | Certificate transparency logs |

### Exfiltration

| Technique ID | Name | Phishing Usage | Detection |
|:-------------|:-----|:--------------|:----------|
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | Credentials sent over same HTTPS channel as C2 | DLP, outbound traffic monitoring |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage | Accessing OneDrive/Dropbox with stolen creds | Cloud CASB alerts |

### Impact

| Technique ID | Name | Phishing Context | Detection |
|:-------------|:-----|:----------------|:----------|
| [T1531](https://attack.mitre.org/techniques/T1531/) | Account Access Removal | Attacker changes victim's password post-theft | Unusual password change, lockout |
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | Ransomware delivered as phishing follow-up | Ransomware behavioral detection |
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Destructive payload in phishing attachment | File system monitoring |

---

## Detection Coverage by Tactic

| Tactic | Technique Count | Your Detection | Mitigation |
|:-------|:---------------|:--------------|:-----------|
| **Initial Access** | T1566.001/002/003/004 | Email gateway + DMARC | DMARC `p=reject`, link sandboxing |
| **Execution** | T1204.001/002, T1059 | Proxy logs, Sysmon EID 1 | Disable macros, AppLocker |
| **Credential Access** | T1056.003, T1110.004 | Login anomalies, geo-alerts | MFA on all accounts |
| **Defense Evasion** | T1036, T1027 | DMARC alignment, AMSI | AMSI, behavioral EDR |
| **Collection** | T1114.003 | Inbox rule creation alert | Monitor mail rules |
| **Exfiltration** | T1041 | DLP, outbound monitoring | DLP policies, TLS inspection |
| **C2** | T1071.001 | Network threat intel | DNS sinkholing, TI feeds |
| **Impact** | T1531, T1486 | Account lockout alerts, ransomware | Immutable backups, EDR |

---

## ATT&CK Navigator Layer

Import this JSON at [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/) to visualize coverage:

```json
{
  "name": "Phishing Campaign — PayPal May 2026",
  "versions": { "attack": "14", "navigator": "4.9", "layer": "4.5" },
  "domain": "enterprise-attack",
  "description": "ATT&CK techniques observed in PayPal credential phishing campaign — Report PTR-20260508-0001",
  "filters": { "platforms": ["Windows", "macOS", "Linux"] },
  "sorting": 0,
  "layout": { "layout": "side", "aggregateFunction": "average", "showID": true, "showName": true },
  "techniques": [
    { "techniqueID": "T1566",     "score": 1, "color": "#ff6666", "comment": "Primary attack vector — phishing email" },
    { "techniqueID": "T1566.001", "score": 1, "color": "#ff4444", "comment": "N/A for this campaign (no attachment)" },
    { "techniqueID": "T1566.002", "score": 1, "color": "#ff0000", "comment": "CONFIRMED — spearphishing link in email body" },
    { "techniqueID": "T1598",     "score": 1, "color": "#ffa500", "comment": "Credential harvesting goal" },
    { "techniqueID": "T1598.003", "score": 1, "color": "#ff6600", "comment": "Fake PayPal login form" },
    { "techniqueID": "T1204.001", "score": 1, "color": "#ff6666", "comment": "User clicked malicious link" },
    { "techniqueID": "T1056.003", "score": 1, "color": "#ff0000", "comment": "CONFIRMED — credentials captured via fake form" },
    { "techniqueID": "T1036.003", "score": 1, "color": "#ffcc00", "comment": "Display name masqueraded as PayPal Security" },
    { "techniqueID": "T1027.001", "score": 1, "color": "#ffaa00", "comment": "URL shortener used to hide destination" },
    { "techniqueID": "T1071.001", "score": 1, "color": "#ffa500", "comment": "Credentials exfiltrated over HTTPS" },
    { "techniqueID": "T1041",     "score": 1, "color": "#ff8800", "comment": "Exfiltration over C2 channel" },
    { "techniqueID": "T1114.003", "score": 1, "color": "#ff9900", "comment": "Possible — monitor for forwarding rule creation" },
    { "techniqueID": "T1531",     "score": 1, "color": "#cc0000", "comment": "CONFIRMED — victim account locked by attacker" }
  ],
  "gradient": {
    "colors": ["#ffff66", "#ffa500", "#ff0000"],
    "minValue": 0,
    "maxValue": 1
  },
  "legendItems": [
    { "label": "Confirmed in this campaign", "color": "#ff0000" },
    { "label": "Likely / Partial",           "color": "#ffa500" },
    { "label": "Possible / Monitor",         "color": "#ffcc00" }
  ]
}
```

---

## TTP Mapping Checklist

For every phishing incident, complete this mapping:

- [ ] **T1566.00X** — Which spearphishing sub-technique? (attachment / link / service / voice)
- [ ] **T1598** — Was the primary goal information/credential gathering?
- [ ] **T1204** — Did user interaction occur? (click / open)
- [ ] **T1056.003** — Were credentials captured via a fake login form?
- [ ] **T1036** — Was masquerading used? (brand impersonation, domain lookalike)
- [ ] **T1027** — Was payload/URL obfuscation detected? (shortener, encoding)
- [ ] **T1059** — Did any script execution occur? (PowerShell / VBA / JS)
- [ ] **T1071** — What protocol was used for C2/exfiltration?
- [ ] **T1114.003** — Check for auto-forwarding rules post-compromise
- [ ] **T1531/T1486** — What was the ultimate impact?
- [ ] Export ATT&CK Navigator layer JSON
- [ ] Include TTP table in threat report

---

## Severity Classification by TTP Count

| TTPs Mapped | Campaign Type | Severity |
|:-----------|:-------------|:---------|
| 1–3 | Opportunistic / commodity phishing | Low |
| 4–6 | Targeted campaign with some sophistication | Medium |
| 7–10 | Organized threat actor | High |
| 10+ (multiple tactics, full kill chain) | APT-level / nation-state | Critical |

---

## References

- [MITRE ATT&CK — Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [MITRE ATT&CK — T1566 Phishing](https://attack.mitre.org/techniques/T1566/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [CAR — Cyber Analytics Repository](https://car.mitre.org/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [ATT&CK for SOC Analysts](https://attack.mitre.org/resources/getting-started/)
