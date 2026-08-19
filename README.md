# 🔍 Phishing Analysis & Threat Intelligence Lab

<div align="center">

<br>

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-blueviolet?style=for-the-badge&logo=linux&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)

<br>

**A professional-grade phishing email analysis toolkit for threat intelligence and incident response.**

*Built for SOC analysts, threat hunters, and security researchers.*

<br>

[Overview](#-overview) &nbsp;·&nbsp;
[Features](#-features) &nbsp;·&nbsp;
[Architecture](#%EF%B8%8F-architecture) &nbsp;·&nbsp;
[Quick Start](#-quick-start) &nbsp;·&nbsp;
[Usage](#-usage) &nbsp;·&nbsp;
[Reports](#-reports) &nbsp;·&nbsp;
[MITRE Coverage](#%EF%B8%8F-mitre-attck-coverage) &nbsp;·&nbsp;
[Methodology](#-methodology)

<br>

</div>

---

## 📋 Overview

This lab provides a **comprehensive, end-to-end pipeline** for analyzing phishing emails. Drop in a `.eml` file and get back:

- Full SPF / DKIM / DMARC authentication verdicts
- Extracted and deobfuscated URLs and IOCs
- Real-time VirusTotal threat intelligence
- MITRE ATT&CK technique mapping
- A professional JSON + Markdown threat report with risk score

Built and battle-tested on **Kali Linux**, designed for repeatable, documented analysis workflows that can plug directly into SOC playbooks.

> **Who is this for?** SOC Tier 1–2 analysts, threat intelligence teams, blue teamers building detection rules, and security students who want hands-on phishing analysis experience.

---

## ✨ Features

| Feature | Description |
|:--------|:------------|
| 📧 **Header Analysis** | Extract and validate SPF, DKIM, and DMARC authentication results; trace hop-by-hop delivery path |
| 🔗 **URL & IOC Extraction** | Deobfuscate embedded URLs, detect homograph attacks, enumerate IPs, domains, and file hashes |
| 🛡️ **Threat Intelligence** | Query VirusTotal, AlienVault OTX, and AbuseIPDB APIs for real-time reputation scoring |
| 🗺️ **MITRE ATT&CK Mapping** | Automatically map findings to T1566 (Phishing) and related sub-techniques |
| 📊 **Automated Reporting** | Generate structured JSON and Markdown threat reports with risk scores |
| ⚠️ **Risk Scoring** | Calculate severity using a weighted multi-indicator scoring model (0–100) |
| 🐳 **Docker Support** | Fully containerized — run the entire lab in one command |

---

## 🏗️ Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Phishing Email │────▶│  Header Analyzer  │────▶│  URL Extractor   │
│   (.eml file)   │     │ (SPF/DKIM/DMARC)  │     │  (IOC Parsing)   │
└─────────────────┘     └──────────────────┘     └────────┬─────────┘
                                                           │
                                                           ▼
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Threat Report  │◀────│  MITRE Mapping   │◀────│ VirusTotal API   │
│ (JSON/Markdown) │     │ (T1566 Tactics)  │     │  (Reputation)    │
└─────────────────┘     └──────────────────┘     └──────────────────┘
```

**Data Flow:**
1. `.eml` file is ingested by the header analyzer
2. Authentication checks (SPF/DKIM/DMARC) are performed via DNS lookups
3. URLs and IOCs are extracted and deobfuscated from the email body
4. Extracted IOCs are queried against VirusTotal and other threat intel APIs
5. Findings are mapped to MITRE ATT&CK techniques
6. A complete threat report is generated with risk scoring

---

## 🛠️ Tools & Technologies

| Category | Tools |
|:---------|:------|
| **Languages** | Python 3.8+, Bash |
| **Email Analysis** | `oletools`, `mailparser`, `pyeml`, Python `email` library |
| **Network Intelligence** | `dnspython`, `python-whois`, `curl`, `requests` |
| **Threat Intel APIs** | VirusTotal v3 API, AlienVault OTX, AbuseIPDB, PhishTank |
| **Frameworks** | MITRE ATT&CK v14 |
| **Infrastructure** | Docker, Docker Compose, Kali Linux, REMnux |
| **Detection** | YARA, Sigma, Snort/Suricata rules |

---

## 📁 Project Structure

```
phishing-analysis-lab/
│
├── README.md                               # You are here
├── LICENSE
├── .env.example                            # API key template
│
├── lab-setup/
│   ├── requirements.txt                    # All Python dependencies
│   ├── setup.sh                            # One-click environment setup
│   ├── Dockerfile                          # Container image definition
│   └── docker-compose.yml                  # Full lab as a container stack
│
├── tools/
│   ├── header_analyzer.py                  # SPF / DKIM / DMARC + hop trace
│   ├── url_extractor.py                    # URL extraction + obfuscation detection
│   ├── ioc_parser.py                       # IOC harvesting (IPs, domains, hashes)
│   ├── vt_lookup.py                        # VirusTotal API v3 integration
│   └── threat_report_generator.py          # Full pipeline → JSON + Markdown report
│
├── samples/
│   ├── Sample_001.eml                      # PayPal credential phishing (sanitized)
│   ├── Sample_002.eml                      # Microsoft 365 phishing (sanitized)
│   └── Sample_003.eml                      # Netflix billing phishing (sanitized)
│
├── reports/
│   ├── Phishing_Threat_Report_Template.md  # Blank report template
│   └── Sample_Report.md                    # Filled example report (PayPal campaign)
│
└── methodology/
    ├── 01_recon_headers.md                 # Email header reconnaissance
    ├── 02_url_analysis.md                  # URL extraction & obfuscation analysis
    ├── 03_ioc_extraction.md                # IOC harvesting & STIX formatting
    ├── 04_remediation.md                   # Incident response & remediation
    └── 05_mitre_ttps.md                    # MITRE ATT&CK TTP mapping
```

---

## 🚀 Quick Start

### Prerequisites

- Kali Linux VM (or any Debian-based Linux)
- Python 3.8+
- Git
- VirusTotal API key — [get one free here](https://www.virustotal.com/gui/join-us)

### Step 1 — Clone the Repository

```bash
git clone https://github.com/AjayKalbhile/phishing-analysis-lab.git
cd phishing-analysis-lab
```

### Step 2 — Install Dependencies

```bash
cd lab-setup
pip3 install -r requirements.txt --break-system-packages
chmod +x setup.sh && ./setup.sh
```

### Step 3 — Configure API Keys

```bash
cp .env.example .env
nano .env
# Add: VT_API_KEY=your_virustotal_key_here
# Add: OTX_API_KEY=your_otx_key_here (optional)
```

### Step 4 — Run Your First Analysis

```bash
python3 tools/threat_report_generator.py --email samples/Sample_001.eml
```

### Step 5 — View the Report

```bash
cat reports/Sample_001_report.md
# or for JSON:
cat reports/Sample_001_report.json
```

> 💡 **Docker alternative:** No Python setup needed — just run `docker-compose up` from the `lab-setup/` directory.

---

## 🔬 Usage

### Analyze Email Headers Only

```bash
python3 tools/header_analyzer.py --email samples/Sample_001.eml
```

**Output:**
```
╔══════════════════════════════════════╗
║     PHISHING HEADER ANALYZER         ║
╚══════════════════════════════════════╝

[HEADERS]
  From:         "PayPal Security Center" <security@verify-now.com>
  Reply-To:     verification@phishingsite.cc
  Return-Path:  bounce@evil-sender.net
  Subject:      ⚠️ Your account has been limited — Verify now

[AUTH RESULTS]
  SPF:   ✗ FAIL   (IP 198.51.100.45 not authorized for verify-now.com)
  DKIM:  ✗ FAIL   (signature did not validate)
  DMARC: ✗ FAIL   (header.from does not align with paypal.com)

[HOP TRACE]  3 hops detected
  Hop 1: [198.51.100.45] → mx.spoofed-sender.xyz        (2026-05-07 14:23:05)
  Hop 2: mx.spoofed-sender.xyz → mx-relay.filter.net    (2026-05-07 14:23:12)
  Hop 3: mx-relay.filter.net → mx.target-org.com        (2026-05-07 14:23:18)

[ORIGINATING IP]  198.51.100.45  (ASN 45102 — Vortex Hosting, RU)

[!] RISK: HIGH — SPF/DKIM/DMARC all failed. Confirmed spoofed sender.
```

### Extract URLs and IOCs

```bash
python3 tools/url_extractor.py --email samples/Sample_001.eml --output reports/
python3 tools/ioc_parser.py --email samples/Sample_001.eml --format json
```

### Query VirusTotal

```bash
python3 tools/vt_lookup.py --domain "paypal-security.verify-now.com"
python3 tools/vt_lookup.py --ip "185.234.72.18"
python3 tools/vt_lookup.py --hash "a1b2c3d4e5f6..."
```

### Generate Full Threat Report

```bash
python3 tools/threat_report_generator.py \
  --email samples/Sample_001.eml \
  --format json,markdown \
  --output reports/
```

---

## 📊 Reports

Each analysis produces a structured threat report with the following sections:

| Section | Contents |
|:--------|:---------|
| **Executive Summary** | Risk score (0–100), severity level, key finding |
| **Email Metadata** | From, Reply-To, Subject, Message-ID, timestamps |
| **Authentication Results** | SPF / DKIM / DMARC verdicts with explanations |
| **Hop Trace** | Full email delivery path with originating IP |
| **Extracted IOCs** | URLs, IPs, domains, email addresses, file hashes |
| **Threat Intelligence** | VirusTotal, OTX, AbuseIPDB verdicts per IOC |
| **MITRE ATT&CK Mapping** | Technique IDs, names, tactics, and detection notes |
| **Recommendations** | Prioritized remediation actions |

**Sample JSON output:**

```json
{
  "report_id": "PTR-20260508-0001",
  "sample": "Sample_001.eml",
  "risk_score": 87,
  "severity": "CRITICAL",
  "auth_results": {
    "spf": "fail",
    "dkim": "fail",
    "dmarc": "fail"
  },
  "mitre_techniques": ["T1566.002", "T1056.003", "T1071.001", "T1036.003"],
  "ioc_count": 12,
  "vt_detections": 34,
  "recommendation": "Block domain immediately. Reset credentials. Enforce DMARC p=reject."
}
```

---

## 🗺️ MITRE ATT&CK Coverage

| Technique ID | Name | Tactic | Covered |
|:-------------|:-----|:-------|:-------:|
| T1566 | Phishing | Initial Access | ✅ |
| T1566.001 | Spearphishing Attachment | Initial Access | ✅ |
| T1566.002 | Spearphishing Link | Initial Access | ✅ |
| T1598.003 | Phishing for Information | Reconnaissance | ✅ |
| T1056.003 | Web Portal Capture | Credential Access | ✅ |
| T1204.001 | Malicious Link | Execution | ✅ |
| T1204.002 | Malicious File | Execution | ✅ |
| T1036.003 | Masquerading | Defense Evasion | ✅ |
| T1071.001 | Web Protocols (C2) | Command & Control | ✅ |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | ✅ |
| T1114.003 | Email Forwarding Rule | Collection | ✅ |
| T1531 | Account Access Removal | Impact | ✅ |

---

## 📖 Methodology

Each phase of analysis is documented step-by-step in the `methodology/` directory:

| # | File | What It Covers |
|:--|:-----|:---------------|
| 01 | [Header Reconnaissance](methodology/01_recon_headers.md) | SPF/DKIM/DMARC analysis, hop tracing, Authentication-Results parsing, automated Python scripts |
| 02 | [URL Analysis](methodology/02_url_analysis.md) | URL extraction from EML body/HTML, homograph detection, IP encoding, @ injection, redirect chain tracing |
| 03 | [IOC Extraction](methodology/03_ioc_extraction.md) | Network + file + behavioral IOC harvesting, STIX 2.1 formatting, threat intel enrichment |
| 04 | [Remediation](methodology/04_remediation.md) | NIST 800-61 incident lifecycle, DMARC deployment steps, YARA/Snort/Sigma detection rules, recovery procedures |
| 05 | [MITRE TTP Mapping](methodology/05_mitre_ttps.md) | Full ATT&CK kill chain walkthrough, detection per tactic, Splunk/KQL queries, ATT&CK Navigator layer JSON |

---

## ⚠️ Disclaimer

> All phishing samples in this repository are **sanitized and defanged** — all domains, URLs, and IPs have been modified to prevent accidental access. Provided strictly for **educational and research purposes**. Do not attempt to access any referenced infrastructure. The authors accept no liability for misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for full details.

---

## 🤝 Contributing

Contributions welcome! Please open an issue to discuss changes before submitting a PR. Include sanitized test samples and updated documentation with any new features.

---

<div align="center">

<br>

Made with ❤️ for the security community

⭐ **Star this repo if you found it useful!**

[![GitHub stars](https://img.shields.io/github/stars/AjayKalbhile/phishing-analysis-lab?style=social)](https://github.com/AjayKalbhile/phishing-analysis-lab)

<br>

</div>
