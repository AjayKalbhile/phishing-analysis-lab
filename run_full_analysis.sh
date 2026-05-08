#!/bin/bash
# run_full_analysis.sh — Complete phishing analysis pipeline
# Usage: ./run_full_analysis.sh <email.eml> [VT_API_KEY]
# Example: ./run_full_analysis.sh samples/urgent_invoice.eml

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EMAIL="$1"
VT_API_KEY="${2:-${VT_API_KEY:-}}"  # Arg or env var

# ── Validation ──────────────────────────────────────────────
if [ -z "$EMAIL" ]; then
    echo ""
    echo "Usage:   $0 <email.eml> [virustotal_api_key]"
    echo "Example: $0 samples/urgent_invoice.eml"
    echo ""
    echo "Available samples:"
    ls "$SCRIPT_DIR"/samples/*.eml 2>/dev/null | sed 's|^|  - |'
    echo ""
    exit 1
fi

if [ ! -f "$EMAIL" ]; then
    echo "[!] File not found: $EMAIL"
    exit 1
fi

BASENAME=$(basename "$EMAIL" .eml)
SAMPLE_DIR=$(dirname "$EMAIL")
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# ── Banner ──────────────────────────────────────────────────
echo ""
echo "████████████████████████████████████████████████████████████"
echo "  PHISHING ANALYSIS PIPELINE"
echo "  Sample:  $EMAIL"
echo "  Time:    $TIMESTAMP"
echo "████████████████████████████████████████████████████████████"
echo ""

# ── Step 1: Header Analysis ─────────────────────────────────
echo "┌─────────────────────────────────────────────────────────┐"
echo "│  STEP 1/3 — Email Header Analysis                       │"
echo "└─────────────────────────────────────────────────────────┘"
python3 "$SCRIPT_DIR/tools/header_analyzer.py" "$EMAIL"
echo ""

# ── Step 2: URL & IOC Extraction ────────────────────────────
echo "┌─────────────────────────────────────────────────────────┐"
echo "│  STEP 2/3 — URL & IOC Extraction                        │"
echo "└─────────────────────────────────────────────────────────┘"
if [ -n "$VT_API_KEY" ]; then
    python3 "$SCRIPT_DIR/tools/url_extractor.py" "$EMAIL" "$VT_API_KEY"
else
    python3 "$SCRIPT_DIR/tools/url_extractor.py" "$EMAIL"
    echo "  [i] Tip: Pass your VT_API_KEY as arg 2 for live VT lookups"
fi
echo ""

# ── Step 3: Threat Report Generation ────────────────────────
echo "┌─────────────────────────────────────────────────────────┐"
echo "│  STEP 3/3 — Threat Report Generation                    │"
echo "└─────────────────────────────────────────────────────────┘"
python3 "$SCRIPT_DIR/tools/threat_report_generator.py" "$EMAIL"
echo ""

# ── Summary ─────────────────────────────────────────────────
echo "████████████████████████████████████████████████████████████"
echo "  ANALYSIS COMPLETE"
echo ""
echo "  Output files generated:"
echo "  ├── ${SAMPLE_DIR}/${BASENAME}_analysis.json      (Header analysis)"
echo "  ├── ${SAMPLE_DIR}/${BASENAME}_iocs.json          (IOC list)"
echo "  └── ${SAMPLE_DIR}/${BASENAME}_threat_report.json (Full report)"
echo ""
echo "  Next steps:"
echo "  • Block identified domains/IPs at your perimeter"
echo "  • Submit IOCs to VirusTotal and AlienVault OTX"
echo "  • Map findings to MITRE ATT&CK (see methodology/05_mitre_ttps.md)"
echo "████████████████████████████████████████████████████████████"
echo ""
