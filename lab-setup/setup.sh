#!/bin/bash
# setup.sh — One-click environment setup for Phishing Analysis Lab
# Tested on Kali Linux 2024+

set -e

echo ""
echo "████████████████████████████████████████████████████████"
echo "  Phishing Analysis Lab — Environment Setup"
echo "████████████████████████████████████████████████████████"
echo ""

# Check OS
if ! command -v apt-get &>/dev/null; then
    echo "[!] This setup script is designed for Debian/Ubuntu/Kali Linux"
    echo "    For other systems, manually install the requirements.txt"
fi

# Install system deps
echo "[1/4] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    python3 python3-pip python3-venv \
    dnsutils whois curl git \
    2>/dev/null || true

# Install Python packages
echo "[2/4] Installing Python packages..."
pip3 install -r requirements.txt --break-system-packages --quiet

# Set up .env file
echo "[3/4] Setting up environment..."
if [ ! -f ../.env ]; then
    cp ../.env.example ../.env
    echo "      [!] .env file created — add your API keys:"
    echo "          nano ../.env"
else
    echo "      [✓] .env file already exists"
fi

# Verify tools
echo "[4/4] Verifying tool installation..."
cd ..
python3 -c "import requests, dns.resolver, bs4; print('      [✓] Core imports OK')"

echo ""
echo "████████████████████████████████████████████████████████"
echo "  Setup complete! Run your first analysis:"
echo ""
echo "  python3 tools/header_analyzer.py samples/urgent_invoice.eml"
echo "  ./run_full_analysis.sh samples/urgent_invoice.eml"
echo "████████████████████████████████████████████████████████"
echo ""
