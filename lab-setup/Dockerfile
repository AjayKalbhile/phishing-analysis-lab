FROM python:3.11-slim

LABEL maintainer="Phishing Analysis Lab"
LABEL description="Containerized phishing email analysis environment"

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y \
    dnsutils \
    whois \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY lab-setup/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Default command: show usage
CMD ["python3", "tools/threat_report_generator.py", "--help"]
