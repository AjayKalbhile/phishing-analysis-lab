# 🤝 Contributing to Phishing Analysis Lab

Thank you for your interest in contributing! This project welcomes:

- New sanitized phishing `.eml` samples
- Improvements to the Python analysis tools
- Additional methodology documentation
- Bug fixes and tool enhancements

---

## How to Contribute

### 1. Fork & Clone

```bash
git clone https://github.com/yourusername/phishing-analysis-lab.git
cd phishing-analysis-lab
```

### 2. Create a Branch

```bash
git checkout -b feature/my-improvement
# or
git checkout -b fix/bug-description
```

### 3. Make Your Changes

- Follow the existing code style (PEP 8)
- Add docstrings to new functions
- Test your changes with at least one `.eml` sample

### 4. Submit a Pull Request

- Describe what you changed and why
- Include sanitized test samples if adding new features
- Reference any related issues

---

## Sample Submission Guidelines

When submitting phishing `.eml` samples:

- **Sanitize all real infrastructure:** Replace real malicious domains with `.example.com`
- **Defang all URLs:** Replace `http` with `hxxp` in body text
- **Remove PII:** Replace real victim email addresses with generic ones
- **Keep authentication headers intact:** SPF/DKIM/DMARC headers are the analysis value
- **Add a comment at the top** with: date, campaign type, brand impersonated

---

## Code Standards

- Python 3.8+ compatible
- No hardcoded API keys (use `.env` / `os.environ`)
- All tools must accept `--email` or positional argument for the `.eml` path
- Tools should save output JSON alongside the input file by default

---

## Reporting Issues

Open an issue with:
- Which tool failed
- The command you ran
- The error message
- Your Python version (`python3 --version`)
