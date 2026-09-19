# Phishing URL Detector

A rule-based Python tool that checks URLs for common phishing red flags and gives a risk score: LOW, MEDIUM, or HIGH.

## What It Checks

- IP address used instead of a domain name
- `@` symbol hiding the real destination
- URL shorteners (bit.ly, tinyurl, etc.)
- Suspicious keywords (login, verify, secure, etc.)
- Brand impersonation (e.g. paypa1.com)
- Missing HTTPS
- Excessive subdomains

## Usage

```bash
python phishing_url_detector.py
```

Paste a URL when prompted. The tool prints the findings and a risk level.

## Example

URL analyzed: http://192.168.1.1/paypal-login-verify
Risk level : HIGH (score: 8)
Findings:

Domain is a raw IP address instead of a name
Contains suspicious keywords: login, verify
Possible brand impersonation: paypal

## Disclaimer

Educational tool only — rule-based, not machine learning or live threat intel. Don't rely on it alone to judge if a link is safe.

## Built With

Python 3, `re`, `urllib.parse`
