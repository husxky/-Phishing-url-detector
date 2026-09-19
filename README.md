#Phishing URL Detector

A rule-based Python tool that analyzes URLs for common phishing indicators — IP-based domains, brand impersonation, URL shorteners, suspicious keywords, and more — and returns a risk score (Low / Medium / High).

Why I Built This

Phishing is one of the most common real-world cyber threats, and email/browser security tools use heuristic-based URL analysis as a first line of defense before deeper threat intelligence kicks in. I wanted to understand and build that logic myself — identifying the actual structural red flags that make a URL suspicious, rather than relying on a pre-built blocklist.

Features
Detects IP addresses used in place of a domain name
Flags @ symbols in URLs (used to disguise the real destination)
Identifies known URL shorteners (bit.ly, tinyurl, etc.)
Flags unusually long URLs
Detects suspicious keywords (login, verify, secure, account, etc.)
Flags possible brand impersonation (e.g. paypal-secure-login.net, paypa1.com)
Checks for missing HTTPS
Flags excessive subdomains used to bury the real domain
Calculates a risk score and classifies the URL as LOW, MEDIUM, or HIGH risk
How It Works

Each URL is run through a series of independent checks. Every red flag found adds points to a risk score:

Signal	Points
IP address as domain	+3
@ symbol in URL	+3
Brand impersonation	+3 per brand
URL shortener	+2
Excessive subdomains	+2
Long URL (>75 chars)	+1
Suspicious keyword	+1 per keyword
No HTTPS	+1

Score → Risk Level

6+ → HIGH
3–5 → MEDIUM
0–2 → LOW
Usage
bash
python phishing_url_detector.py

You'll be prompted to enter a URL. The tool prints a report showing the risk level, score, and the specific findings. Enter q to quit.

Example Output
Enter a URL to check (or 'q' to quit): http://192.168.1.1/paypal-login-verify

=======================================================
URL analyzed: http://192.168.1.1/paypal-login-verify
Risk level  : HIGH  (score: 8)
-------------------------------------------------------
Findings:
  - Domain is a raw IP address instead of a name
  - Contains suspicious keywords: login, verify
  - Possible brand impersonation: paypal
=======================================================
⚠️ Disclaimer

This is an educational, rule-based tool — not a production security product. It does not use machine learning or live threat intelligence, so it will have false positives and false negatives. Do not rely on it alone to decide whether a link is safe. For real protection, use established tools (browser Safe Browsing, VirusTotal, dedicated email security filters) alongside general caution.

Built With
Python 3
re (regex, standard library)
urllib.parse (standard library)
Possible Future Improvements
Integrate a real threat intelligence API (e.g. VirusTotal, PhishTank) for live verification
Expand the brand and keyword lists
Add a simple GUI or web interface
Log scan history to a file
Replace fixed scoring thresholds with a trained ML classifier
