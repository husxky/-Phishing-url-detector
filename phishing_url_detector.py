#!/usr/bin/env python3
"""
Phishing URL Detector
-----------------------
A beginner-friendly cybersecurity project that analyzes a URL for common
signs of phishing, using rule-based heuristics (no external API needed).

⚠️ Educational tool only. This uses simple heuristics, not machine learning
or live threat intelligence, so it WILL have false positives/negatives.
Do not rely on this alone to decide if a link is safe.

Usage:
    python phishing_url_detector.py
    (then paste a URL when prompted)
"""

import re
from urllib.parse import urlparse


# A short list of well-known shortener domains (not exhaustive)
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rb.gy", "cutt.ly", "shorte.st"
]

# A tiny sample of commonly-spoofed brand names (not exhaustive)
COMMON_BRANDS = [
    "paypal", "google", "facebook", "apple", "amazon",
    "microsoft", "netflix", "instagram", "whatsapp", "bank"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "confirm", "signin", "banking", "password"
]


def has_ip_address(url: str) -> bool:
    """Check if the domain is a raw IP address instead of a name."""
    domain = urlparse(url).netloc.split(":")[0]
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(ip_pattern, domain))


def has_at_symbol(url: str) -> bool:
    """The '@' symbol in a URL makes browsers ignore everything before it —
    a classic trick to disguise the real destination."""
    return "@" in url


def is_shortened(url: str) -> bool:
    domain = urlparse(url).netloc.lower()
    return any(shortener in domain for shortener in URL_SHORTENERS)


def is_too_long(url: str, threshold: int = 75) -> bool:
    """Phishing URLs are often unusually long to obscure the real domain."""
    return len(url) > threshold


def has_suspicious_keywords(url: str) -> list:
    url_lower = url.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]


def has_brand_impersonation(url: str) -> list:
    """
    Flags cases where a brand name appears in the URL but NOT as the actual
    registered domain — e.g. 'paypal-login-secure.com' or 'paypa1.com'
    instead of the real 'paypal.com'.
    """
    domain = urlparse(url).netloc.lower()
    flagged = []
    for brand in COMMON_BRANDS:
        if brand in url.lower() and brand not in domain.replace("-", ""):
            flagged.append(brand)
        # crude lookalike check: brand with a digit swapped in (e.g. paypa1)
        elif re.search(brand[:-1] + r"[0-9]", domain):
            flagged.append(brand + " (lookalike)")
    return flagged


def uses_https(url: str) -> bool:
    return urlparse(url).scheme == "https"


def has_excessive_subdomains(url: str, threshold: int = 3) -> bool:
    """Too many subdomains can be used to bury the real domain, e.g.
    'paypal.com.verify-login.example-site.net'."""
    domain = urlparse(url).netloc
    return domain.count(".") >= threshold


def analyze_url(url: str) -> dict:
    """
    Run all checks on a URL and return a report dict with
    a risk score and the specific findings.
    """
    findings = []
    score = 0

    if has_ip_address(url):
        findings.append("Domain is a raw IP address instead of a name")
        score += 3

    if has_at_symbol(url):
        findings.append("URL contains '@' symbol (can hide real destination)")
        score += 3

    if is_shortened(url):
        findings.append("URL uses a link shortener (real destination is hidden)")
        score += 2

    if is_too_long(url):
        findings.append("URL is unusually long")
        score += 1

    keywords = has_suspicious_keywords(url)
    if keywords:
        findings.append(f"Contains suspicious keywords: {', '.join(keywords)}")
        score += len(keywords)

    brands = has_brand_impersonation(url)
    if brands:
        findings.append(f"Possible brand impersonation: {', '.join(brands)}")
        score += 3 * len(brands)

    if not uses_https(url):
        findings.append("Does not use HTTPS")
        score += 1

    if has_excessive_subdomains(url):
        findings.append("Unusually many subdomains (can bury the real domain)")
        score += 2

    # Simple risk banding — thresholds are illustrative, not scientific
    if score >= 6:
        risk = "HIGH"
    elif score >= 3:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {"url": url, "score": score, "risk": risk, "findings": findings}


def print_report(report: dict):
    print("\n" + "=" * 55)
    print(f"URL analyzed: {report['url']}")
    print(f"Risk level  : {report['risk']}  (score: {report['score']})")
    print("-" * 55)
    if report["findings"]:
        print("Findings:")
        for f in report["findings"]:
            print(f"  - {f}")
    else:
        print("No suspicious signals detected in this simple ruleset.")
    print("=" * 55)


def main():
    print("=" * 55)
    print(" Phishing URL Detector (rule-based, educational)")
    print(" Not a substitute for real threat intelligence.")
    print("=" * 55)

    while True:
        url = input("\nEnter a URL to check (or 'q' to quit): ").strip()
        if url.lower() == "q":
            break
        if not url:
            continue
        if not url.startswith(("http://", "https://")):
            url = "http://" + url  # allow bare domains like "example.com"

        report = analyze_url(url)
        print_report(report)


if __name__ == "__main__":
    main()