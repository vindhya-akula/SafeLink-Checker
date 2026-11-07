
import ipaddress
import re
from urllib.parse import urlsplit


# Known URL shortening services
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at"
}


# Words sometimes used in phishing URLs
SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "secure",
    "account",
    "password",
    "update",
    "banking",
    "wallet",
    "bonus",
    "free",
    "gift",
    "claim",
    "signin"
}


def analyze_url(url: str):

    parsed = urlsplit(url)

    hostname = parsed.hostname or ""

    findings = []

    risk_score = 0

    # Helper function to add findings
    def add_finding(name, description, points):

        nonlocal risk_score

        risk_score += points

        findings.append({
            "name": name,
            "description": description,
            "risk_points": points
        })

    # 1. Check HTTPS
    if parsed.scheme != "https":

        add_finding(
            "Insecure connection",
            "The URL does not use HTTPS.",
            15
        )

    # 2. Check whether hostname is an IP address
    try:

        ipaddress.ip_address(hostname)

        add_finding(
            "IP-based URL",
            "The hostname is an IP address.",
            20
        )

    except ValueError:
        pass

    # 3. Check @ symbol
    if "@" in url:

        add_finding(
            "URL contains @ symbol",
            "The URL contains an @ symbol that can obscure the destination.",
            20
        )

    # 4. Check excessive subdomains
    if len(hostname.split(".")) > 4:

        add_finding(
            "Excessive subdomains",
            "The hostname contains many subdomain levels.",
            15
        )

    # 5. Check unusually long URLs
    if len(url) > 100:

        add_finding(
            "Long URL",
            "The URL is unusually long.",
            10
        )

    # 6. Check URL shorteners
    if hostname.lower() in SHORTENERS:

        add_finding(
            "URL shortener",
            "The URL uses a known shortening service.",
            15
        )

    # 7. Check suspicious keywords
    searchable_text = (
        hostname + " " + (parsed.path or "")
    ).lower()

    matched_keywords = [
        word
        for word in SUSPICIOUS_KEYWORDS
        if re.search(
            rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])",
            searchable_text
        )
    ]

    if matched_keywords:

        add_finding(
            "Suspicious keywords",
            "Potentially misleading words detected: "
            + ", ".join(sorted(matched_keywords)),
            min(20, len(matched_keywords) * 5)
        )

    # Limit score to 100
    risk_score = min(risk_score, 100)

    # Determine risk level
    if risk_score >= 60:

        risk_level = "High Risk"

    elif risk_score >= 30:

        risk_level = "Medium Risk"

    else:

        risk_level = "Low Risk"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": findings
    }
