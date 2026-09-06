from urllib.parse import urlparse
import ipaddress
import re


def extract_url_features(url):
    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    features = {
        "https": parsed.scheme.lower() == "https",
        "has_ip": False,
        "has_at_symbol": "@" in url,
        "subdomain_count": 0,
        "suspicious_words": [],
        "is_shortened": False,
        "hostname": hostname
    }

    # Check whether hostname is an IP address
    try:
        ipaddress.ip_address(hostname)
        features["has_ip"] = True
    except ValueError:
        pass

    # Count subdomains
    if hostname:
        features["subdomain_count"] = max(0, len(hostname.split(".")) - 2)

    # Suspicious keywords
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "signin",
        "confirm"
    ]

    url_lower = url.lower()

    for word in suspicious_words:
        if word in url_lower:
            features["suspicious_words"].append(word)

    # URL shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "short.link",
        "t.co",
        "goo.gl"
    ]

    if hostname.lower() in shorteners:
        features["is_shortened"] = True

    return features