from .features import extract_url_features

from .threat_intel import (
    check_phishing_database,
    check_urlhaus,
    check_phishdetect
)


def analyze_url(url):

    # ---------------------------------
    # Basic URL features
    # ---------------------------------

    features = extract_url_features(url)

    # ---------------------------------
    # Threat intelligence
    # ---------------------------------

    phishing_database = check_phishing_database(url)

    urlhaus = check_urlhaus(url)
    phishdetect = check_phishdetect(url)

    # ---------------------------------
    # Initial score
    # ---------------------------------

    score = 0

    signals = []

    # ---------------------------------
    # HTTPS
    # ---------------------------------

    if not features["https"]:

        score += 15

        signals.append({
            "source": "heuristic",
            "name": "No HTTPS",
            "severity": "medium"
        })

    # ---------------------------------
    # IP address
    # ---------------------------------

    if features["has_ip"]:

        score += 30

        signals.append({
            "source": "heuristic",
            "name": "IP address used as hostname",
            "severity": "high"
        })

    # ---------------------------------
    # @ symbol
    # ---------------------------------

    if features["has_at_symbol"]:

        score += 25

        signals.append({
            "source": "heuristic",
            "name": "@ symbol found in URL",
            "severity": "high"
        })

    # ---------------------------------
    # URL shortener
    # ---------------------------------

    if features["is_shortened"]:

        score += 20

        signals.append({
            "source": "heuristic",
            "name": "URL shortener detected",
            "severity": "medium"
        })

    # ---------------------------------
    # Subdomains
    # ---------------------------------

    if features["subdomain_count"] > 2:

        score += 15

        signals.append({
            "source": "heuristic",
            "name": "Unusually high number of subdomains",
            "severity": "medium"
        })

    # ---------------------------------
    # Suspicious words
    # ---------------------------------

    if features["suspicious_words"]:

        score += 10

        signals.append({
            "source": "heuristic",
            "name": "Suspicious security/account keywords",
            "severity": "medium"
        })

    # ---------------------------------
    # Phishing.Database
    # ---------------------------------

    if phishing_database["found"]:

        score += 70

        signals.extend(
            phishing_database["signals"]
        )

    # ---------------------------------
    # URLhaus
    # ---------------------------------

    if phishdetect["available"]:
        score += int(phishdetect["score"] * 0.30)
    if urlhaus["found"]:

        score += 70


        signals.extend(
            urlhaus["signals"]
        )

    

    # ---------------------------------
    # Maximum score
    # ---------------------------------

    score = min(score, 100)

    # ---------------------------------
    # Verdict
    # ---------------------------------

    if score >= 70:

        verdict = "HIGH_RISK"

    elif score >= 40:

        verdict = "SUSPICIOUS"

    else:

        verdict = "LOW_RISK"

    # ---------------------------------
    # Final response
    # ---------------------------------

    return {

        "score": score,

        "verdict": verdict,

        "signals": signals,

        "features": features,

        "threat_intelligence": {
            "phishing_database": phishing_database["found"],
            "urlhaus": urlhaus["found"],
            "urlhaus_available": urlhaus["available"],
            "phishdetect": phishdetect
        }

    }