import os
import requests
import time
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")

PHISHING_DOMAINS_URL = (
    "https://raw.githubusercontent.com/"
    "Phishing-Database/Phishing.Database/"
    "master/phishing-domains-ACTIVE.txt"
)

PHISHING_LINKS_URL = (
    "https://raw.githubusercontent.com/"
    "Phishing-Database/Phishing.Database/"
    "master/phishing-links-ACTIVE.txt"
)


CACHE_DURATION = 60 * 60  # 1 hour


domain_cache = {
    "data": set(),
    "updated": 0
}

link_cache = {
    "data": set(),
    "updated": 0
}


def download_feed(feed_url):
    try:

        response = requests.get(
            feed_url,
            timeout=20
        )

        response.raise_for_status()

        return {
            line.strip().lower()
            for line in response.text.splitlines()
            if line.strip()
            and not line.startswith("#")
        }

    except requests.RequestException as error:

        print(
            f"Threat intelligence download failed: {error}"
        )

        return set()


def get_domains():

    current_time = time.time()

    if (
        domain_cache["data"]
        and current_time - domain_cache["updated"]
        < CACHE_DURATION
    ):
        return domain_cache["data"]

    print("Updating Phishing.Database domain feed...")

    data = download_feed(PHISHING_DOMAINS_URL)

    if data:

        domain_cache["data"] = data
        domain_cache["updated"] = current_time

        print(
            f"Loaded {len(data)} phishing domains"
        )

    return domain_cache["data"]


def get_links():

    current_time = time.time()

    if (
        link_cache["data"]
        and current_time - link_cache["updated"]
        < CACHE_DURATION
    ):
        return link_cache["data"]

    print("Updating Phishing.Database URL feed...")

    data = download_feed(PHISHING_LINKS_URL)

    if data:

        link_cache["data"] = data
        link_cache["updated"] = current_time

        print(
            f"Loaded {len(data)} phishing URLs"
        )

    return link_cache["data"]


def check_phishing_database(url):

    parsed = urlparse(url)

    hostname = (
        parsed.hostname or ""
    ).lower()

    normalized_url = url.rstrip("/").lower()

    domains = get_domains()

    links = get_links()

    signals = []

    # Exact URL match
    if normalized_url in links:

        signals.append({
            "source": "phishing_database",
            "name": "URL found in Phishing.Database",
            "severity": "critical"
        })

    # Exact domain match
    if hostname in domains:

        signals.append({
            "source": "phishing_database",
            "name": "Domain found in Phishing.Database",
            "severity": "critical"
        })

    return {
        "found": len(signals) > 0,
        "signals": signals
    }

def test_urlhaus_auth():

    if not URLHAUS_AUTH_KEY:
        print("❌ URLHAUS_AUTH_KEY not found")
        return

    print("🔑 URLhaus key loaded successfully")
    print("Key length:", len(URLHAUS_AUTH_KEY))

def check_urlhaus(url):

    if not URLHAUS_AUTH_KEY:
        print("URLhaus API key not configured")

        return {
            "found": False,
            "available": False,
            "signals": []
        }

    try:

        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={
                "url": url
            },
            headers={
                "Auth-Key": URLHAUS_AUTH_KEY
            },
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

        query_status = data.get("query_status")

        if query_status == "ok":

            return {
                "found": True,
                "available": True,
                "signals": [
                    {
                        "source": "urlhaus",
                        "name": "URL found in URLhaus",
                        "severity": "critical"
                    }
                ]
            }

        if query_status == "no_results":

            return {
                "found": False,
                "available": True,
                "signals": []
            }

        print(
            "Unexpected URLhaus status:",
            query_status
        )

        return {
            "found": False,
            "available": True,
            "signals": []
        }

    except requests.RequestException as error:

        print(
            "URLhaus request failed:",
            error
        )

        return {
            "found": False,
            "available": False,
            "signals": []
        }


def check_phishdetect(url):

    try:

        response = requests.post(
            "http://127.0.0.1:5003/analyze",
            json={
                "url": url
            },
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        return {
            "available": True,
            "score": data.get("score", 0),
            "safelisted": data.get("safelisted", False),
            "brand": data.get("brand", ""),
            "warnings": data.get("warnings", [])
        }

    except requests.RequestException as error:

        print(
            "PhishDetect request failed:",
            error
        )

        return {
            "available": False,
            "score": 0,
            "safelisted": False,
            "brand": "",
            "warnings": []
        }