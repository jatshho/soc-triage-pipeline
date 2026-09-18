import os
import json
import time
import requests

CACHE_PATH = "enrichment/cache.json"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def _load_cache():
    try:
        with open(CACHE_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def _save_cache(cache):
    with open(CACHE_PATH, "w") as f:
        json.dump(cache, f, indent=2)

def check_ip_reputation(ip, max_age_days=90):
    """Look up an IP against AbuseIPDB, with a local on-disk cache to avoid
    burning API quota on repeat lookups during development/demos."""
    cache = _load_cache()
    if ip in cache:
        return cache[ip]

    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        result = {"ip": ip, "error": "no_api_key", "abuse_score": None}
        cache[ip] = result
        _save_cache(cache)
        return result

    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        result = {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports"),
            "checked_at": time.time(),
        }
    except requests.RequestException as e:
        result = {"ip": ip, "error": str(e), "abuse_score": None}

    cache[ip] = result
    _save_cache(cache)
    return result

def enrich_findings(findings):
    for f in findings:
        if f.get("src_ip"):
            f["threat_intel"] = check_ip_reputation(f["src_ip"])
    return findings
