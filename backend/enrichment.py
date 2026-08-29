"""SentinelAI IP Enrichment — AbuseIPDB reputation + ip-api.com geolocation.

This module provides two enrichment functions for IP addresses:

  1. get_ip_reputation(ip)  — AbuseIPDB /check endpoint  (API key required)
  2. get_geolocation(ip)    — ip-api.com free endpoint    (no key needed)

Both functions are async-safe (use httpx) and include:
  - In-memory caching keyed by IP  (avoid duplicate API calls)
  - Graceful failure  (return "unavailable" dict, never crash the pipeline)
  - Rate-limit awareness  (explicit throttle sleeps)

IMPORTANT — Simulated IPs for NSL-KDD replay:
    NSL-KDD data does NOT contain real IP addresses.  For replay/demo purposes
    we derive a deterministic, plausible-looking IP from the event's feature
    hash.  These IPs are clearly labelled "simulated" in the output.  Phase 14
    (live capture) will provide genuinely real source IPs.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from typing import Any

import httpx
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Load backend/.env (same pattern as agents/.env for GROQ_API_KEY)
load_dotenv()

ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")

# Rate-limit guards  (timestamps of last call)
_last_abuseipdb_call: float = 0.0
_last_ipapi_call: float = 0.0

# Minimum interval between calls (seconds)
_ABUSEIPDB_MIN_INTERVAL: float = 0.1   # 1000/day ≈ 1 every 86s, but bursty is fine
_IPAPI_MIN_INTERVAL: float = 1.4       # ip-api.com: 45 req/min ≈ 1 every 1.33s

# In-memory caches  (IP → result dict)
_reputation_cache: dict[str, dict[str, Any]] = {}
_geolocation_cache: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Simulated IP generation for NSL-KDD events
# ---------------------------------------------------------------------------

def generate_simulated_ip(raw_event: dict[str, Any]) -> str:
    """Derive a deterministic, plausible-looking IP from an event's features.

    Uses a SHA-256 hash of the event's key numeric fields to produce four
    octets.  The same event always maps to the same IP.  These are clearly
    labelled as 'simulated' throughout the pipeline.

    We bias toward routable-looking IPs by avoiding 0.x.x.x, 127.x.x.x,
    and 10.x.x.x private ranges for a more realistic demo.
    """
    # Build a stable fingerprint from event fields
    fingerprint_fields = [
        "duration", "protocol_type", "service", "flag",
        "src_bytes", "dst_bytes", "count", "srv_count",
        "dst_host_count", "dst_host_srv_count",
    ]
    fingerprint = "|".join(str(raw_event.get(f, "")) for f in fingerprint_fields)
    digest = hashlib.sha256(fingerprint.encode()).digest()

    # Map 4 bytes to octets, ensuring routable-looking IPs
    octets = [
        max(11, min(223, digest[0])),   # First octet: 11-223 (skip private/loopback)
        digest[1] % 256,
        digest[2] % 256,
        max(1, digest[3] % 255),        # Last octet: 1-254
    ]

    return f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}"


# ---------------------------------------------------------------------------
# AbuseIPDB reputation lookup
# ---------------------------------------------------------------------------

async def get_ip_reputation(ip: str) -> dict[str, Any]:
    """Query AbuseIPDB for an IP's abuse confidence score.

    Returns a dict with keys:
        ip, abuse_confidence_score, total_reports, country_code,
        isp, domain, usage_type, is_whitelisted, source

    On failure, returns a dict with source="unavailable" and error details.
    """
    global _last_abuseipdb_call

    # Check cache first
    if ip in _reputation_cache:
        return _reputation_cache[ip]

    # No API key → can't query
    if not ABUSEIPDB_API_KEY:
        result: dict[str, Any] = {
            "ip": ip,
            "abuse_confidence_score": None,
            "total_reports": None,
            "country_code": None,
            "isp": None,
            "source": "unavailable",
            "error": "ABUSEIPDB_API_KEY not set",
        }
        _reputation_cache[ip] = result
        return result

    # Rate-limit throttle
    now = time.monotonic()
    wait = _ABUSEIPDB_MIN_INTERVAL - (now - _last_abuseipdb_call)
    if wait > 0:
        await asyncio.sleep(wait)
    _last_abuseipdb_call = time.monotonic()

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={
                    "Key": ABUSEIPDB_API_KEY,
                    "Accept": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

            result = {
                "ip": ip,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "usage_type": data.get("usageType", ""),
                "is_whitelisted": data.get("isWhitelisted", False),
                "source": "abuseipdb",
            }
            _reputation_cache[ip] = result
            print(f"  [enrichment] AbuseIPDB: {ip} -> "
                  f"abuse={result['abuse_confidence_score']}% "
                  f"reports={result['total_reports']} "
                  f"country={result['country_code']}")
            return result

    except Exception as exc:
        print(f"  [enrichment] AbuseIPDB error for {ip}: {exc}")
        result = {
            "ip": ip,
            "abuse_confidence_score": None,
            "total_reports": None,
            "country_code": None,
            "isp": None,
            "source": "unavailable",
            "error": str(exc),
        }
        _reputation_cache[ip] = result
        return result


# ---------------------------------------------------------------------------
# ip-api.com geolocation lookup
# ---------------------------------------------------------------------------

async def get_geolocation(ip: str) -> dict[str, Any]:
    """Query ip-api.com for geolocation data.

    Returns a dict with keys:
        ip, country, country_code, city, region, lat, lon, isp, org,
        timezone, source

    On failure, returns a dict with source="unavailable".
    """
    global _last_ipapi_call

    # Check cache first
    if ip in _geolocation_cache:
        return _geolocation_cache[ip]

    # Rate-limit throttle (45 req/min for ip-api.com)
    now = time.monotonic()
    wait = _IPAPI_MIN_INTERVAL - (now - _last_ipapi_call)
    if wait > 0:
        await asyncio.sleep(wait)
    _last_ipapi_call = time.monotonic()

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,regionName,city,lat,lon,isp,org,timezone"},
            )
            resp.raise_for_status()
            data = resp.json()

            if data.get("status") == "fail":
                raise ValueError(f"ip-api.com: {data.get('message', 'unknown error')}")

            result: dict[str, Any] = {
                "ip": ip,
                "country": data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "city": data.get("city", ""),
                "region": data.get("regionName", ""),
                "lat": data.get("lat", 0.0),
                "lon": data.get("lon", 0.0),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "timezone": data.get("timezone", ""),
                "source": "ip-api.com",
            }
            _geolocation_cache[ip] = result
            print(f"  [enrichment] Geolocation: {ip} -> "
                  f"{result['city']}, {result['country']} "
                  f"({result['lat']}, {result['lon']})")
            return result

    except Exception as exc:
        print(f"  [enrichment] Geolocation error for {ip}: {exc}")
        result = {
            "ip": ip,
            "country": None,
            "country_code": None,
            "city": None,
            "region": None,
            "lat": None,
            "lon": None,
            "isp": None,
            "source": "unavailable",
            "error": str(exc),
        }
        _geolocation_cache[ip] = result
        return result


# ---------------------------------------------------------------------------
# Combined enrichment (convenience wrapper)
# ---------------------------------------------------------------------------

async def enrich_ip(raw_event: dict[str, Any], *, real_ip: str | None = None) -> dict[str, Any]:
    """Run both reputation and geolocation lookups for an event's source IP.

    Parameters
    ----------
    raw_event : dict
        The NSL-KDD feature dict.  Used to derive a simulated IP when
        *real_ip* is not provided.
    real_ip : str | None
        If provided, this is a genuine source IP (e.g. from live capture).
        If None, a simulated IP is generated from the event features.

    Returns
    -------
    dict with keys: ip, ip_type ("simulated"|"real"), reputation, geolocation
    """
    if real_ip:
        ip = real_ip
        ip_type = "real"
    else:
        ip = generate_simulated_ip(raw_event)
        ip_type = "simulated"

    # Run both lookups concurrently (respecting individual throttles)
    reputation, geolocation = await asyncio.gather(
        get_ip_reputation(ip),
        get_geolocation(ip),
    )

    return {
        "ip": ip,
        "ip_type": ip_type,
        "reputation": reputation,
        "geolocation": geolocation,
    }
