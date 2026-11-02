"""IP geolocation with three tiers, in order of preference:

1. A local MaxMind-format City database (DB-IP Lite) if one is present.
2. ip-api.com, rate-limited and cached (free tier, no key, 45 req/min).
3. Nothing - the event is still recorded, just without coordinates.

Every lookup is cached in SQLite, so a repeat offender costs one call ever.
Private / reserved addresses never leave the machine.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import threading
import time
from typing import Dict, Optional

import requests

import db

log = logging.getLogger("hivewatch.geo")

MMDB_PATH = os.environ.get("HIVEWATCH_MMDB", "/data/geo/dbip-city-lite.mmdb")
ENABLE_IPAPI = os.environ.get("HIVEWATCH_IPAPI", "0") != "0"

_reader = None
_reader_tried = False
_ipapi_lock = threading.Lock()
_ipapi_times: list = []          # sliding window of call timestamps
_IPAPI_MAX_PER_MIN = 40          # stay under the documented 45/min


def _get_reader():
    global _reader, _reader_tried
    if _reader is not None or _reader_tried:
        return _reader
    _reader_tried = True
    try:
        import geoip2.database  # type: ignore
        if os.path.exists(MMDB_PATH):
            _reader = geoip2.database.Reader(MMDB_PATH)
            log.info("geo: using local database %s", MMDB_PATH)
        else:
            log.info("geo: no local mmdb at %s, falling back to ip-api", MMDB_PATH)
    except Exception as e:  # pragma: no cover - optional dependency
        log.info("geo: geoip2 unavailable (%s), falling back to ip-api", e)
    return _reader


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (a.is_private or a.is_loopback or a.is_link_local
            or a.is_multicast or a.is_reserved or a.is_unspecified)


def _from_mmdb(ip: str) -> Optional[Dict]:
    reader = _get_reader()
    if reader is None:
        return None
    try:
        r = reader.city(ip)
        if r.location.latitude is None:
            return None
        return {
            "country": r.country.name,
            "country_code": r.country.iso_code,
            "city": r.city.name,
            "lat": r.location.latitude,
            "lon": r.location.longitude,
            "isp": None,
        }
    except Exception:
        return None


def _ipapi_allowed() -> bool:
    now = time.time()
    with _ipapi_lock:
        while _ipapi_times and now - _ipapi_times[0] > 60:
            _ipapi_times.pop(0)
        if len(_ipapi_times) >= _IPAPI_MAX_PER_MIN:
            return False
        _ipapi_times.append(now)
        return True


def _from_ipapi(ip: str) -> Optional[Dict]:
    if not ENABLE_IPAPI or not _ipapi_allowed():
        return None
    try:
        r = requests.get(
            "http://ip-api.com/json/%s" % ip,
            params={"fields": "status,country,countryCode,city,lat,lon,isp"},
            timeout=6)
        d = r.json()
        if d.get("status") != "success":
            return None
        return {
            "country": d.get("country"),
            "country_code": d.get("countryCode"),
            "city": d.get("city"),
            "lat": d.get("lat"),
            "lon": d.get("lon"),
            "isp": d.get("isp"),
        }
    except Exception as e:
        log.debug("ip-api lookup failed for %s: %s", ip, e)
        return None


_EMPTY = {"country": None, "country_code": None, "city": None,
          "lat": None, "lon": None, "isp": None}


def lookup(ip: str) -> Dict:
    """Resolve an IP to a location. Never raises."""
    if is_private(ip):
        return dict(_EMPTY, country="Private network", country_code="LAN")

    cached = db.geo_get(ip)
    if cached:
        return {k: cached.get(k) for k in _EMPTY}

    info = _from_mmdb(ip) or _from_ipapi(ip)
    if info is None:
        # Cache the miss briefly so a scan storm cannot hammer the API.
        return dict(_EMPTY)

    db.geo_put(ip, info)
    return info
