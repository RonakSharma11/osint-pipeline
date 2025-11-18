# enricher/geoip_enricher.py
"""
GeoIP enricher: uses MaxMind GeoLite2-City.mmdb (local) if available; otherwise uses sample_data/sample_geoip.json in DEMO_MODE.
Uses maxminddb library (fast, no HTTP required).
Caches lookups to avoid repeated disk reads.
"""
import os
import json
import logging
from utils.config import Config
from utils.cache import Cache

logger = logging.getLogger("enricher.geoip")
cache = Cache()

SAMPLE_PATH = "sample_data/sample_geoip.json"

def enrich_geoip(ip, use_cache=True, ttl=60*60*24):
    """
    Returns a dict: {city, country, location: {lat,lon}, asn, org} or {} on failure.
    """
    if not ip:
        return {}

    key = f"geoip:{ip}"
    if use_cache:
        cached = cache.get(key)
        if cached:
            return cached

    # Demo / no DB fallback
    if Config.DEMO_MODE or not os.path.exists(Config.GEOIP_DB_PATH):
        if os.path.exists(SAMPLE_PATH):
            try:
                with open(SAMPLE_PATH, "r") as f:
                    sample = json.load(f)
                res = sample.get(ip, {})
                cache.set(key, res, ttl=ttl)
                logger.debug("GeoIP (demo) for %s -> %s", ip, bool(res))
                return res
            except Exception as e:
                logger.exception("Failed reading sample geoip: %s", e)
                return {}

    # Try to use maxminddb
    try:
        import maxminddb
        with maxminddb.open_database(Config.GEOIP_DB_PATH) as reader:
            rec = reader.get(ip)
            if not rec:
                cache.set(key, {}, ttl=ttl)
                return {}
            city = rec.get("city", {}).get("names", {}).get("en")
            country = rec.get("country", {}).get("names", {}).get("en")
            loc = rec.get("location", {})
            asn = rec.get("traits", {}).get("autonomous_system_number")
            org = rec.get("traits", {}).get("autonomous_system_organization")
            out = {
                "city": city,
                "country": country,
                "location": {"lat": loc.get("latitude"), "lon": loc.get("longitude")} if loc else None,
                "asn": asn,
                "org": org
            }
            cache.set(key, out, ttl=ttl)
            logger.info("GeoIP lookup for %s -> %s/%s", ip, country, city)
            return out
    except Exception as e:
        logger.exception("GeoIP lookup error for %s: %s", ip, e)
        return {}
