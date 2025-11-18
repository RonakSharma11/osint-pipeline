# enricher/whois_enricher.py
"""
WHOIS enricher: returns registrar, creation/expiration dates, registrant/org and raw text.
Uses python-whois for live lookups, falls back to sample_data/sample_whois.json in DEMO_MODE
Cache: caches results using utils.cache.Cache to avoid repetition.
"""
import os
import json
import logging
from datetime import datetime

from utils.config import Config
from utils.cache import Cache

logger = logging.getLogger("enricher.whois")
cache = Cache()

SAMPLE_PATH = "sample_data/sample_whois.json"

def _normalize_whois_obj(w):
    """Normalize python-whois output into serializable dict."""
    out = {}
    try:
        out["registrar"] = getattr(w, "registrar", None)
        # creation_date/expiration_date can be list or datetime
        cd = getattr(w, "creation_date", None)
        ed = getattr(w, "expiration_date", None)
        def _fmt(d):
            if not d:
                return None
            if isinstance(d, (list, tuple)):
                d = d[0]
            if hasattr(d, "isoformat"):
                return d.isoformat()
            return str(d)
        out["creation_date"] = _fmt(cd)
        out["expiration_date"] = _fmt(ed)
        out["registrant"] = getattr(w, "org", None) or getattr(w, "name", None)
        out["name_servers"] = getattr(w, "name_servers", None)
        out["raw"] = getattr(w, "text", "") or str(w)
    except Exception as e:
        logger.exception("Error normalizing whois object: %s", e)
    return out

def enrich_whois(domain, use_cache=True, ttl=60*60*24):
    """
    Enrich a domain with WHOIS data.
    Returns dict (possibly empty) with keys registrar, creation_date, expiration_date, registrant, raw.
    """
    domain = (domain or "").lower().strip()
    if not domain:
        return {}

    key = f"whois:{domain}"
    if use_cache:
        cached = cache.get(key)
        if cached:
            return cached

    # DEMO mode -> read from sample file
    if Config.DEMO_MODE or not Config.ALLOW_PUBLIC_FETCH:
        if os.path.exists(SAMPLE_PATH):
            try:
                with open(SAMPLE_PATH, "r") as f:
                    sample = json.load(f)
                res = sample.get(domain, {})
                cache.set(key, res, ttl=ttl)
                logger.debug("WHOIS (demo) for %s -> %s", domain, bool(res))
                return res
            except Exception as e:
                logger.exception("Failed to read sample whois: %s", e)
                return {}

    # Live WHOIS
    try:
        import whois as whois_py
        w = whois_py.whois(domain)
        res = _normalize_whois_obj(w)
        cache.set(key, res, ttl=ttl)
        logger.info("WHOIS lookup for %s done", domain)
        return res
    except Exception as e:
        logger.exception("WHOIS lookup failed for %s: %s", domain, e)
        return {}
