# enricher/dns_enricher.py
"""
DNS enricher: A/AAAA/TXT/MX lookups and reverse PTR lookups.
Uses dnspython. Results are cached.
"""
import logging
from utils.cache import Cache
from utils.config import Config
import dns.resolver
import dns.reversename

logger = logging.getLogger("enricher.dns")
cache = Cache()

def _safe_resolve(name, rtype, lifetime=5):
    try:
        answers = dns.resolver.resolve(name, rtype, lifetime=lifetime)
        if rtype == "TXT":
            # TXT answers are sequence of bytes/strings
            return ["".join([s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in a.strings]) for a in answers]
        if rtype == "MX":
            return [m.exchange.to_text() for m in answers]
        return [a.to_text() for a in answers]
    except Exception:
        return []

def enrich_dns(domain, use_cache=True, ttl=60*60):
    """
    Returns dict {a:[], aaaa:[], txt:[], mx:[]}
    """
    if not domain:
        return {}
    key = f"dns:{domain}"
    if use_cache:
        c = cache.get(key)
        if c:
            return c
    # Prevent network if DEMO_MODE or public fetch disabled
    if Config.DEMO_MODE or not Config.ALLOW_PUBLIC_FETCH:
        logger.debug("DNS enrich skipped due to DEMO_MODE or ALLOW_PUBLIC_FETCH=false")
        return {"a":[], "aaaa":[], "txt":[], "mx":[]}

    out = {
        "a": _safe_resolve(domain, "A"),
        "aaaa": _safe_resolve(domain, "AAAA"),
        "txt": _safe_resolve(domain, "TXT"),
        "mx": _safe_resolve(domain, "MX")
    }
    cache.set(key, out, ttl=ttl)
    logger.info("DNS enrichment for %s -> A:%d AAAA:%d TXT:%d MX:%d", domain, len(out["a"]), len(out["aaaa"]), len(out["txt"]), len(out["mx"]))
    return out

def enrich_reverse_ip(ip, use_cache=True, ttl=60*60):
    """
    Reverse PTR lookup for an IP. Returns {'ptr': 'host.example.com'} or {'ptr': None}
    """
    if not ip:
        return {"ptr": None}
    key = f"rptr:{ip}"
    if use_cache:
        c = cache.get(key)
        if c:
            return c
    if Config.DEMO_MODE or not Config.ALLOW_PUBLIC_FETCH:
        return {"ptr": None}
    try:
        rev = dns.reversename.from_address(ip)
        ans = dns.resolver.resolve(rev, "PTR", lifetime=5)
        ptr = ans[0].to_text().rstrip(".")
        out = {"ptr": ptr}
        cache.set(key, out, ttl=ttl)
        logger.info("Reverse PTR for %s -> %s", ip, ptr)
        return out
    except Exception:
        return {"ptr": None}
