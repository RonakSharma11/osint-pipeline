# collectors/enrich.py
"""
Async enrichment helpers with per-step progress reporting.

enrich_local(ioc, progress_queue=...) will put progress messages into the
queue as each sub-step completes. Messages are plain dicts; run_enrich.py
consumes and prints them.

Sub-steps reported:
 - DNS
 - WHOIS
 - REVERSE_DNS
 - GEOIP
 - COMPLETE

All blocking work (whois/dns/geo/reverse) runs in executor so this can be awaited concurrently.
"""

import socket
import asyncio
from functools import partial

import dns.resolver
import whois as whoislib
import geoip2.database

from utils.config import Config

GEOIP_DB = Config.GEOIP_DB_PATH

# -- low-level blocking helpers ------------------------------------------------
def _run_dns(domain):
    out = {"a": [], "aaaa": [], "mx": [], "txt": []}
    try:
        a = dns.resolver.resolve(domain, "A", lifetime=3)
        out["a"] = [str(x) for x in a]
    except Exception:
        out["a"] = []
    try:
        aaaa = dns.resolver.resolve(domain, "AAAA", lifetime=3)
        out["aaaa"] = [str(x) for x in aaaa]
    except Exception:
        out["aaaa"] = []
    try:
        mx = dns.resolver.resolve(domain, "MX", lifetime=3)
        out["mx"] = [str(x.exchange).rstrip('.') for x in mx]
    except Exception:
        out["mx"] = []
    try:
        txt = dns.resolver.resolve(domain, "TXT", lifetime=3)
        # TXT records can be arrays of bytes
        out["txt"] = []
        for r in txt:
            try:
                # r.strings is a list of byte-strings
                if hasattr(r, "strings"):
                    out["txt"].append("".join([s.decode(errors="ignore") if isinstance(s, (bytes, bytearray)) else str(s) for s in r.strings]))
                else:
                    out["txt"].append(str(r))
            except Exception:
                out["txt"].append(str(r))
    except Exception:
        pass
    return out

def _run_rdns(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
        return host
    except Exception:
        return None

def _run_geoip(ip):
    try:
        reader = geoip2.database.Reader(GEOIP_DB)
        r = reader.city(ip)
        return {
            "city": r.city.name,
            "country": r.country.name,
            "country_iso": r.country.iso_code,
            "location": {"lat": r.location.latitude, "lon": r.location.longitude}
        }
    except Exception:
        return {}

def _run_whois(domain):
    try:
        w = whoislib.whois(domain)
        return {
            "registrar": getattr(w, "registrar", None),
            "creation_date": str(getattr(w, "creation_date", None)),
            "expiration_date": str(getattr(w, "expiration_date", None)),
            "name_servers": getattr(w, "name_servers", None),
            "raw": str(w)[:4000]
        }
    except Exception:
        return {}

# -- high-level async function -------------------------------------------------
async def enrich_local(ioc: dict, progress_queue: asyncio.Queue | None = None, skip_whois: bool = False):
    """
    Perform local enrichments for a single IOC and report progress steps via progress_queue.

    Returns:
      {
        "type": ioc_type,
        "value": value,
        "source": ioc.get("source"),
        "enrichment": {...}
      }

    Progress messages written to queue (if provided) are dicts:
      {"idx": int, "total": int, "id": "type::value", "step": "DNS", "status": "done"}
    """
    loop = asyncio.get_running_loop()
    ioc_type = ioc.get("type")
    value = ioc.get("value")
    key = f"{ioc_type}::{value}"
    enrichment = {}

    # DNS (domains)
    if ioc_type == "domain":
        dns_res = await loop.run_in_executor(None, partial(_run_dns, value))
        enrichment["dns"] = dns_res or {}
        if progress_queue:
            await progress_queue.put({"id": key, "step": "DNS", "status": "done"})

        # WHOIS
        if not skip_whois:
            whois_res = await loop.run_in_executor(None, partial(_run_whois, value))
            enrichment["whois"] = whois_res or {}
            if progress_queue:
                await progress_queue.put({"id": key, "step": "WHOIS", "status": "done"})
    else:
        # not a domain -> ensure dns empty
        enrichment["dns"] = {"a": [], "aaaa": [], "mx": [], "txt": []}

    # IP-specific: reverse DNS + geoip
    if ioc_type == "ip":
        rdns_res = await loop.run_in_executor(None, partial(_run_rdns, value))
        if rdns_res:
            enrichment["reverse"] = {"ptr": rdns_res}
        if progress_queue:
            await progress_queue.put({"id": key, "step": "REVERSE_DNS", "status": "done"})

        geo_res = await loop.run_in_executor(None, partial(_run_geoip, value))
        enrichment["geoip"] = geo_res or {}
        if progress_queue:
            await progress_queue.put({"id": key, "step": "GEOIP", "status": "done"})

    # Make sure fields exist
    enrichment.setdefault("passive_dns", enrichment.get("passive_dns", []))
    enrichment.setdefault("reverse", enrichment.get("reverse", {}))
    enrichment.setdefault("geoip", enrichment.get("geoip", {}))
    enrichment.setdefault("whois", enrichment.get("whois", {}))

    # Final completion message
    if progress_queue:
        await progress_queue.put({"id": key, "step": "COMPLETE", "status": "done"})

    return {
        "type": ioc_type,
        "value": value,
        "source": ioc.get("source"),
        "first_seen": ioc.get("first_seen"),
        "last_seen": ioc.get("last_seen"),
        "enrichment": enrichment
    }
