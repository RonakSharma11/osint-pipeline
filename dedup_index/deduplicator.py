# dedup_index/deduplicator.py
"""
Canonicalization and scoring helpers.

- canonicalize(ioc): normalize domains, IPs, hashes
- compute_confidence(enrichment): heuristic score [0..100]
- make_cluster_id(doc): simple deterministic cluster id for grouping
"""

import ipaddress
from urllib.parse import urlparse
import hashlib
import logging

logger = logging.getLogger("dedup")

def canonicalize(ioc):
    """
    Normalize indicator dict into canonical form:
    input: {"type":"ip"|"domain"|"hash", "value":"..."}
    returns: normalized dict with same keys plus original metadata preserved
    """
    typ = ioc.get("type")
    val = ioc.get("value")
    if not val:
        return ioc

    if typ == "domain":
        v = str(val).lower().strip()
        # remove scheme if present
        if v.startswith("http://") or v.startswith("https://"):
            try:
                p = urlparse(v)
                v = p.netloc or p.path
            except Exception:
                pass
        # remove trailing slashes
        v = v.strip("/ ")
        # remove leftover port
        if ":" in v:
            v = v.split(":")[0]
        ioc_c = dict(ioc)
        ioc_c["value"] = v
        ioc_c["type"] = "domain"
        return ioc_c

    if typ == "ip":
        try:
            v = str(ipaddress.ip_address(val))
            ioc_c = dict(ioc)
            ioc_c["value"] = v
            ioc_c["type"] = "ip"
            return ioc_c
        except Exception:
            # if cannot parse, return as-is
            return ioc

    if typ == "hash":
        ioc_c = dict(ioc)
        ioc_c["value"] = str(val).lower()
        ioc_c["type"] = "hash"
        return ioc_c

    # fallback: lowercase string
    try:
        iv = str(val).strip()
        ioc_c = dict(ioc)
        ioc_c["value"] = iv
        return ioc_c
    except Exception:
        return ioc

def compute_confidence(enrichment):
    """
    Heuristic confidence scoring using presence of enrichment artifacts.
    Returns int 0..100.
    Rules (example):
      - geoip country -> +25
      - whois registrar -> +20
      - dns records (A/AAAA/TXT/MX) -> +20
      - reverse ptr -> +5
      - sources_count >1 -> +20
    Adjusts to cap 100.
    """
    if not enrichment or not isinstance(enrichment, dict):
        return 0
    score = 0
    try:
        geo = enrichment.get("geoip") or {}
        if geo and geo.get("country"):
            score += 25
        who = enrichment.get("whois") or {}
        if who and who.get("registrar"):
            score += 20
        dns = enrichment.get("dns") or {}
        if dns and any(dns.get(k) for k in ("a","aaaa","txt","mx")):
            score += 20
        if enrichment.get("reverse") and enrichment["reverse"].get("ptr"):
            score += 5
        # multiple sources
        sc = enrichment.get("sources_count") or enrichment.get("sources_count", 1)
        try:
            if int(sc) > 1:
                score += 20
        except Exception:
            pass
    except Exception as e:
        logger.exception("compute_confidence error: %s", e)
    return min(100, int(score))

def make_cluster_id(doc):
    """
    Create a deterministic cluster id string for a doc based on key enrichment
    fields (ASN, related domains/hashes, geoip country). This is a simple
    fingerprint — not a graph-clustering algorithm.
    """
    parts = []
    try:
        enr = doc.get("enrichment", {})
        # include ASN and org if present
        geo = enr.get("geoip") or {}
        if geo.get("asn"):
            parts.append(str(geo.get("asn")))
        if geo.get("org"):
            parts.append(str(geo.get("org")))
        who = enr.get("whois") or {}
        if who.get("registrar"):
            parts.append(str(who.get("registrar")))
        # related lists
        for k in ("related_domains","related_hashes"):
            v = enr.get(k)
            if v:
                if isinstance(v, (list,tuple)):
                    parts.extend(sorted([str(x) for x in v]))
                else:
                    parts.append(str(v))
        # fallback to indicator value/type
        parts.append(str(doc.get("type","")) + ":" + str(doc.get("value","")))
    except Exception:
        pass
    if not parts:
        base = (doc.get("type","") + ":" + doc.get("value","")).encode("utf-8")
    else:
        base = "::".join(parts).encode("utf-8")
    cid = hashlib.sha1(base).hexdigest()[:12]
    return f"cluster-{cid}"
