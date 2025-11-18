# utils/scoring.py
"""
Improved scoring utilities for OSINT pipeline.

Outputs (score:int, breakdown:dict) where breakdown contains
every numeric contribution so results are explainable.

Key improvements over previous version:
 - lower abuse_confidence direct dominance
 - add recency weight for recent reports
 - detect and penalize cloud provider ISPs (reduces noisy high scores)
 - add reports-per-user (density) signal (log-scaled)
 - domain-specific age-based signal (younger domains get more weight)
 - small rebalancing of contribution caps to spread scores more
"""

from math import log10
from datetime import datetime, timezone
import re

def _num(v, default=0):
    try:
        if v is None:
            return default
        return float(v)
    except Exception:
        return default

PTR_SUSPICIOUS_KEYWORDS = [
    "scan", "security", "scan-", "scanner", "ipip", "f6.security", "scan.", "bot",
    "malicious", "suspicious", "spam", "mail", "proxy", "tor", "vpn"
]

HIGH_RISK_COUNTRIES = {"IR", "RU", "CN", "KP", "SY", "VN"}

# common cloud / hosting ISP keywords to detect cloud hosts and reduce weight
CLOUD_KEYWORDS = [
    "amazon", "aws", "google", "gcp", "microsoft", "azure", "digitalocean",
    "ovh", "linode", "vultr", "cloudflare", "cloud", "ucloud", "vps", "hosting",
    "hetzner", "scaleway", "rackspace", "oracle", "aliyun", "tencent"
]

# tries to parse ISO datetime strings including timezone
def _parse_dt(s):
    if not s:
        return None
    try:
        # some strings sometimes include extra whitespace/newlines
        s = str(s).strip()
        # Python's fromisoformat handles "YYYY-MM-DDTHH:MM:SS+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        # fallback naive parse with regex for YYYY-MM-DD
        m = re.search(r"(\d{4}-\d{2}-\d{2})", s)
        if m:
            try:
                return datetime.fromisoformat(m.group(1))
            except Exception:
                return None
    return None

def score_ioc(ioc):
    """
    Input: ioc dict (expected to have 'type','value','enrichment')
    Returns: (final_score:int 0..100, breakdown:dict)
    """
    ench = ioc.get("enrichment") or {}
    typ = (ioc.get("type") or "").lower()

    breakdown = {}
    score = 10
    breakdown["base"] = 10

    # Source weight
    src = (ioc.get("source") or "").lower()
    src_weight = 0
    if "abuseipdb" in src:
        src_weight = 4
    elif "otx" in src or "alienvault" in src:
        src_weight = 3
    elif "github" in src or "rss" in src:
        src_weight = 1
    breakdown["source_weight"] = src_weight
    score += src_weight

    # AbuseIPDB abuseConfidenceScore (bounded, reduced weight)
    abuse_conf = None
    if isinstance(ench.get("abuseipdb"), dict):
        abuse_conf = ench["abuseipdb"].get("abuseConfidenceScore")
    if abuse_conf is None:
        abuse_conf = ench.get("abuseipdb_score")
    abuse_conf = int(_num(abuse_conf, 0))
    # smaller multiplier than before: 100 -> ~20
    abuse_contrib = int(min(24, round(abuse_conf * 0.2)))
    breakdown["abuse_confidence"] = abuse_conf
    breakdown["abuse_contrib"] = abuse_contrib
    score += abuse_contrib

    # totalReports -> log-scale (0..18)
    total_reports = int(_num((ench.get("abuseipdb") or {}).get("totalReports") or ench.get("abuse_totalReports") or 0, 0))
    if total_reports > 0:
        total_reports_contrib = int(min(18, round(log10(total_reports + 1) * 4.0)))
    else:
        total_reports_contrib = 0
    breakdown["total_reports"] = total_reports
    breakdown["total_reports_contrib"] = total_reports_contrib
    score += total_reports_contrib

    # distinct users -> log scale (0..12)
    distinct = int(_num((ench.get("abuseipdb") or {}).get("numDistinctUsers") or ench.get("abuse_numDistinctUsers") or 0, 0))
    if distinct > 0:
        distinct_contrib = int(min(12, round(log10(distinct + 1) * 3.2)))
    else:
        distinct_contrib = 0
    breakdown["distinct_users"] = distinct
    breakdown["distinct_users_contrib"] = distinct_contrib
    score += distinct_contrib

    # reports per distinct user (density) -> 0..8 (high density more suspicious)
    rp = 0
    if distinct > 0:
        rp = total_reports / max(1, distinct)
    rp_contrib = int(min(8, round(log10(rp + 1) * 2.5))) if rp > 0 else 0
    breakdown["reports_per_user"] = float(rp)
    breakdown["reports_per_user_contrib"] = rp_contrib
    score += rp_contrib

    # Passive DNS count -> 0..8
    pdns = ench.get("passive_dns") or []
    pdns_count = len(pdns) if isinstance(pdns, list) else 0
    pdns_contrib = int(min(8, pdns_count * 1))
    breakdown["passive_dns_count"] = pdns_count
    breakdown["passive_dns_contrib"] = pdns_contrib
    score += pdns_contrib

    # OTX/AlienVault pulse_count -> 0..8
    otx_count = 0
    if isinstance(ench.get("otx"), dict):
        otx_count = int(_num(ench["otx"].get("pulse_count") or ench["otx"].get("count") or 0, 0))
    else:
        otx_count = int(_num(ench.get("otx_count") or 0, 0))
    otx_contrib = int(min(8, otx_count * 2))  # small multiplier but bounded
    breakdown["otx_count"] = otx_count
    breakdown["otx_contrib"] = otx_contrib
    score += otx_contrib

    # PTR heuristics
    ptr = None
    if isinstance(ench.get("reverse"), dict):
        ptr = ench["reverse"].get("ptr")
    if not ptr:
        if isinstance(ench.get("reverse"), str):
            ptr = ench.get("reverse")
    ptr_contrib = 0
    ptr_flag = 0
    if ptr:
        ptr_lower = str(ptr).lower()
        for kw in PTR_SUSPICIOUS_KEYWORDS:
            if kw in ptr_lower:
                ptr_flag = 1
                ptr_contrib = 10
                break
    breakdown["ptr"] = ptr or None
    breakdown["ptr_contrib"] = ptr_contrib
    score += ptr_contrib

    # ISP/cloud penalty to reduce noisy cloud hosts
    isp = (ench.get("abuseipdb") or {}).get("isp") or ench.get("abuse_isp") or ""
    isp_lower = (isp or "").lower()
    cloud_flag = 0
    cloud_penalty = 0
    for kw in CLOUD_KEYWORDS:
        if kw in isp_lower:
            cloud_flag = 1
            cloud_penalty = 8  # penalize noisy cloud providers
            break
    breakdown["isp"] = isp or None
    breakdown["cloud_flag"] = cloud_flag
    breakdown["cloud_penalty"] = -cloud_penalty
    score -= cloud_penalty  # subtract penalty

    # WHOIS presence and domain-age (domain specific)
    whois_obj = ench.get("whois") or {}
    whois_present = 0
    whois_contrib = 0
    domain_age_contrib = 0
    if typ == "domain":
        # treat whois presence as signal
        if isinstance(whois_obj, dict) and (whois_obj.get("registrar") or whois_obj.get("creation_date") or whois_obj.get("raw")):
            whois_present = 1
            whois_contrib = 6
            # try domain creation_date -> reward very young domains
            creation = whois_obj.get("creation_date") or whois_obj.get("created")
            # Some whois libs return list
            if isinstance(creation, list) and creation:
                creation = creation[0]
            parsed = None
            if creation:
                parsed = _parse_dt(creation)
            if parsed:
                try:
                    age_days = (datetime.now(timezone.utc) - parsed.replace(tzinfo=parsed.tzinfo or timezone.utc)).days
                except Exception:
                    # fallback naive
                    try:
                        age_days = (datetime.now() - parsed).days
                    except Exception:
                        age_days = None
                if age_days is not None:
                    if age_days <= 30:
                        domain_age_contrib = 8
                    elif age_days <= 365:
                        domain_age_contrib = 4
                    else:
                        domain_age_contrib = 0
                breakdown["domain_age_days"] = age_days
    breakdown["whois_present"] = whois_present
    breakdown["whois_contrib"] = whois_contrib
    breakdown["domain_age_contrib"] = domain_age_contrib
    score += whois_contrib + domain_age_contrib

    # Recency of lastReportedAt (AbuseIPDB) - favors recently reported items
    last_rep = (ench.get("abuseipdb") or {}).get("lastReportedAt") or ench.get("abuse_lastReportedAt")
    recency_contrib = 0
    recency_days = None
    parsed_last = None
    if last_rep:
        parsed_last = _parse_dt(last_rep)
    if parsed_last:
        try:
            now = datetime.now(timezone.utc)
            parsed_last_utc = parsed_last if parsed_last.tzinfo else parsed_last.replace(tzinfo=timezone.utc)
            recency_days = (now - parsed_last_utc).days
        except Exception:
            try:
                recency_days = (datetime.now() - parsed_last).days
            except Exception:
                recency_days = None
    if recency_days is not None:
        if recency_days <= 7:
            recency_contrib = 10
        elif recency_days <= 30:
            recency_contrib = 7
        elif recency_days <= 90:
            recency_contrib = 4
        elif recency_days <= 365:
            recency_contrib = 2
    breakdown["last_reported_days"] = recency_days
    breakdown["recency_contrib"] = recency_contrib
    score += recency_contrib

    # Country heuristic: small bump for high-risk countries
    country = None
    if isinstance(ench.get("geoip"), dict):
        country = ench["geoip"].get("country_iso") or ench["geoip"].get("country")
    country = (country or "").upper()
    country_contrib = 3 if country in HIGH_RISK_COUNTRIES else 0
    breakdown["country"] = country or None
    breakdown["country_contrib"] = country_contrib
    score += country_contrib

    # If no signals at all, small penalty
    signals = 0
    for k in ("abuse_confidence","total_reports","distinct_users","passive_dns_count","otx_count","ptr_contrib","whois_present"):
        val = breakdown.get(k) or 0
        if val:
            signals += 1
    if signals == 0:
        penalty = 5
        score -= penalty
        breakdown["no_signals_penalty"] = -penalty
    else:
        breakdown["no_signals_penalty"] = 0

    # Final clamp
    final_score = int(max(0, min(100, round(score))))
    breakdown["final_score_raw"] = score
    breakdown["final_score"] = final_score

    # Attach a few convenience fields so callers can see the meaningful signals easily
    breakdown["abuse_confidence_raw"] = abuse_conf
    breakdown["total_reports_raw"] = total_reports
    breakdown["distinct_users_raw"] = distinct
    breakdown["isp_raw"] = isp or None

    return final_score, breakdown
