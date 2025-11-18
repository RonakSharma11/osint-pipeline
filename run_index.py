# run_index.py
"""
Indexer for enriched IOCs.

Reads:
 - ./store/iocs_enriched.json  (preferred)
 - or ./store/iocs_enriched.jsonl (fall back, line-delimited)

Writes:
 - ./store/iocs_indexed.json (final output)

This script computes:
 - a modular score_breakdown dict (components are easy to tweak)
 - a final integer score 0-100
 - a risk_bucket ("high","medium","low")
"""
import os
import json
import sys

IN_JSON = "./store/iocs_enriched.json"
IN_JSONL = "./store/iocs_enriched.jsonl"
OUT_INDEX = "./store/iocs_indexed.json"


def load_enriched():
    if os.path.exists(IN_JSON):
        with open(IN_JSON, "r") as f:
            return json.load(f)
    if os.path.exists(IN_JSONL):
        out = []
        with open(IN_JSONL, "r") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    out.append(json.loads(ln))
                except Exception:
                    continue
        return out
    print("No enriched IOCs found. Run run_enrich.py first.")
    sys.exit(1)


# scoring helpers
def map_reports_to_contrib(r):
    r = int(r or 0)
    if r >= 10000:
        return 18
    if r >= 5000:
        return 16
    if r >= 2000:
        return 14
    if r >= 1000:
        return 12
    if r >= 500:
        return 10
    if r >= 200:
        return 8
    if r >= 50:
        return 5
    if r >= 10:
        return 2
    return 0


def map_users_to_contrib(u):
    u = int(u or 0)
    if u >= 1000:
        return 10
    if u >= 500:
        return 9
    if u >= 200:
        return 7
    if u >= 100:
        return 5
    if u >= 25:
        return 3
    return 0


def ptr_heuristic(ptr):
    if not ptr:
        return 0
    p = ptr.lower()
    suspicious = ["scan", "security", "malware", "bot", "spammer", "scan-"]
    for s in suspicious:
        if s in p:
            return 12
    return 0


HIGH_RISK_COUNTRIES = {"CN", "RU", "IR", "KP", "SY"}
def country_heuristic(country_iso):
    if not country_iso:
        return 0
    return 5 if country_iso.upper() in HIGH_RISK_COUNTRIES else 0


def source_weight(src):
    if not src:
        return 5
    s = str(src).lower()
    if "abuseipdb" in s:
        return 20
    if "otx" in s:
        return 10
    if "urlhaus" in s:
        return 12
    return 5


def compute_score(item):
    # build breakdown
    breakdown = {}
    breakdown["base"] = 10
    breakdown["source_weight"] = source_weight(item.get("source"))

    abuse = item.get("enrichment", {}).get("abuseipdb") or item.get("enrichment", {}).get("abuse")
    # extract abuseConfidenceScore
    abuse_conf = None
    if isinstance(abuse, dict):
        abuse_conf = abuse.get("abuseConfidenceScore") or (abuse.get("data") or {}).get("abuseConfidenceScore") or item.get("enrichment", {}).get("abuseipdb_score")
    try:
        abuse_conf = int(abuse_conf) if abuse_conf is not None else 0
    except Exception:
        abuse_conf = 0
    breakdown["abuse_confidence"] = abuse_conf
    breakdown["abuse_contrib"] = round(abuse_conf * 0.25)  # 0-25

    total_reports = 0
    distinct_users = 0
    if isinstance(abuse, dict):
        total_reports = int(abuse.get("totalReports") or (abuse.get("data") or {}).get("totalReports") or 0)
        distinct_users = int(abuse.get("numDistinctUsers") or (abuse.get("data") or {}).get("numDistinctUsers") or 0)
    breakdown["total_reports"] = total_reports
    breakdown["total_reports_contrib"] = map_reports_to_contrib(total_reports)
    breakdown["distinct_users"] = distinct_users
    breakdown["distinct_users_contrib"] = map_users_to_contrib(distinct_users)

    passive_dns_count = len(item.get("enrichment", {}).get("passive_dns") or [])
    breakdown["passive_dns_count"] = passive_dns_count
    breakdown["passive_dns_contrib"] = 0

    otx_count = int(item.get("enrichment", {}).get("otx_count") or 0)
    breakdown["otx_count"] = otx_count
    breakdown["otx_contrib"] = min(8, otx_count)

    ptr = item.get("enrichment", {}).get("reverse", {}).get("ptr")
    breakdown["ptr"] = ptr
    breakdown["ptr_contrib"] = ptr_heuristic(ptr)

    whois_present = bool(item.get("enrichment", {}).get("whois") or item.get("enrichment", {}).get("whois_hint"))
    breakdown["whois_present"] = 1 if whois_present else 0
    breakdown["whois_contrib"] = 0

    country_iso = item.get("enrichment", {}).get("geoip", {}).get("country_iso")
    breakdown["country"] = country_iso
    breakdown["country_contrib"] = country_heuristic(country_iso)

    # small penalty if literally zero signals
    signals = (breakdown["abuse_confidence"] or breakdown["total_reports"] or breakdown["otx_count"] or passive_dns_count)
    breakdown["no_signals_penalty"] = -5 if not signals else 0

    total_raw = (
        breakdown["base"]
        + breakdown["source_weight"]
        + breakdown["abuse_contrib"]
        + breakdown["total_reports_contrib"]
        + breakdown["distinct_users_contrib"]
        + breakdown["passive_dns_contrib"]
        + breakdown["otx_contrib"]
        + breakdown["ptr_contrib"]
        + breakdown["country_contrib"]
        + breakdown["whois_contrib"]
        + breakdown["no_signals_penalty"]
    )
    breakdown["final_score_raw"] = total_raw
    final_score = max(0, min(100, int(round(total_raw))))
    breakdown["final_score"] = final_score

    return final_score, breakdown


def main():
    enriched = load_enriched()
    print(f"Loaded {len(enriched)} enriched IOCs")
    indexed = []
    scores = []
    for it in enriched:
        score, breakdown = compute_score(it)
        out = {
            "id": f"{it.get('type')}::{it.get('value')}",
            "type": it.get("type"),
            "value": it.get("value"),
            "source": it.get("source"),
            "sources_count": it.get("enrichment", {}).get("sources_count", 1),
            "enrichment": it.get("enrichment", {}),
            "score": score,
            "score_breakdown": breakdown
        }
        if score >= 70:
            out["risk_bucket"] = "high"
        elif score >= 40:
            out["risk_bucket"] = "medium"
        else:
            out["risk_bucket"] = "low"
        indexed.append(out)
        scores.append(score)

    os.makedirs(os.path.dirname(OUT_INDEX), exist_ok=True)
    with open(OUT_INDEX, "w") as f:
        json.dump(indexed, f, indent=2)

    avg = (sum(scores) / len(scores)) if scores else 0
    top = sorted(scores, reverse=True)[:5]
    counts = {"high": 0, "medium": 0, "low": 0}
    for it in indexed:
        counts[it["risk_bucket"]] += 1
    print(f"Indexed {len(indexed)} IOCs -> {OUT_INDEX}")
    print(f"Risk buckets: {counts}")
    print(f"Avg score: {avg:.1f} Top scores: {top}")
    print("Example top 10:")
    for it in sorted(indexed, key=lambda x: x["score"], reverse=True)[:10]:
        abuse = it["enrichment"].get("abuseipdb") or it["enrichment"].get("abuse")
        reports = None
        users = None
        if isinstance(abuse, dict):
            reports = abuse.get("totalReports") or (abuse.get("data") or {}).get("totalReports")
            users = abuse.get("numDistinctUsers") or (abuse.get("data") or {}).get("numDistinctUsers")
        ptr = it["enrichment"].get("reverse", {}).get("ptr")
        isp = (abuse or {}).get("isp") if isinstance(abuse, dict) else None
        print(f"  {it['score']:2d} - {it['id']} (abuse:{it['score_breakdown'].get('abuse_confidence')} reports:{reports} users:{users} ptr:{ptr} isp:{isp})")


if __name__ == "__main__":
    main()
