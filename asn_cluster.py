# asn_cluster.py
"""
ASN clustering helper.

Reads ./store/iocs_indexed.json (indexed IOCs produced by your pipeline).
Filters IP IOCs by risk (high by default or --min-score) and groups them
by ASN/organization using ipinfo.io free lookup. Results are cached to
./store/asn_cache.json so re-runs are fast and rate-limited.

Outputs:
 - ./store/asn_clusters.json  -> summary of clusters
 - ./store/asn_cache.json     -> cached ip -> ipinfo results used by this run

Usage:
    python asn_cluster.py                  # default: risk_bucket=="high"
    python asn_cluster.py --min-score 70   # use score threshold instead
    python asn_cluster.py --max 500        # limit how many IOCs to process
"""

import argparse
import json
import os
import time
import ipaddress
from collections import defaultdict, Counter

try:
    import requests
except Exception:
    raise SystemExit("Please install 'requests' (pip install requests)")

STORE_INDEX = "./store/iocs_indexed.json"
ASN_CACHE = "./store/asn_cache.json"
OUT_CLUSTER = "./store/asn_clusters.json"


def load_indexed():
    if not os.path.exists(STORE_INDEX):
        raise FileNotFoundError(f"{STORE_INDEX} not found. Run indexing first.")
    with open(STORE_INDEX, "r") as f:
        return json.load(f)


def load_cache():
    if os.path.exists(ASN_CACHE):
        with open(ASN_CACHE, "r") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    os.makedirs(os.path.dirname(ASN_CACHE), exist_ok=True)
    with open(ASN_CACHE, "w") as f:
        json.dump(cache, f, indent=2)


def query_ipinfo(ip):
    """Query ipinfo.io for IP. No API key used (free public)."""
    url = f"https://ipinfo.io/{ip}/json"
    try:
        r = requests.get(url, timeout=8)
        if r.status_code == 200:
            return r.json()
        else:
            return {"error": f"status_{r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def parse_org(org_string):
    """
    ipinfo 'org' example: "AS12345 Example ISP"
    Returns (asn:int/str, org_name:str)
    """
    if not org_string:
        return None, None
    parts = org_string.split(" ", 1)
    if len(parts) == 2 and parts[0].upper().startswith("AS"):
        return parts[0], parts[1]
    return None, org_string


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-score", type=int, default=None,
                        help="Minimum score to include (overrides --only-high).")
    parser.add_argument("--only-high", action="store_true",
                        help="Only include risk_bucket == 'high' (default if --min-score not set).")
    parser.add_argument("--max", type=int, default=None,
                        help="Limit number of IPs processed this run.")
    parser.add_argument("--sleep", type=float, default=0.05,
                        help="Sleep sec between external queries to avoid rate-limit.")
    args = parser.parse_args()

    indexed = load_indexed()
    cache = load_cache()

    # Build candidate IP list
    ips = []
    for item in indexed:
        try:
            t = item.get("type")
            val = item.get("value")
            score = item.get("score") or 0
            bucket = item.get("risk_bucket", "").lower()
            if t != "ip" or not val:
                continue
            if args.min_score is not None:
                if score >= args.min_score:
                    ips.append((val, score, bucket, item))
            else:
                if args.only_high:
                    if bucket == "high":
                        ips.append((val, score, bucket, item))
                else:
                    # default fallback: include high only
                    if bucket == "high":
                        ips.append((val, score, bucket, item))
        except Exception:
            continue

    if args.max:
        ips = ips[:args.max]

    print(f"Processing {len(ips)} IPs (cached entries will be reused).")

    results = {}
    asn_map = defaultdict(list)
    asn_meta = {}

    for idx, (ip, score, bucket, item) in enumerate(ips, start=1):
        if ip in cache:
            info = cache[ip]
        else:
            # Validate IP format
            try:
                ipaddress.ip_address(ip)
            except Exception:
                info = {"error": "invalid_ip"}
                cache[ip] = info
                continue

            info = query_ipinfo(ip)
            cache[ip] = info
            time.sleep(args.sleep)

        results[ip] = info

        org = info.get("org")
        asn, org_name = parse_org(org)
        if not asn:
            asn = "AS_UNKNOWN"
            org_name = org or "Unknown"

        # gather metrics for the IP from indexed item (if present)
        abuse = item.get("enrichment", {}).get("abuseipdb", {})
        reports = abuse.get("totalReports") if isinstance(abuse, dict) else None
        asn_map[asn].append({
            "ip": ip,
            "score": score,
            "ptr": item.get("enrichment", {}).get("reverse", {}).get("ptr"),
            "reports": reports,
            "org_name": org_name,
        })
        asn_meta.setdefault(asn, {"org_name": org_name, "count": 0})
        asn_meta[asn]["count"] += 1

    # Summarize clusters
    clusters = []
    for asn, members in asn_map.items():
        total_reports = sum((m.get("reports") or 0) for m in members)
        clusters.append({
            "asn": asn,
            "org_name": asn_meta.get(asn, {}).get("org_name"),
            "count": len(members),
            "members_sample": members[:6],
            "total_reports": total_reports,
        })

    clusters = sorted(clusters, key=lambda x: x["count"], reverse=True)

    out = {
        "summary_count": len(clusters),
        "clusters": clusters,
    }

    # save outputs
    os.makedirs(os.path.dirname(ASN_CACHE), exist_ok=True)
    save_cache(cache)
    with open(OUT_CLUSTER, "w") as f:
        json.dump(out, f, indent=2)

    # Print top clusters
    print("Top ASN clusters:")
    for c in clusters[:10]:
        print(f"  {c['asn']:15} {c['org_name'][:40]:40} count={c['count']:4} reports={c['total_reports']}")

    print(f"Clusters written -> {OUT_CLUSTER}")
    print(f"Cache written -> {ASN_CACHE}")


if __name__ == "__main__":
    main()
