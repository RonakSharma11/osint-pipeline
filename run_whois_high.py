# run_whois_high.py
"""
Run WHOIS (and optional HTTP quick checks) for only high-risk IOCs.

Usage:
  python run_whois_high.py --threshold 75 --limit 200 --concurrency 5 --do-http false

Behavior:
 - Loads ./store/iocs_indexed.json to find IOCs with score >= threshold
 - Loads ./store/enrich_cache.json (or creates it)
 - For each high IOC that lacks WHOIS enrichment, runs a safe whois lookup
   and stores the result into enrich_cache.json and updates ./store/iocs_enriched.json
 - Respects Config.ALLOW_PUBLIC_FETCH via utils.config if you want to guard fetching
"""

import argparse
import json
import os
import time
from utils.config import Config
# optional whois library; we wrap it for safety
try:
    import whois as whois_lib
except Exception:
    whois_lib = None

CACHE_FILE = "./store/enrich_cache.json"
AGG_FILE = "./store/iocs_enriched.json"
INDEX_FILE = "./store/iocs_indexed.json"

def safe_whois(domain):
    if not whois_lib:
        return {"error": "whois-lib-missing"}
    try:
        # python-whois returns different shapes, wrap in dict
        out = whois_lib.whois(domain)
        # Convert object -> dict safely
        return dict(out) if isinstance(out, dict) else {k: getattr(out, k) for k in dir(out) if not k.startswith("_")}
    except Exception as e:
        return {"error": f"whois-failed: {str(e)}"}

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    return {}

def write_cache(cache):
    os.makedirs("./store", exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

def rebuild_agg_from_cache(cache):
    arr = list(cache.values())
    with open(AGG_FILE, "w") as f:
        json.dump(arr, f, indent=2)
    print(f"Wrote aggregated enriched file: {AGG_FILE} entries={len(arr)}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=int, default=75, help="score threshold to treat as high risk")
    parser.add_argument("--limit", type=int, default=500, help="max number of high iocs to whois")
    parser.add_argument("--do-http", type=str, default="false", help="quick http check (true/false)")
    args = parser.parse_args()

    # guard public fetch flag
    if not Config.ALLOW_PUBLIC_FETCH:
        print("Public fetch disabled by Config.ALLOW_PUBLIC_FETCH. Exiting.")
        return

    do_http = str(args.do_http).lower() in ("1","true","yes")

    if not os.path.exists(INDEX_FILE):
        print("Missing index file. Run run_index.py first.")
        return

    with open(INDEX_FILE, "r") as f:
        indexed = json.load(f)

    # find high-risk entries
    high = [i for i in indexed if (i.get("score") or 0) >= args.threshold]
    print(f"Found {len(high)} entries with score >= {args.threshold} (limiting to {args.limit})")
    high = high[: args.limit]

    cache = load_cache()

    updated = 0
    for i, item in enumerate(high, start=1):
        val = item.get("value")
        typ = item.get("type")
        cache_key = f"{typ}::{val}"
        cache_entry = cache.get(cache_key, item.copy())  # either existing enriched or basic

        ench = cache_entry.get("enrichment") or {}

        # Only run WHOIS for domains (skip for IPs)
        if typ == "domain":
            # if WHOIS already present with registrar/raw, skip
            if not ench.get("whois") or (ench.get("whois") == {}):
                print(f"[{i}/{len(high)}] WHOIS {val} ...", end=" ", flush=True)
                whois_res = safe_whois(val)
                ench["whois"] = whois_res
                cache_entry["enrichment"] = ench
                cache[cache_key] = cache_entry
                updated += 1
                print("done")
                # polite sleep to avoid hammering whois servers
                time.sleep(1.0)
            else:
                print(f"[{i}/{len(high)}] WHOIS {val} (already present)")

        # Optionally do HTTP quick check (head request) for domains
        if do_http and typ == "domain":
            import requests
            if not ench.get("http_checked"):
                try:
                    url = f"http://{val}"
                    r = requests.head(url, timeout=6, allow_redirects=True)
                    ench["http_checked"] = {"status": r.status_code, "final_url": r.url}
                except Exception as e:
                    ench["http_checked"] = {"error": str(e)}
                cache_entry["enrichment"] = ench
                cache[cache_key] = cache_entry
                updated += 1
                time.sleep(0.25)

    if updated:
        write_cache(cache)
        rebuild_agg_from_cache(cache)
        print(f"WHOIS/HTTP updated {updated} entries and wrote cache.")
    else:
        print("No updates needed (WHOIS present for all high entries).")

if __name__ == "__main__":
    main()
