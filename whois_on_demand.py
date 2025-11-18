# whois_on_demand.py
"""
WHOIS-on-demand helper.

Runs WHOIS only for high-risk IOCs (or IOCs above a score threshold).
Parallelized with threads; results are appended as JSON-lines to:
  ./store/whois_high.jsonl

Also merges WHOIS into ./store/enrich_cache.json when --merge is used.

Usage:
    python whois_on_demand.py                  # default: risk_bucket == 'high', concurrency=10
    python whois_on_demand.py --threshold 70   # numeric threshold
    python whois_on_demand.py --max 50         # only process top 50 candidates
    python whois_on_demand.py --concurrency 20
    python whois_on_demand.py --merge          # merge whois into enrich_cache.json
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import argparse
import json
import os
import subprocess
import sys
import time
import shutil
import traceback

STORE_INDEX = "./store/iocs_indexed.json"
WHOIS_OUT = "./store/whois_high.jsonl"
WHOIS_CACHE = "./store/whois_cache.json"
ENRICH_CACHE = "./store/enrich_cache.json"
BACKUP_SUFFIX = ".bak"

# Try to import python-whois; if not present we'll fall back to system 'whois'
try:
    import whois as pywhois  # python-whois package (pip install python-whois)
    HAVE_PYWHOIS = True
except Exception:
    HAVE_PYWHOIS = False


def load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            print(f"[WARN] Failed to parse {path}, returning default.")
            return default
    return default


def save_json(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    # atomic-ish move
    if os.path.exists(path):
        shutil.copy2(path, path + BACKUP_SUFFIX)
    os.replace(tmp, path)


def run_system_whois(value, timeout=30):
    """Run system 'whois' command and return stdout (or error)."""
    if shutil.which("whois") is None:
        return {"error": "whois_cli_missing", "raw": ""}
    try:
        proc = subprocess.run(["whois", value], capture_output=True, text=True, timeout=timeout)
        return {"raw": proc.stdout or "", "rc": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "raw": ""}
    except Exception as e:
        return {"error": str(e), "raw": ""}


def run_pywhois(value):
    """Use python-whois to get parsed fields (best-effort)."""
    try:
        w = pywhois.whois(value)
        # python-whois sometimes returns a dict-like object; serialize to plain dict
        result = {}
        # typical fields we want
        for k in ("domain_name", "registrar", "whois_server", "creation_date", "expiration_date", "name", "org", "emails", "raw"):
            if hasattr(w, k):
                result[k] = getattr(w, k)
            elif isinstance(w, dict) and k in w:
                result[k] = w.get(k)
        # also include full text if available
        raw = None
        try:
            raw = "\n".join(w.text) if hasattr(w, "text") else w.get("raw") if isinstance(w, dict) else None
        except Exception:
            raw = None
        if raw:
            result["raw"] = raw
        return {"parsed": result, "raw": result.get("raw", "")}
    except Exception as e:
        return {"error": "pywhois_error", "error_msg": str(e), "raw": ""}


def whois_lookup(value, timeout=30):
    """Unified WHOIS lookup: try python-whois, fallback to system whois."""
    if HAVE_PYWHOIS:
        res = run_pywhois(value)
        if res.get("parsed"):
            return res
        # fallthrough to system if python-whois failed to provide useful data
    return run_system_whois(value, timeout=timeout)


def make_ioc_key(ioc):
    """Return canonical enrich_cache key used elsewhere (id used in cache): 'type::value'"""
    t = ioc.get("type") or "unknown"
    v = ioc.get("value")
    return f"{t}::{v}"


def prepare_candidates(index_list, threshold=None, only_high=True):
    cands = []
    for it in index_list:
        try:
            score = it.get("score") or 0
            bucket = it.get("risk_bucket", "").lower()
            if threshold is not None:
                if score >= threshold:
                    cands.append(it)
            else:
                if only_high:
                    if bucket == "high":
                        cands.append(it)
        except Exception:
            continue
    return cands


def merge_whois_into_enrich_cache(enrich_cache, ioc, whois_data):
    """Merge into enrich_cache entry for this IOC. Keep existing fields; add/overwrite whois."""
    key = make_ioc_key(ioc)
    entry = enrich_cache.get(key, {})
    # ensure standard structure
    if "enrichment" not in entry:
        entry["enrichment"] = {}
    # we store whois under enrichment.whois as a dict with parsed and raw
    entry["enrichment"]["whois"] = whois_data
    # preserve metadata where possible
    for k in ("type", "value", "source"):
        if k not in entry and ioc.get(k) is not None:
            entry[k] = ioc.get(k)
    # update timestamps
    entry["_whois_last_seen"] = datetime.utcnow().isoformat() + "Z"
    enrich_cache[key] = entry
    return enrich_cache


def worker_whois(ioc, timeout):
    """Worker that runs WHOIS and returns a record for output and cache."""
    v = ioc.get("value")
    t = ioc.get("type")
    record = {
        "value": v,
        "type": t,
        "source": ioc.get("source"),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "cached": False,
        "whois": None,
    }
    try:
        res = whois_lookup(v, timeout=timeout)
        # normalize response: prefer parsed dict if available, else raw text
        whois_struct = {}
        if isinstance(res, dict):
            if res.get("parsed"):
                whois_struct["parsed"] = res.get("parsed")
                whois_struct["raw"] = res.get("raw", "")
            elif res.get("raw"):
                whois_struct["parsed"] = {}
                whois_struct["raw"] = res.get("raw")
            else:
                whois_struct["error"] = res.get("error", "unknown")
                whois_struct["raw"] = res.get("raw", "")
        else:
            whois_struct = {"raw": str(res)}
        record["whois"] = whois_struct
    except Exception as e:
        record["whois"] = {"error": "exception", "msg": str(e), "trace": traceback.format_exc()}
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=int, default=None, help="Minimum numeric score to WHOIS")
    parser.add_argument("--only-high", action="store_true", default=True, help="Only process risk_bucket=='high' (default)")
    parser.add_argument("--max", type=int, default=None, help="Limit number processed this run")
    parser.add_argument("--concurrency", type=int, default=10, help="Thread concurrency")
    parser.add_argument("--timeout", type=int, default=30, help="WHOIS command timeout (seconds)")
    parser.add_argument("--only-domains", action="store_true", help="Only WHOIS domain IOCs (skip IPs)")
    parser.add_argument("--merge", action="store_true", help="Merge WHOIS into enrich_cache.json (safe write)")
    args = parser.parse_args()

    # Load the indexed IOCs
    if not os.path.exists(STORE_INDEX):
        print(f"[ERROR] {STORE_INDEX} not found - run indexer first.")
        sys.exit(1)
    indexed = load_json(STORE_INDEX, [])

    candidates = prepare_candidates(indexed, threshold=args.threshold, only_high=args.only_high)
    if args.only_domains:
        candidates = [c for c in candidates if c.get("type") == "domain"]

    # sort by score desc so we WHOIS most critical first
    candidates.sort(key=lambda x: x.get("score", 0), reverse=True)

    if args.max:
        candidates = candidates[: args.max]

    print(f"[INFO] Candidates to WHOIS: {len(candidates)} (concurrency={args.concurrency})")

    # Load caches
    whois_cache = load_json(WHOIS_CACHE, {})
    enrich_cache = load_json(ENRICH_CACHE, {})

    # Prepare seen set from existing WHOIS_OUT to avoid double output
    seen = set()
    if os.path.exists(WHOIS_OUT):
        try:
            with open(WHOIS_OUT, "r") as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                        seen.add(obj.get("value"))
                    except Exception:
                        continue
        except Exception:
            pass

    # Filter out already-cached items (but if cached we still append to WHOIS_OUT for audit)
    to_run = []
    append_from_cache = []
    for it in candidates:
        v = it.get("value")
        if v in seen:
            continue
        key = make_ioc_key(it)
        if v in whois_cache or (key in enrich_cache and "whois" in enrich_cache[key].get("enrichment", {})):
            # append cached record to WHOIS_OUT later
            append_from_cache.append((it, whois_cache.get(v) or enrich_cache.get(key).get("enrichment", {}).get("whois")))
            continue
        to_run.append(it)

    print(f"[INFO] To query (not cached/already-output): {len(to_run)} ; Cached-to-append: {len(append_from_cache)}")

    # Append cached items first (so WHOIS_OUT contains a full picture)
    if append_from_cache:
        os.makedirs(os.path.dirname(WHOIS_OUT) or ".", exist_ok=True)
        with open(WHOIS_OUT, "a") as f:
            for it, cached in append_from_cache:
                rec = {
                    "value": it.get("value"),
                    "type": it.get("type"),
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "cached": True,
                    "whois": cached,
                }
                f.write(json.dumps(rec) + "\n")

    # Run lookups concurrently
    completed = 0
    if to_run:
        with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            futures = {ex.submit(worker_whois, it, args.timeout): it for it in to_run}
            os.makedirs(os.path.dirname(WHOIS_OUT) or ".", exist_ok=True)
            with open(WHOIS_OUT, "a") as f_out:
                for fut in as_completed(futures):
                    it = futures[fut]
                    try:
                        res = fut.result()
                    except Exception as e:
                        res = {"value": it.get("value"), "type": it.get("type"), "timestamp": datetime.utcnow().isoformat() + "Z", "whois": {"error": str(e)}}
                    # Append to JSONL
                    f_out.write(json.dumps(res) + "\n")
                    # Update caches in memory
                    value_key = res["value"]
                    whois_cache[value_key] = res.get("whois") or {}
                    # Also merge into enrich_cache entry
                    try:
                        merge_whois_into_enrich_cache(enrich_cache, it, res.get("whois") or {})
                    except Exception:
                        pass

                    completed += 1
                    if completed % 10 == 0 or completed == len(to_run):
                        print(f"[INFO] Completed {completed}/{len(to_run)}")

    # Save caches
    try:
        save_json(WHOIS_CACHE, whois_cache)
        print(f"[INFO] WHOIS cache -> {WHOIS_CACHE}")
    except Exception as e:
        print(f"[WARN] Failed saving WHOIS cache: {e}")

    if args.merge:
        try:
            save_json(ENRICH_CACHE, enrich_cache)
            print(f"[INFO] Merged WHOIS into enrich cache -> {ENRICH_CACHE}")
        except Exception as e:
            print(f"[WARN] Failed to save enrich cache: {e}")

    print("[DONE] whois_on_demand completed.")


if __name__ == "__main__":
    main()
