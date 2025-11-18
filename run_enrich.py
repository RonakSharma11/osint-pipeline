# run_enrich.py
"""
Async prioritized enricher with detailed per-step progress reporting.

Usage:
  python run_enrich.py --limit 200 --concurrency 50 --skip-whois --skip-http

Behavior:
 - Shows per-step progress messages like:
   [ 12/500] domain::example.com - DNS ✓
   [ 12/500] domain::example.com - WHOIS ✓
   [ 12/500] domain::example.com - OTX ✓
   [ 12/500] domain::example.com - COMPLETE ✓

 - Writes incremental JSONL to ./store/iocs_enriched.jsonl and final JSON to ./store/iocs_enriched.json
 - Uses a cache ./store/enrich_cache.json to avoid redoing work
"""

import os
import json
import asyncio
import aiohttp
import argparse
import time
from functools import partial
from math import ceil

from collectors.enrich import enrich_local
from utils.config import Config

STORE_IN = "./store/iocs.json"
OUT_JSONL = "./store/iocs_enriched.jsonl"
OUT_JSON = "./store/iocs_enriched.json"
CACHE_FILE = "./store/enrich_cache.json"

# -------------------- cache helpers --------------------
def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_cache(cache):
    tmp = CACHE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cache, f, indent=2)
    os.replace(tmp, CACHE_FILE)

# -------------------- HTTP helpers --------------------
async def http_otx_lookup(session, domain):
    key = Config.OTX_API_KEY
    if not key:
        return {}
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": key}
    try:
        async with session.get(url, headers=headers, timeout=12) as resp:
            if resp.status == 200:
                return await resp.json()
    except Exception:
        return {}
    return {}

async def http_abuseipdb_lookup(session, ip):
    key = Config.ABUSEIPDB_API_KEY
    if not key:
        return {}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Key": key, "Accept": "application/json"}
    try:
        async with session.get(url, params=params, headers=headers, timeout=12) as resp:
            if resp.status == 200:
                return await resp.json()
    except Exception:
        return {}
    return {}

# -------------------- progress printer --------------------
async def progress_printer(queue: asyncio.Queue):
    """
    Consume progress messages and print them neatly.
    Message format (dict): {"idx": int, "total": int, "id": "type::value", "step": "...", "status": "done"}
    """
    while True:
        msg = await queue.get()
        if msg is None:  # sentinel to stop
            queue.task_done()
            break
        # Format: [ 12/500] domain::example.com - DNS ✓
        idx = msg.get("idx")
        total = msg.get("total")
        key = msg.get("id")
        step = msg.get("step")
        status = msg.get("status")
        # use checkmark for done
        mark = "✓" if status == "done" else status
        if idx is not None and total is not None:
            print(f"[{idx:4d}/{total}] {key} - {step} {mark}")
        else:
            print(f"[    ] {key} - {step} {mark}")
        queue.task_done()

# -------------------- worker --------------------
async def enrich_worker(ioc, idx, total, session, sem: asyncio.Semaphore, cache, progress_queue: asyncio.Queue, skip_whois=False, skip_http=False):
    key = f"{ioc.get('type')}::{ioc.get('value')}"
    # If cached, report and return
    if key in cache:
        # report cached complete - but still print inline steps quickly
        if progress_queue:
            await progress_queue.put({"idx": idx, "total": total, "id": key, "step": "CACHED", "status": "done"})
            await progress_queue.put({"idx": idx, "total": total, "id": key, "step": "COMPLETE", "status": "done"})
        return cache[key]

    async with sem:
        # local enrich (DNS, WHOIS, reverse, geo). This reports its own steps to the progress_queue.
        local = await enrich_local(ioc, progress_queue=progress_queue, skip_whois=skip_whois)
        enrichment = local.get("enrichment", {}) or {}

        # optional HTTP enrich
        if not skip_http:
            if ioc.get("type") == "domain":
                otx = await http_otx_lookup(session, ioc.get("value"))
                if otx:
                    pulse_count = otx.get("pulse_info", {}).get("count") or otx.get("pulse_info", {}).get("indicator_count") or 0
                    enrichment["otx"] = {"raw": otx, "count": pulse_count}
                    enrichment["otx_count"] = pulse_count
                # passive_dns may be present in OTX
                if isinstance(otx, dict) and otx.get("passive_dns"):
                    enrichment["passive_dns"] = otx.get("passive_dns")
                if progress_queue:
                    await progress_queue.put({"idx": idx, "total": total, "id": key, "step": "OTX", "status": "done"})
            elif ioc.get("type") == "ip":
                abuse = await http_abuseipdb_lookup(session, ioc.get("value"))
                if abuse and isinstance(abuse, dict):
                    data = abuse.get("data") or {}
                    enrichment["abuseipdb"] = data
                    sev = data.get("abuseConfidenceScore") or data.get("abuseConfidence")
                    if sev is not None:
                        enrichment["abuseipdb_score"] = int(sev)
                if progress_queue:
                    await progress_queue.put({"idx": idx, "total": total, "id": key, "step": "ABUSEIPDB", "status": "done"})

        # add sources_count
        enrichment["sources_count"] = ioc.get("sources_count") or ioc.get("sources") or enrichment.get("sources_count", 1)

        result = {
            "type": ioc.get("type"),
            "value": ioc.get("value"),
            "source": ioc.get("source"),
            "first_seen": ioc.get("first_seen"),
            "last_seen": ioc.get("last_seen"),
            "enrichment": enrichment
        }

        cache[key] = result

        # final complete message
        if progress_queue:
            await progress_queue.put({"idx": idx, "total": total, "id": key, "step": "COMPLETE", "status": "done"})

        return result

# -------------------- main async flow --------------------
async def main_async(limit, concurrency, skip_whois, skip_http):
    # load input
    try:
        with open(STORE_IN, "r") as f:
            all_iocs = json.load(f)
    except Exception as e:
        print("ERROR: could not load input iocs:", e)
        return

    # prioritize (sources_count desc, then as-is)
    def keyfn(i):
        sc = i.get("sources_count") or i.get("sources") or 0
        return -int(sc)
    all_iocs_sorted = sorted(all_iocs, key=keyfn)
    to_process = all_iocs_sorted[:limit]
    total = len(to_process)
    if total == 0:
        print("No IOCs to process (empty input or limit=0).")
        return

    cache = load_cache()

    # prepare progress queue and printer
    progress_queue = asyncio.Queue()
    printer_task = asyncio.create_task(progress_printer(progress_queue))

    timeout = aiohttp.ClientTimeout(total=20)
    sem = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = []
        for idx, ioc in enumerate(to_process, start=1):
            tasks.append(asyncio.create_task(enrich_worker(ioc, idx, total, session, sem, cache, progress_queue, skip_whois=skip_whois, skip_http=skip_http)))

        # gather results in chunks so we can write incremental JSONL
        results = []
        BATCH = 100
        for i in range(0, len(tasks), BATCH):
            chunk = tasks[i:i+BATCH]
            chunk_res = await asyncio.gather(*chunk)
            results.extend(chunk_res)
            # write chunk to JSONL
            with open(OUT_JSONL, "a") as outf:
                for r in chunk_res:
                    outf.write(json.dumps(r) + "\n")
            # persist cache incrementally
            save_cache(cache)
            print(f"Enriched chunk {i//BATCH + 1} ({len(results)}/{total})")

    # finalize: write aggregated JSON
    try:
        with open(OUT_JSON, "w") as f:
            json.dump(list(cache.values()), f, indent=2)
        print(f"Enrichment complete: wrote {OUT_JSON}")
    except Exception as e:
        print("ERROR writing final JSON:", e)

    # stop the printer
    await progress_queue.put(None)
    await printer_task

# -------------------- CLI parse and entry --------------------
def parse_args():
    p = argparse.ArgumentParser(description="Async enrichment runner with detailed progress")
    p.add_argument("--limit", type=int, default=500, help="Max IOCs to enrich (default 500)")
    p.add_argument("--concurrency", type=int, default=50, help="Concurrent workers (default 50)")
    p.add_argument("--skip-whois", action="store_true", help="Do not perform WHOIS (faster)")
    p.add_argument("--skip-http", action="store_true", help="Skip external HTTP APIs (OTX/AbuseIPDB)")
    return p.parse_args()

def main():
    args = parse_args()
    os.makedirs("./store", exist_ok=True)
    # clear JSONL if starting fresh
    if os.path.exists(OUT_JSONL):
        os.remove(OUT_JSONL)
    start = time.time()
    asyncio.run(main_async(args.limit, args.concurrency, args.skip_whois, args.skip_http))
    print("Elapsed: %.1f seconds" % (time.time() - start))

if __name__ == "__main__":
    main()
