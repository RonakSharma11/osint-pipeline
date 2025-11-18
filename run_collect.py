# run_collect.py
"""
Simple entrypoint for collectors. Ensures the repo root is on sys.path
so that `from collectors.foo import BarCollector` works reliably.

This file intentionally keeps collector invocation simple and non-destructive.
It expects individual collector modules to exist under ./collectors/.

Usage:
  python run_collect.py
  python run_collect.py --limit 1000
"""
import os
import sys
import json
import argparse
from importlib import import_module

# Ensure repo root (script directory) is in sys.path
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Also support running when current working directory is elsewhere
if os.getcwd() not in sys.path:
    sys.path.insert(0, os.getcwd())

STORE_OUT = os.path.join(REPO_ROOT, "store", "iocs.json")
COLLECTORS = [
    # name of modules to try to import from collectors/
    "github_ioc_collector",
    "otx_collector",
    "abuseipdb_collector",
    "rss_collector",
    # add other collectors that you maintain under collectors/
    # "urlhaus_collector",  # if you create this file later
    # "malwarebazaar_collector",
    # "phishtank_collector",
]

def load_collectors():
    discovered = []
    for name in COLLECTORS:
        try:
            mod = import_module(f"collectors.{name}")
            # many collector modules expose a 'collect' function
            if hasattr(mod, "collect"):
                discovered.append(mod)
            else:
                print(f"Collector module collectors.{name} imported but has no collect() function — skipping.")
        except ModuleNotFoundError:
            print(f"Collector module collectors.{name} not found — skipping.")
        except Exception as e:
            print(f"Error importing collectors.{name}: {e} — skipping.")
    return discovered

def run_collect(limit=None):
    collectors = load_collectors()
    all_iocs = []
    for c in collectors:
        try:
            print(f"Running collector: {c.__name__}")
            items = c.collect(limit=limit) if hasattr(c, "collect") else []
            print(f"  -> collected {len(items)} items from {c.__name__}")
            all_iocs.extend(items)
        except TypeError:
            # fallback if collect() signature different
            try:
                items = c.collect()
                all_iocs.extend(items)
            except Exception as e:
                print(f"  -> error running {c.__name__}: {e}")
        except Exception as e:
            print(f"  -> error running {c.__name__}: {e}")

    # deduplicate by (type,value)
    seen = set()
    unique = []
    for i in all_iocs:
        if not isinstance(i, dict):
            continue
        key = (i.get("type"), i.get("value"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(i)

    os.makedirs(os.path.dirname(STORE_OUT), exist_ok=True)
    with open(STORE_OUT, "w") as f:
        json.dump(unique, f, indent=2)

    print(f"Collected {len(unique)} unique IOCs -> {STORE_OUT}")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--limit", type=int, default=None, help="Optional per-collector limit")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    run_collect(limit=args.limit)
