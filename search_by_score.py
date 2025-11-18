# search_by_score.py
"""
Search indexed IOCs by confidence score.

Usage:
  python search_by_score.py --min 70 --max 100 --type domain --limit 200

Outputs JSON array to stdout (pretty). You can pipe to jq or redirect to a file.
"""

import json
import argparse
import sys
from pathlib import Path

INDEX_FILE = Path("./store/iocs_indexed.json")

def load_index(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: index file {path} not found. Run run_index.py first.", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"ERROR reading index file: {e}", file=sys.stderr)
        sys.exit(3)

def matches(doc, min_score, max_score, ioc_type, keyword):
    score = doc.get("score", 0)
    if score < min_score or score > max_score:
        return False
    if ioc_type and doc.get("type") != ioc_type:
        return False
    if keyword and keyword.lower() not in doc.get("value", "").lower():
        return False
    return True

def main():
    p = argparse.ArgumentParser(description="Search indexed IOCs by confidence score")
    p.add_argument("--min", type=int, default=0, help="Minimum score (inclusive). Default 0")
    p.add_argument("--max", type=int, default=100, help="Maximum score (inclusive). Default 100")
    p.add_argument("--type", type=str, choices=["domain", "ip", "hash", "url"], default=None, help="IOC type to filter")
    p.add_argument("--keyword", type=str, default=None, help="Substring to match in IOC value")
    p.add_argument("--limit", type=int, default=100, help="Maximum results to return")
    p.add_argument("--index", type=str, default=str(INDEX_FILE), help="Path to indexed JSON file")
    args = p.parse_args()

    docs = load_index(args.index)
    results = []
    for doc in docs:
        if matches(doc, args.min, args.max, args.type, args.keyword):
            results.append(doc)
            if len(results) >= args.limit:
                break

    # pretty print results
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
