# stix_exporter.py
"""
Produce a STIX 2.1 bundle from ./store/iocs_indexed.json (or ./store/iocs.json).
Fixes pattern formatting: valid STIX object/property names and quoting for hash algorithms.
"""
import json
import os
from datetime import datetime, timezone
from stix2 import Bundle, Indicator, TLP_WHITE, exceptions as stix_exceptions

STORE_INDEXED = "./store/iocs_indexed.json"
FALLBACK_STORE = "./store/iocs.json"
OUTPUT = "./store/iocs_stix.json"

# mapping for MITRE (optional)
MITRE_MAPPING = {
    "ip": ["T1071", "T1070"],
    "domain": ["T1071.001"],
    "hash": ["T1204"]
}

HASH_ALG_MAP = {
    32: "MD5",
    40: "SHA-1",
    64: "SHA-256"
}


def guess_hash_algo(hash_value):
    if not hash_value:
        return None
    h = hash_value.strip().lower()
    L = len(h)
    return HASH_ALG_MAP.get(L)


def ioc_to_pattern(ioc):
    t = ioc.get("type")
    v = ioc.get("value")
    if not t or not v:
        raise ValueError("missing type or value")

    if t == "ip":
        # choose ipv4 vs ipv6 (very simple check)
        if ":" in v:
            return f"[ipv6-addr:value = '{v}']"
        else:
            return f"[ipv4-addr:value = '{v}']"
    if t == "domain":
        # domain-name observable
        return f"[domain-name:value = '{v}']"
    if t == "hash" or t == "file_hash" or t == "md5" or t == "sha256":
        alg = guess_hash_algo(v)
        if not alg:
            # fallback: try SHA-256 if length matches else raise
            raise ValueError("Unknown hash algorithm/length for value")
        # correct quoting for algorithm name in stix pattern
        return f"[file:hashes.'{alg}' = '{v}']"
    # fallback generic string match (less ideal, but valid pattern using domain-name)
    return f"[domain-name:value = '{v}']"


def map_mitre(ioc_type):
    return MITRE_MAPPING.get(ioc_type, [])


def create_indicator(obj):
    # obj expected to be an indexed IOC entry (from run_index)
    name = f"{obj.get('type')}::{obj.get('value')}"
    description = obj.get("score_breakdown", {}).get("final_score", None)
    try:
        pattern = ioc_to_pattern(obj)
    except Exception as e:
        raise ValueError(f"Cannot build pattern for {name}: {e}")

    kwargs = {
        "name": name,
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "description": f"Enriched IOC. Confidence: {obj.get('score', 0)}",
        "created": datetime.now(timezone.utc),
        "modified": datetime.now(timezone.utc),
        "labels": ["malicious-activity"],
        "valid_from": datetime.now(timezone.utc),
        # NOTE: object_marking_refs requires existing marking definition id. Use TLP_WHITE
        "object_marking_refs": [TLP_WHITE["id"]],
    }
    # custom properties
    mitre = map_mitre(obj.get("type"))
    if mitre:
        kwargs["x_mitre_attack_ids"] = mitre

    # allow custom so x_mitre_attack_ids accepted
    try:
        return Indicator(**kwargs, allow_custom=True)
    except stix_exceptions.InvalidValueError as e:
        # re-raise with detail
        raise ValueError(f"stix2 validation error for {name}: {e}")
    except stix_exceptions.ExtraPropertiesError as e:
        # should not happen with allow_custom, but handle
        raise ValueError(f"stix2 extra props for {name}: {e}")


def main():
    store_file = STORE_INDEXED if os.path.exists(STORE_INDEXED) else (FALLBACK_STORE if os.path.exists(FALLBACK_STORE) else None)
    if not store_file:
        print("No source file found (iocs_indexed.json or iocs.json). Run pipeline first.")
        return

    with open(store_file, "r") as f:
        objs = json.load(f)

    indicators = []
    skipped = 0
    for o in objs:
        try:
            ind = create_indicator(o)
            indicators.append(ind)
        except Exception as e:
            skipped += 1
            print(f"Skipping IOC {o.get('type')}::{o.get('value')}: {e}")

    bundle = Bundle(objects=indicators, allow_custom=True)
    with open(OUTPUT, "w") as f:
        f.write(bundle.serialize(pretty=True))
    print(f"STIX bundle written: {OUTPUT} (indicators: {len(indicators)}, skipped: {skipped})")


if __name__ == "__main__":
    main()
