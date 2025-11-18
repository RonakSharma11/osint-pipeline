# dedup_index/indexer.py
"""
Indexer: upsert enriched IOCs into a local SQLite store (and optionally OpenSearch).
Provides:
  - Indexer.upsert(ioc, enrichment) -> merged document
  - Indexer.list_all() -> list of docs
  - Indexer.get(type, value) -> doc or None
  - Indexer.export_json(path) -> write all docs to JSON file
"""
import os
import json
import sqlite3
import logging
from datetime import datetime

from utils.config import Config
from dedup_index.deduplicator import canonicalize, compute_confidence, make_cluster_id

logger = logging.getLogger("indexer")

STORE_DIR = "./store"
os.makedirs(STORE_DIR, exist_ok=True)
SQLITE_DB = os.path.join(STORE_DIR, "iocs.db")
JSON_FALLBACK = os.path.join(STORE_DIR, "iocs.json")

class Indexer:
    def __init__(self):
        self.use_opensearch = False  # placeholder: can enable later
        # initialize sqlite
        self._ensure_sqlite()

    def _ensure_sqlite(self):
        conn = sqlite3.connect(SQLITE_DB)
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id TEXT PRIMARY KEY,
            type TEXT,
            value TEXT,
            document TEXT,
            last_updated TEXT
        )""")
        conn.commit()
        conn.close()

    def _read_sql_doc(self, doc_id):
        conn = sqlite3.connect(SQLITE_DB)
        cur = conn.cursor()
        cur.execute("SELECT document FROM iocs WHERE id=?", (doc_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except Exception:
            return None

    def _write_sql_doc(self, doc_id, doc):
        conn = sqlite3.connect(SQLITE_DB)
        cur = conn.cursor()
        jsondoc = json.dumps(doc, default=str)
        cur.execute("INSERT OR REPLACE INTO iocs (id,type,value,document,last_updated) VALUES (?,?,?,?,?)",
                    (doc_id, doc.get("type"), doc.get("value"), jsondoc, datetime.utcnow().isoformat()+"Z"))
        conn.commit()
        conn.close()

    def upsert(self, ioc, enrichment):
        """
        Canonicalize, merge enrichment with any existing doc, compute confidence,
        attach cluster id, persist to sqlite, and return the final doc.
        """
        if not ioc or "type" not in ioc or "value" not in ioc:
            logger.warning("Invalid IOC for upsert: %s", ioc)
            return None

        can = canonicalize(ioc)
        doc_id = f"{can['type']}::{can['value']}"
        existing = self._read_sql_doc(doc_id)
        if existing:
            # merge enrichment: existing.enrichment updated with new enrichment keys
            merged = dict(existing)
            merged_enr = merged.get("enrichment", {}) or {}
            # merge dicts - prefer new values if present
            for k,v in (enrichment or {}).items():
                try:
                    if v is None:
                        continue
                    if isinstance(v, dict) and isinstance(merged_enr.get(k), dict):
                        merged_enr[k].update(v)
                    else:
                        merged_enr[k] = v
                except Exception:
                    merged_enr[k] = v
            merged["enrichment"] = merged_enr
            merged["sources_count"] = max(int(merged.get("sources_count",1)), int(enrichment.get("sources_count",1) if enrichment else 1))
            merged["confidence"] = max(int(merged.get("confidence",0)), compute_confidence(merged_enr))
            # recompute cluster id
            merged["cluster_id"] = make_cluster_id(merged)
            # update persisted doc
            self._write_sql_doc(doc_id, merged)
            logger.info("Updated IOC %s (merged)", doc_id)
            return merged

        # new document
        doc = {
            "id": doc_id,
            "type": can["type"],
            "value": can["value"],
            "first_seen": datetime.utcnow().isoformat()+"Z",
            "last_seen": datetime.utcnow().isoformat()+"Z",
            "enrichment": enrichment or {},
            "sources_count": int((enrichment or {}).get("sources_count", 1)),
        }
        doc["confidence"] = compute_confidence(doc["enrichment"])
        doc["cluster_id"] = make_cluster_id(doc)
        # persisted
        self._write_sql_doc(doc_id, doc)
        logger.info("Inserted new IOC %s", doc_id)
        return doc

    def list_all(self):
        """
        Return list of all stored documents (from sqlite).
        """
        try:
            conn = sqlite3.connect(SQLITE_DB)
            cur = conn.cursor()
            cur.execute("SELECT document FROM iocs")
            rows = cur.fetchall()
            conn.close()
            docs = [json.loads(r[0]) for r in rows]
            return docs
        except Exception as e:
            logger.exception("list_all error: %s", e)
            # fallback to JSON file
            if os.path.exists(JSON_FALLBACK):
                with open(JSON_FALLBACK) as f:
                    return json.load(f)
            return []

    def get(self, typ, value):
        doc_id = f"{typ}::{value}"
        return self._read_sql_doc(doc_id)

    def export_json(self, path=None):
        """
        Dump all docs to a JSON file for quick viewing / STIX export.
        """
        docs = self.list_all()
        path = path or JSON_FALLBACK
        with open(path, "w") as f:
            json.dump(docs, f, indent=2, default=str)
        logger.info("Exported %d docs to %s", len(docs), path)
        return path
