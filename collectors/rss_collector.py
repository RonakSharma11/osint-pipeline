# collectors/rss_collector.py
"""
RSS collector: in DEMO_MODE returns empty (to avoid live fetch),
otherwise fetches configured feeds and extracts IP/domain/hash patterns.
"""
import asyncio
import feedparser
import re
import logging
from .base_collector import BaseCollector
from utils.config import Config

logger = logging.getLogger("collectors.rss")

FEEDS = [
    "https://www.us-cert.gov/ncas/alerts.xml",
    "https://isc.sans.edu/rssfeed.xml",
]

IP_RE = re.compile(r"((?:\d{1,3}\.){3}\d{1,3})")
DOMAIN_RE = re.compile(r"([a-z0-9\.-]+\.[a-z]{2,})", re.I)
HASH_RE = re.compile(r"\b([A-Fa-f0-9]{32,64})\b")

class RSSCollector(BaseCollector):
    def __init__(self, feeds=None, cache=None):
        super().__init__(cache)
        self.feeds = feeds or FEEDS

    async def collect(self):
        if Config.DEMO_MODE:
            logger.info("RSSCollector running in DEMO_MODE -> returning empty list")
            return []

        if not Config.ALLOW_PUBLIC_FETCH:
            logger.warning("Public fetch disabled; RSSCollector returning empty list")
            return []

        loop = asyncio.get_event_loop()
        results = []
        for feed in self.feeds:
            try:
                parsed = await loop.run_in_executor(None, feedparser.parse, feed)
                for entry in parsed.entries:
                    text = (entry.get("title","") + " " + entry.get("summary","")).strip()
                    for ip in IP_RE.findall(text):
                        results.append({"type":"ip","value":ip,"source":feed,"raw":entry})
                    for dom in DOMAIN_RE.findall(text):
                        results.append({"type":"domain","value":dom,"source":feed,"raw":entry})
                    for h in HASH_RE.findall(text):
                        results.append({"type":"hash","value":h,"source":feed,"raw":entry})
            except Exception as e:
                logger.exception("RSS parse error for %s: %s", feed, e)

        # dedupe
        seen = set()
        dedup = []
        for r in results:
            k = (r["type"], r["value"])
            if k not in seen:
                seen.add(k)
                dedup.append(r)
        return dedup
