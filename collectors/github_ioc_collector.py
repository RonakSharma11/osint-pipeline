# collectors/github_ioc_collector.py
"""
Simple Github raw-file collector.
In DEMO_MODE this reads sample_data/demo_iocs.json (no network).
In production, configure REPO_RAW_URLS with raw.githubusercontent URLs.
"""
import os
import json
import re
import aiohttp
import logging
from .base_collector import BaseCollector
from utils.config import Config

logger = logging.getLogger("collectors.github")

REPO_RAW_URLS = [
    # Example:
    # "https://raw.githubusercontent.com/username/repo/main/iocs.txt"
]

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HASH_RE = re.compile(r"^[a-f0-9]{32,128}$", re.I)
DOMAIN_RE = re.compile(r"[a-z0-9\.-]+\.[a-z]{2,}", re.I)

class GithubIOCCollector(BaseCollector):
    def __init__(self, urls=None, cache=None):
        super().__init__(cache)
        self.urls = urls or REPO_RAW_URLS

    async def collect(self):
        if Config.DEMO_MODE:
            path = "sample_data/demo_iocs.json"
            if os.path.exists(path):
                with open(path, "r") as f:
                    data = json.load(f)
                    logger.info("GithubIOCCollector (demo) loaded %d iocs from %s", len(data), path)
                    return data
            logger.info("GithubIOCCollector (demo) found no sample file")
            return []

        # production: fetch remote raw files
        if not Config.ALLOW_PUBLIC_FETCH:
            logger.warning("Public fetch disabled; skipping GitHub collector")
            return []

        results = []
        async with aiohttp.ClientSession() as sess:
            for url in self.urls:
                try:
                    async with sess.get(url, timeout=20) as resp:
                        if resp.status != 200:
                            logger.warning("Non-200 from %s: %s", url, resp.status)
                            continue
                        text = await resp.text()
                        for line in text.splitlines():
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            if IP_RE.match(line):
                                results.append({"type":"ip","value":line,"source":url})
                            elif HASH_RE.match(line):
                                results.append({"type":"hash","value":line,"source":url})
                            elif DOMAIN_RE.search(line):
                                results.append({"type":"domain","value":line,"source":url})
                except Exception as e:
                    logger.exception("Error fetching %s: %s", url, e)
        # dedupe
        unique = {}
        for r in results:
            unique[(r["type"], r["value"])] = r
        return list(unique.values())
