# OSINT Pipeline (Production-ready)

## Overview
This repo implements a free/open-source OSINT Threat Intelligence pipeline:
- Collectors: RSS, GitHub, AlienVault OTX (optional), AbuseIPDB (optional), blocklists.
- Enrichers: WHOIS, MaxMind GeoIP (if installed), DNS, crt.sh passive DNS.
- Indexing: OpenSearch (recommended) or SQLite fallback.
- STIX 2.1 export and weekly report generator.
- FastAPI web UI for viewing IOCs.
- Scheduler uses APScheduler; caching via Redis (optional).

## Quick start (VS Code)
1. Clone repo and open in VS Code.
2. Copy `.env.example` to `.env` and edit (set DEMO_MODE=false for production).
3. Create venv & install dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
