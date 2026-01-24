# OSINT Pipeline

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-green.svg)](https://www.python.org/)

---

## Table of contents

1. [Overview](#overview)
2. [Quick start (VS Code)](#quick-start-vs-code)
3. [Configuration & secrets (safe GitHub practices)](#configuration--secrets-safe-github-practices)
4. [Run the pipeline (common commands)](#run-the-pipeline-common-commands)
5. [Geo visualization & Flask UI](#geo-visualization--flask-ui)
6. [Testing & validation](#testing--validation)
7. [Production / deployment tips](#production--deployment-tips)
8. [Troubleshooting](#troubleshooting)
9. [Contributing](#contributing)
10. [License & acknowledgements](#license--acknowledgements)

---

## Overview

This repository implements a practical, production-oriented OSINT threat intelligence pipeline:

* **Collectors:** RSS, GitHub IOCs, AlienVault OTX (optional), AbuseIPDB (optional), public blocklists.
* **Enrichers:** WHOIS (on-demand for high-risk), MaxMind GeoIP (optional), DNS, passive DNS (crt.sh / other), AbuseIPDB lookups.
* **Indexing:** OpenSearch recommended (fast + scalable). SQLite fallback available for local/demo.
* **Exports:** STIX 2.1 bundles, GeoJSON, interactive Folium maps, weekly report generator.
* **Web UI:** FastAPI / Flask front-end for exploring IOCs and filters.
* **Scheduler / caching:** APScheduler + Redis optional caching for rate-limited APIs.
* **Safety:** Designed to run WHOIS only for `high` risk to save API/time and reduce unnecessary queries.

This README gives step-by-step commands, security guidance (so you never leak API tokens), and commands to reproduce the main outputs.

---

## Quick start (VS Code)

1. Clone and open in VS Code:

```bash
git clone https://github.com/RonakSharma11/osint-pipeline.git
cd osint-pipeline
code .
```

2. Copy the example env and edit the values (do **not** commit `.env`):

```bash
cp .env.example .env
# Edit .env with your editor and add your API keys locally
```

3. Create a venv, activate and install deps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

4. Optional: install GeoLite2 (if you want local GeoIP fallback):

* Register at MaxMind, download GeoLite2-City.mmdb and place into `data/GeoLite2-City.mmdb`
* Add `data/` to `.gitignore` (already included).

5. Start the web UI (example):

```bash
# default app.py finds an open port and launches Flask; adjust host/port via .env or CLI if needed
python app.py
# or run geopandas Flask app:
python geopandas_app.py
```

---

## Configuration & secrets (safe GitHub practices)

**Do not commit secrets.** Follow this checklist before pushing:

1. Ensure `.env` is in `.gitignore`. Keep only `.env.example` in the repo.
2. Use GitHub Secrets (recommended) for CI / Actions. In your workflow reference secrets with `${{ secrets.MY_KEY }}`.
3. If a secret was accidentally committed, *purge it from history* (see step-by-step below).

### Add `.gitignore` (example)

```gitignore
.env
.venv/
data/GeoLite2-City.mmdb
*.db
store/*.db
store/*.sqlite
store/*.pem
node_modules/
.DS_Store
```

### Removing accidentally committed secrets

If you accidentally committed `.env` or keys, remove and purge history:

**Quick remove from latest commit (if just added):**

```bash
git rm --cached .env
git commit -m "Remove .env from repo"
git push origin main
```

**Purge from entire history (recommended tools):**

* **BFG Repo-Cleaner** (easier):

```bash
# Install BFG (https://rtyley.github.io/bfg-repo-cleaner/)
# Replace 'YOUR-PATTERN' with filename or token string
bfg --delete-files .env
# or to replace a secret:
bfg --replace-text passwords.txt

# then:
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push --force
```

* **git filter-repo** (fast & safe):

```bash
# install filter-repo (pip or system-specific)
git filter-repo --invert-paths --paths .env
git push --force
```

> **Important:** Force-pushing rewrites history — coordinate with collaborators and understand consequences.

### Use GitHub Secrets & Actions (example)

* Go to **Repo -> Settings -> Secrets and variables -> Actions -> New repository secret**.
* Name it `ABUSEIPDB_API_KEY` and paste token.
* In `.github/workflows/ci.yml` use:

```yaml
env:
  ABUSEIPDB_API_KEY: ${{ secrets.ABUSEIPDB_API_KEY }}
```

---

## Run the pipeline (common commands)

### Collect → Enrich → Index → Export

```bash
# collect raw IOCs
python run_collect.py

# enrich with concurrency (be mindful of API quotas)
python run_enrich.py --limit 10012 --concurrency 150 --skip-http

# index and compute scores
python run_index.py

# produce STIX bundle
python stix_exporter.py

# generate geo outputs (fills missing coords if you have GeoIP database)
python geopandas_visualize.py --fill-missing --max-points 5000 --choropleth
```

### WHOIS-on-demand (only high risk)

```bash
# whois on demand (default: only risk_bucket == high)
python whois_on_demand.py --concurrency 10 --max 200
```

### Start the Flask dashboard (finds free port automatically)

```bash
python app.py
# or to run on a specific port:
python app.py --port 5001
```

---

## Geo visualization & Flask UI

* `geopandas_visualize.py` creates:

  * `./store/iocs_points_improved.geojson`
  * `./store/iocs_map_improved.html` (interactive folium map)
  * optional `choropleth_improved.png`

* The Flask UI (`app.py`) exposes:

  * `GET /api/iocs` — with query params `?risk=high|medium|low|all`
  * `/` — dashboard (serves `templates/your_dashboard.html`)

**To view generated map**:

```bash
# After geopandas_visualize.py runs
open ./store/iocs_map_improved.html   # macOS
# or
xdg-open ./store/iocs_map_improved.html  # Linux
```

---

## Testing & validation

* Unit tests for scoring components (edge cases):

```bash
pytest tests/test_scoring.py -q
```

* Reproducibility: Include `requirements.txt` and `Dockerfile`. Example test to reproduce top tables:

```bash
jq 'length' ./store/iocs_indexed.json
jq -r 'group_by(.risk_bucket) | map({(.[0].risk_bucket // "unknown"): length}) | add' ./store/iocs_indexed.json
```

* Evaluation notebook: `notebooks/evaluate_scoring.ipynb` (produces confusion matrices, precision/recall, ROC/AUC using silver labels).

---

## Production / deployment tips

* Use **OpenSearch** (or Elasticsearch) for scalable indexing; configure `OPENSEARCH_HOST` in `.env`.
* Run workers using a process manager (systemd, supervisord) or container orchestration (Docker Compose / Kubernetes).
* Use Redis for caching API responses and rate-limited lookups.
* Schedule periodic collection/enrichment via APScheduler or an external cron service.
* Make WHOIS and heavy enrichments **on-demand** to save API usage and analyst time.

### Example Docker Compose (concept)

```yaml
version: "3"
services:
  app:
    build: .
    ports: ["8080:8080"]
    env_file: .env
  redis:
    image: redis:7
  opensearch:
    image: opensearchproject/opensearch:2.10.0
    environment:
      - discovery.type=single-node
```

---

## Troubleshooting (common issues)

* **Port 5000 already in use**

  ```bash
  lsof -i :5000
  kill <PID>
  # or run app on a different port:
  python app.py --port 5001
  ```

* **git push: Permission denied (publickey)**

  * Follow SSH setup steps (generate key, add to GitHub) or use HTTPS + PAT. See section **Configuration & secrets** above.

* **Geo map build fails (branca / colormap error)**

  ```bash
  pip install folium branca matplotlib geopandas
  # ensure versions are compatible; try using the venv from requirements.txt
  ```

* **WHOIS command not found**

  * Install a CLI whois:

    ```bash
    # macOS
    brew install whois
    # Ubuntu
    sudo apt-get install whois
    ```

---

## Contributing

Thanks for your interest! Suggested workflow:

1. Fork the repo.
2. Create a feature branch: `git checkout -b feat/awesome-change`.
3. Add tests and update `requirements.txt` if needed.
4. Open a PR describing changes, link relevant issues and add screenshots of outputs.

Please follow coding style, add unit tests for scoring logic changes, and document breaking changes in `CHANGELOG.md`.


---

## License & acknowledgements

Licensed under MIT. See `LICENSE` for details.

Thanks to the open-source projects that make this possible (Folium, GeoPandas, pycountry, AbuseIPDB/OTX APIs, MaxMind, etc.). Add credits in your paper and README where required.

