#!/usr/bin/env python3
"""
geopandas_app.py

Simple Flask app serving the geo dashboard.

- Robust template folder resolution (relative to script)
- Route aliases: "/" -> "/dashboard-geo"
- Helpful startup prints and basic error handling
"""

import argparse
import json
import socket
import sys
from pathlib import Path
from typing import List, Dict, Any

from flask import Flask, jsonify, request, render_template

# Resolve paths relative to this file so running from another cwd still works
ROOT = Path(__file__).resolve().parent
TEMPLATES_DIR = ROOT / "templates"

STORE_INDEX = ROOT / "store" / "iocs_indexed.json"
CACHE_POINTS = ROOT / "store" / "iocs_points_cache.geojson"
FOLIUM_MAP_OUT = ROOT / "store" / "iocs_map.html"

# Create Flask app with explicit template folder path
APP = Flask(__name__, template_folder=str(TEMPLATES_DIR))


def find_free_port(start_port=5000, max_port=5100):
    """Return an available port or None."""
    for port in range(start_port, max_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return None


def load_indexed_iocs() -> List[Dict[str, Any]]:
    if not STORE_INDEX.exists():
        return []
    try:
        with open(STORE_INDEX, "r") as f:
            return json.load(f)
    except Exception:
        return []


def extract_geo_points(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for it in iocs:
        try:
            geo = it.get("enrichment", {}).get("geoip", {})
            loc = geo.get("location") or {}
            lat = loc.get("lat")
            lon = loc.get("lon")
            if lat is None or lon is None:
                continue
            props = {
                "value": it.get("value"),
                "type": it.get("type"),
                "score": it.get("score", 0),
                "risk_bucket": it.get("risk_bucket"),
                "source": it.get("source"),
                "isp": (it.get("enrichment", {}).get("abuseipdb", {}) or {}).get("isp"),
                "ptr": (it.get("enrichment", {}).get("reverse", {}) or {}).get("ptr"),
                "country": geo.get("country"),
                "country_iso": geo.get("country_iso"),
            }
            out.append({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [float(lon), float(lat)]},
                "properties": props,
            })
        except Exception:
            continue
    return out


def build_geojson_feature_collection(features: List[Dict[str, Any]]):
    return {"type": "FeatureCollection", "features": features}


def top_countries_counts(features: List[Dict[str, Any]], top_n=20):
    counts = {}
    for f in features:
        c = (f.get("properties", {}).get("country_iso") or "UN").upper()
        counts[c] = counts.get(c, 0) + 1
    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    return sorted_items


@APP.route("/api/geo/stats")
def api_geo_stats():
    iocs = load_indexed_iocs()
    features = extract_geo_points(iocs)
    return jsonify({
        "total_indexed": len(iocs),
        "geo_points": len(features),
        "top_countries": top_countries_counts(features, top_n=20),
    })


@APP.route("/api/geo/points")
def api_geo_points():
    q_max = int(request.args.get("max_points") or 5000)
    risk_filter = (request.args.get("risk") or "all").lower()
    min_score = int(request.args.get("min_score") or 0)

    iocs = load_indexed_iocs()
    if risk_filter != "all":
        iocs = [i for i in iocs if (i.get("risk_bucket") or "").lower() == risk_filter]

    features = extract_geo_points(iocs)
    features_sorted = sorted(features, key=lambda f: f.get("properties", {}).get("score", 0), reverse=True)
    if len(features_sorted) > q_max:
        features_sorted = features_sorted[:q_max]

    fc = build_geojson_feature_collection(features_sorted)
    try:
        CACHE_POINTS.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_POINTS, "w") as f:
            json.dump(fc, f)
    except Exception:
        pass

    return jsonify(fc)


@APP.route("/api/geo/regenerate", methods=["POST"])
def api_geo_regenerate():
    body = {}
    try:
        body = request.get_json() or {}
    except Exception:
        body = {}
    max_points = int(body.get("max_points") or 5000)
    build_map = bool(body.get("build_map"))

    iocs = load_indexed_iocs()
    features = extract_geo_points(iocs)
    features_sorted = sorted(features, key=lambda f: f.get("properties", {}).get("score", 0), reverse=True)[:max_points]
    fc = build_geojson_feature_collection(features_sorted)

    try:
        CACHE_POINTS.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_POINTS, "w") as f:
            json.dump(fc, f)
    except Exception as e:
        return jsonify({"ok": False, "error": f"cache_write_failed: {e}"}), 500

    result = {"ok": True, "cached_points": len(features_sorted)}
    if build_map:
        try:
            import folium
            from folium.plugins import MarkerCluster
            lats = [feat["geometry"]["coordinates"][1] for feat in features_sorted]
            lons = [feat["geometry"]["coordinates"][0] for feat in features_sorted]
            center = [ (sum(lats)/len(lats)) if lats else 0, (sum(lons)/len(lons)) if lons else 0 ]
            m = folium.Map(location=center, zoom_start=2, tiles="OpenStreetMap")
            mc = MarkerCluster().add_to(m)
            for f in features_sorted:
                props = f["properties"]
                lon, lat = f["geometry"]["coordinates"]
                popup = folium.Popup(html=f"<b>{props.get('value')}</b><br/>score: {props.get('score')}<br/>risk: {props.get('risk_bucket')}", max_width=300)
                folium.CircleMarker(location=[lat, lon], radius=5, color="#333", fill=True,
                                    fill_color="#ff5252" if props.get("risk_bucket")=="high" else ("#ffb020" if props.get("risk_bucket")=="medium" else "#6cc070"),
                                    fill_opacity=0.9, popup=popup).add_to(mc)
            FOLIUM_MAP_OUT.parent.mkdir(parents=True, exist_ok=True)
            m.save(str(FOLIUM_MAP_OUT))
            result["map_html"] = str(FOLIUM_MAP_OUT)
        except Exception as e:
            result["map_error"] = f"folium_failed: {e}"

    return jsonify(result)


# Alias root to dashboard route to avoid "not found"
@APP.route("/")
def dashboard_root():
    return render_template("geo_dashboard.html")


@APP.route("/dashboard-geo")
def dashboard_geo():
    return render_template("geo_dashboard.html")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--start-port", type=int, default=5000)
    p.add_argument("--max-port", type=int, default=5100)
    p.add_argument("--regenerate", action="store_true", help="Regenerate cache on startup")
    p.add_argument("--max-points", type=int, default=5000)
    p.add_argument("--host", default="127.0.0.1")
    return p.parse_args()


def main():
    args = parse_args()
    port = args.port or find_free_port(args.start_port, args.max_port)
    if port is None:
        print(f"No free port found in range {args.start_port}-{args.max_port}", file=sys.stderr)
        sys.exit(1)

    # Optionally regenerate cache on startup
    if args.regenerate:
        with APP.test_request_context():
            try:
                api_geo_regenerate()
                print("Cache regenerated (no map) on startup.")
            except Exception as e:
                print("Startup regenerate failed:", e)

    url = f"http://{args.host}:{port}/"
    print(f"Starting geo dashboard -> {url}  (also available at /dashboard-geo)")
    APP.run(host=args.host, port=port, debug=True)


if __name__ == "__main__":
    main()
