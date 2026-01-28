#!/usr/bin/env python3
"""
geopandas_visualize.py — final improved version

Usage examples:
  python geopandas_visualize.py
  python geopandas_visualize.py --fill-missing --geoip-db data/GeoLite2-City.mmdb
  python geopandas_visualize.py --risk high --min-score 50 --max-points 5000 --choropleth --open

Outputs:
  ./store/iocs_points_improved.geojson
  ./store/iocs_map_improved.html
  ./store/choropleth_improved.png  (if --choropleth)
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import webbrowser
from pathlib import Path
from typing import Optional, Dict, Any, List

import numpy as np
import pandas as pd

# geopandas + shapely
try:
    import geopandas as gpd
    from shapely.geometry import Point
except Exception:
    gpd = None
    Point = None

# optional libs for map
try:
    import folium
    from folium.plugins import MarkerCluster, HeatMap
    import branca.colormap as bcm
except Exception:
    folium = None
    MarkerCluster = None
    HeatMap = None
    bcm = None

# optional mapping of country codes
try:
    import pycountry
except Exception:
    pycountry = None

# matplotlib for colormap generation
import matplotlib.cm as mpl_cm
import matplotlib.colors as mpl_colors
import matplotlib.pyplot as plt

# geoip2 optional
try:
    import geoip2.database
except Exception:
    geoip2 = None

DEFAULT_INPUT = "./store/iocs_indexed.json"
DEFAULT_OUT_MAP = "./store/iocs_map_improved.html"
DEFAULT_OUT_POINTS = "./store/iocs_points_improved.geojson"
DEFAULT_OUT_CHORO = "./store/choropleth_improved.png"
DEFAULT_GEOIP_DB = "data/GeoLite2-City.mmdb"


def load_indexed_json(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Input file not found: {path}")
    with open(path, "r") as f:
        return json.load(f)


def _try_get(d: dict, *keys):
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
        if cur is None:
            return None
    return cur


def iso2_to_iso3(alpha2: Optional[str]) -> Optional[str]:
    if not alpha2 or not pycountry:
        return None
    try:
        c = pycountry.countries.get(alpha_2=alpha2.upper())
        return c.alpha_3 if c else None
    except Exception:
        return None


def country_name_to_alpha2(name: str) -> Optional[str]:
    if not name or not pycountry:
        return None
    try:
        c = pycountry.countries.get(name=name)
        if c:
            return c.alpha_2
        cands = pycountry.countries.search_fuzzy(name)
        if cands:
            return cands[0].alpha_2
    except Exception:
        return None
    return None


def extract_geo_rows(iocs, min_score=None, risk=None, ioc_types=None, limit=None):
    rows = []
    for it in iocs:
        if limit and len(rows) >= limit:
            break
        try:
            score = float(it.get("score") or 0)
            bucket = (it.get("risk_bucket") or "").lower()
            if min_score is not None and score < float(min_score):
                continue
            if risk and bucket != risk.lower():
                continue
            if ioc_types and it.get("type") not in ioc_types:
                continue

            enrich = it.get("enrichment") or {}

            # try different geo fields for lat/lon
            lat = _try_get(enrich, "geoip", "location", "lat") or _try_get(enrich, "geoip", "location", "latitude")
            lon = _try_get(enrich, "geoip", "location", "lon") or _try_get(enrich, "geoip", "location", "longitude")
            if lat is None or lon is None:
                lat = _try_get(enrich, "geoip", "lat") or _try_get(enrich, "geoip", "latitude")
                lon = _try_get(enrich, "geoip", "lon") or _try_get(enrich, "geoip", "longitude") or _try_get(enrich, "geoip", "long")
            # abuseipdb sometimes contains coordinates under a nested object
            if (lat is None or lon is None) and isinstance(enrich.get("abuseipdb"), dict):
                alt = enrich["abuseipdb"].get("location") or enrich["abuseipdb"].get("geo")
                if isinstance(alt, dict):
                    lat = lat or alt.get("lat") or alt.get("latitude")
                    lon = lon or alt.get("lon") or alt.get("longitude")

            # country detection
            country_iso = _try_get(enrich, "geoip", "country_iso") or _try_get(enrich, "geoip", "country_code")
            if not country_iso:
                c = _try_get(enrich, "geoip", "country")
                if c:
                    country_iso = c.strip().upper() if isinstance(c, str) and len(c.strip()) == 2 else country_name_to_alpha2(c)
            if not country_iso:
                country_iso = _try_get(enrich, "abuseipdb", "countryCode")
            if isinstance(country_iso, str):
                country_iso = country_iso.strip().upper()
                if len(country_iso) == 3 and pycountry:
                    # convert ISO3 to ISO2
                    try:
                        obj = pycountry.countries.get(alpha_3=country_iso)
                        country_iso = obj.alpha_2 if obj else country_iso
                    except Exception:
                        pass

            rows.append({
                "id": it.get("id"),
                "value": it.get("value"),
                "type": it.get("type"),
                "score": float(score),
                "risk_bucket": bucket,
                "country_iso2": country_iso,
                "lat": (float(lat) if lat is not None else None),
                "lon": (float(lon) if lon is not None else None),
                "source": it.get("source"),
                "enrichment": enrich,
                "score_breakdown": it.get("score_breakdown") or None,
            })
        except Exception:
            continue
    return rows


def make_colormap_from_mpl(name: str, vmin: float, vmax: float, n_colors=12):
    """Return a branca LinearColormap based on a matplotlib cmap name."""
    if bcm is None:
        raise RuntimeError("branca not installed (pip install branca)")
    try:
        mpl_cmap = mpl_cm.get_cmap(name)
    except Exception:
        mpl_cmap = mpl_cm.get_cmap("YlOrRd")
    # build list of hex colors
    colors = [mpl_colors.to_hex(mpl_cmap(i)) for i in np.linspace(0, 1, n_colors)]
    # create linear colormap
    try:
        lc = bcm.LinearColormap(colors=colors, vmin=vmin, vmax=vmax)
    except Exception:
        # fallback to simple two-color if LinearColormap signature differs
        lc = bcm.LinearColormap(colors=colors)
        lc.vmin, lc.vmax = vmin, vmax
    return lc


def build_map(df, output_map_path: str, heatmap: bool = True, cmap_name: str = "YlOrRd"):
    if folium is None or bcm is None:
        raise RuntimeError("Required packages not installed: pip install folium branca")

    # compute center (mean)
    mean_lat = float(df["lat"].mean())
    mean_lon = float(df["lon"].mean())
    fmap = folium.Map(location=[mean_lat, mean_lon], zoom_start=2, tiles="CartoDB Positron", control_scale=True)

    min_score = float(df["score"].min())
    max_score = float(df["score"].max())
    if min_score == max_score:
        min_score = max(0, min_score - 1)
        max_score = max_score + 1

    # create colormap with robust fallback
    try:
        colormap = make_colormap_from_mpl(cmap_name, min_score, max_score)
    except Exception as e:
        colormap = make_colormap_from_mpl("YlOrRd", min_score, max_score)

    colormap.caption = "IOC score"
    colormap.add_to(fmap)

    # cluster markers
    cluster = MarkerCluster(name="IOCs (clustered)")
    fmap.add_child(cluster)

    # iterate points and add markers to cluster
    for idx, row in df.iterrows():
        try:
            score = float(row["score"])
            color = colormap(score)
            popup_lines = [
                f"<b>{row['value']}</b> <small>({row.get('type','')})</small>",
                f"Score: {score:.0f}",
                f"Risk: {row.get('risk_bucket') or 'n/a'}",
                f"Source: {row.get('source') or 'n/a'}",
            ]
            # quick enrichment details: abuseipdb or reverse ptr
            enrich = row.get("enrichment") or {}
            abuse = enrich.get("abuseipdb") if isinstance(enrich, dict) else None
            isp = abuse.get("isp") if isinstance(abuse, dict) else None
            ptr = None
            if isinstance(abuse, dict):
                ptr = (abuse.get("hostnames") or [None])[0] or abuse.get("domain")
            if not ptr:
                ptr = _try_get(enrich, "reverse", "ptr")
            if isp:
                popup_lines.append(f"ISP: {isp}")
            if ptr:
                popup_lines.append(f"PTR: {ptr}")
            # small score breakdown if available
            sb = row.get("score_breakdown")
            if isinstance(sb, dict):
                # display only some useful fields
                for k in ("final_score", "abuse_confidence", "abuse_contrib", "total_reports"):
                    if k in sb:
                        popup_lines.append(f"{k}: {sb[k]}")
            popup_html = "<br>".join(popup_lines)
            radius = 4 if score < 30 else (6 if score < 60 else 8)
            folium.CircleMarker(
                location=(row["lat"], row["lon"]),
                radius=radius,
                color=None,
                fill=True,
                fill_color=color,
                fill_opacity=0.9,
                popup=folium.Popup(popup_html, max_width=360)
            ).add_to(cluster)
        except Exception:
            continue

    # optionally add heatmap
    if heatmap and HeatMap is not None:
        heat_points = [[float(r["lat"]), float(r["lon"]), float(r["score"])] for _, r in df.iterrows()]
        try:
            HeatMap(heat_points, name="Score HeatMap", min_opacity=0.3, radius=12, blur=10, max_val=max_score).add_to(fmap)
        except Exception:
            pass

    folium.LayerControl(collapsed=False).add_to(fmap)

    # try to fit bounds to points
    try:
        lats = df["lat"].astype(float).tolist()
        lons = df["lon"].astype(float).tolist()
        fmap.fit_bounds([[min(lats), min(lons)], [max(lats), max(lons)]])
    except Exception:
        pass

    outp = Path(output_map_path)
    outp.parent.mkdir(parents=True, exist_ok=True)
    fmap.save(str(outp))
    return str(outp)


def build_choropleth(gdf, output_png_path: str, aggregate_by: str = "count"):
    if gpd is None:
        raise RuntimeError("geopandas not installed (pip install geopandas)")
    world = gpd.read_file(gpd.datasets.get_path("naturalearth_lowres"))
    if "country_iso2" in gdf.columns and pycountry:
        gdf["iso3"] = gdf["country_iso2"].apply(lambda c: iso2_to_iso3(c) if c else None)
    else:
        gdf["iso3"] = None

    if aggregate_by == "count":
        agg = gdf.groupby("iso3").size().reset_index(name="count")
        col = "count"
    else:
        agg = gdf.groupby("iso3")["score"].mean().reset_index(name="avg_score")
        col = "avg_score"

    merged = world.merge(agg, left_on="iso_a3", right_on="iso3", how="left")
    fig, ax = plt.subplots(1, 1, figsize=(14, 7))
    merged.plot(column=col, ax=ax, legend=True, missing_kwds={"color": "lightgrey"})
    ax.set_title(f"IOC {col} by country")
    ax.set_axis_off()
    outp = Path(output_png_path)
    outp.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(str(outp), dpi=150)
    plt.close(fig)
    return str(outp)


def fill_missing_coords(rows: List[Dict[str, Any]], geoip_db: Optional[str] = None):
    """Try GeoIP DB (IP) then country centroid if missing lat/lon."""
    stats = {"geoip_filled": 0, "centroid_filled": 0}
    reader = None
    if geoip_db and os.path.exists(geoip_db) and geoip2:
        try:
            reader = geoip2.database.Reader(geoip_db)
            print(f"GeoIP DB opened: {geoip_db}")
        except Exception as e:
            print("GeoIP DB open failed:", e)
            reader = None
    elif geoip_db:
        print("GeoIP DB path provided but geoip2 not installed or file missing; skipping GeoIP fallback.")

    world = None
    centroids_cache: Dict[str, tuple] = {}

    if pycountry and gpd is None:
        # user can still have pycountry but not geopandas; centroid fallback needs geopandas
        pass
    if gpd is not None:
        try:
            world = gpd.read_file(gpd.datasets.get_path("naturalearth_lowres"))
        except Exception:
            world = None

    for r in rows:
        if r.get("lat") is not None and r.get("lon") is not None:
            continue
        typ = r.get("type")
        val = r.get("value")
        filled = False

        if typ == "ip" and reader:
            try:
                rec = reader.city(val)
                if rec and rec.location and rec.location.latitude is not None and rec.location.longitude is not None:
                    r["lat"] = float(rec.location.latitude)
                    r["lon"] = float(rec.location.longitude)
                    stats["geoip_filled"] += 1
                    filled = True
            except Exception:
                pass

        if not filled:
            c2 = r.get("country_iso2")
            if c2:
                iso3 = iso2_to_iso3(c2)
                if iso3:
                    if iso3 in centroids_cache:
                        r["lat"], r["lon"] = centroids_cache[iso3]
                        stats["centroid_filled"] += 1
                        filled = True
                    else:
                        if world is None and gpd is not None:
                            try:
                                world = gpd.read_file(gpd.datasets.get_path("naturalearth_lowres"))
                            except Exception:
                                world = None
                        if world is not None:
                            try:
                                match = world[world["iso_a3"] == iso3]
                                if len(match) > 0:
                                    geom = match.unary_union
                                    centroid = geom.representative_point() if hasattr(geom, "representative_point") else geom.centroid
                                    lat = float(centroid.y)
                                    lon = float(centroid.x)
                                    r["lat"], r["lon"] = lat, lon
                                    centroids_cache[iso3] = (lat, lon)
                                    stats["centroid_filled"] += 1
                                    filled = True
                            except Exception:
                                pass

    try:
        if reader:
            reader.close()
    except Exception:
        pass

    return rows, stats


def main():
    p = argparse.ArgumentParser(description="Improved geopandas visualization for IOC dataset")
    p.add_argument("--input", "-i", default=DEFAULT_INPUT)
    p.add_argument("--output-map", default=DEFAULT_OUT_MAP)
    p.add_argument("--output-points", default=DEFAULT_OUT_POINTS)
    p.add_argument("--output-choropleth", default=DEFAULT_OUT_CHORO)
    p.add_argument("--min-score", type=float, default=None)
    p.add_argument("--risk", choices=["high", "medium", "low"], default=None)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--max-points", type=int, default=5000)
    p.add_argument("--choropleth", action="store_true")
    p.add_argument("--fill-missing", action="store_true")
    p.add_argument("--geoip-db", default=DEFAULT_GEOIP_DB)
    p.add_argument("--cmap", default="YlOrRd", help="Matplotlib colormap name")
    p.add_argument("--no-heat", action="store_true", help="Disable heatmap layer")
    p.add_argument("--open", action="store_true", help="Open resulting map in browser")
    args = p.parse_args()

    try:
        iocs = load_indexed_json(args.input)
    except Exception as e:
        print("Failed to load input:", e)
        sys.exit(1)

    print(f"Loaded {len(iocs)} IOCs from {args.input}")
    rows = extract_geo_rows(iocs, min_score=args.min_score, risk=args.risk, limit=args.limit)

    print(f"Initial extracted rows (may include missing coords): {len(rows)}")

    if args.fill_missing:
        print("Filling missing coordinates (GeoIP / country centroids)...")
        rows, stats = fill_missing_coords(rows, geoip_db=args.geoip_db)
        print(f"Filled: geoip={stats.get('geoip_filled',0)}, centroids={stats.get('centroid_filled',0)}")

    # keep only rows with coords
    rows_with_coords = [r for r in rows if r.get("lat") is not None and r.get("lon") is not None]
    print(f"Rows with coordinates: {len(rows_with_coords)}")
    if len(rows_with_coords) == 0:
        print("No rows with coordinates found. Try --fill-missing or check enrich data.")
        return

    df = pd.DataFrame(rows_with_coords)
    # downsample if too large
    if len(df) > args.max_points:
        print(f"Large dataset ({len(df)}) -> downsample to top {args.max_points} by score")
        df = df.sort_values("score", ascending=False).head(args.max_points).reset_index(drop=True)

    # create geometry column if geopandas available
    if gpd is not None and Point is not None:
        df["geometry"] = df.apply(lambda r: Point(float(r["lon"]), float(r["lat"])), axis=1)
        gdf = gpd.GeoDataFrame(df, geometry="geometry", crs="EPSG:4326")
    else:
        gdf = df  # fallback to pandas-only

    # write geojson points when possible
    out_points = Path(args.output_points)
    out_points.parent.mkdir(parents=True, exist_ok=True)
    try:
        if gpd is not None and hasattr(gdf, "to_file"):
            gdf.to_file(out_points, driver="GeoJSON")
        else:
            # fallback: write simple geojson FeatureCollection
            features = []
            for _, r in df.iterrows():
                features.append({
                    "type": "Feature",
                    "geometry": {"type": "Point", "coordinates": [float(r["lon"]), float(r["lat"])]},
                    "properties": {k: (v if k not in ("lat", "lon") else None) for k, v in r.items()}
                })
            with open(out_points, "w") as f:
                json.dump({"type": "FeatureCollection", "features": features}, f)
        print(f"Wrote {len(df)} points -> {out_points}")
    except Exception as e:
        print("Warning: failed to write geojson points:", e)

    # country counts
    country_counts = df.groupby("country_iso2").size().sort_values(ascending=False)
    print("Top countries (iso2 -> count):")
    print(country_counts.head(20).to_string())

    if pycountry:
        print("\nTop countries (alpha2 -> name):")
        for code, cnt in country_counts.head(15).items():
            try:
                name = pycountry.countries.get(alpha_2=code).name if code else "Unknown"
            except Exception:
                name = "Unknown"
            print(f"{code} ({name}): {cnt}")

    # build interactive folium map
    try:
        print("Building interactive map ->", args.output_map)
        out_map_path = build_map(df, args.output_map, heatmap=(not args.no_heat), cmap_name=args.cmap)
        print("Map saved:", out_map_path)
        if args.open:
            try:
                webbrowser.open_new_tab(f"file://{Path(out_map_path).resolve()}")
            except Exception:
                pass
    except Exception as e:
        print("Failed to build interactive map:", e)

    # optionally build choropleth
    if args.choropleth:
        try:
            print("Building choropleth ->", args.output_choropleth)
            choro = build_choropleth(gdf if (gpd is not None) else df, args.output_choropleth)
            print("Choropleth saved ->", choro)
        except Exception as e:
            print("Choropleth failed:", e)

    print("Done.")


if __name__ == "__main__":
    main()
