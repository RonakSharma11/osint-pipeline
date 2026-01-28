#!/usr/bin/env python3
"""
make_paper_figures.py

Produces:
  - paper/score_histogram.png     (score distribution)
  - paper/top_isps.png            (top 10 ISPs / hosting providers by count)
  - paper/choropleth.png          (country counts choropleth)
  - paper/score_comparison.png    (basic vs improved scoring method comparison)
  - paper/pipeline_architecture.png (pipeline architecture diagram)

Usage:
  python make_paper_figures.py
"""

import json
from pathlib import Path
from collections import Counter, defaultdict
import math
import sys
import urllib.request
import zipfile
import textwrap

# plotting / geo libs
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyBboxPatch, Arrow
import matplotlib.patches as mpatches

# Optional geopandas + pycountry
try:
    import geopandas as gpd
    import pycountry
    HAVE_GPD = True
except Exception:
    HAVE_GPD = False

STORE_INDEX = Path("store/iocs_indexed.json")
OUT_DIR = Path("paper")
OUT_DIR.mkdir(exist_ok=True)

def load_index(path):
    if not path.exists():
        print(f"ERROR: input not found: {path}")
        sys.exit(1)
    with open(path, "r") as f:
        return json.load(f)

def score_histogram(items, out_path, bins=40):
    scores = [float(it.get("score") or 0) for it in items]
    # safe fallback if empty
    if not scores:
        print("No scores found for histogram.")
        return
    plt.figure(figsize=(8,4.5))
    plt.hist(scores, bins=bins, edgecolor="black", alpha=0.8)
    plt.xlabel("IOC score")
    plt.ylabel("Count")
    plt.title("Distribution of IOC Scores")
    plt.grid(axis="y", alpha=0.25)
    
    # Add a logarithmic scale to make smaller counts more visible
    plt.yscale('log')
    plt.ylim(bottom=0.5)  # Set a minimum value to avoid issues with log(0)
    
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"Saved score histogram -> {out_path}")

def top_isps_chart(items, out_path, top_n=10, min_score=None):
    # gather ISP strings from enrichment.abuseipdb.isp (if present)
    isp_counter = Counter()
    for it in items:
        if min_score is not None and (it.get("score") or 0) < min_score:
            continue
        enrich = it.get("enrichment") or {}
        # abuseipdb may be string-keyed or missing
        abuse = enrich.get("abuseipdb") if isinstance(enrich, dict) else None
        isp = None
        if isinstance(abuse, dict):
            isp = abuse.get("isp")
        # fallback: some enrichments might put isp at top-level
        if not isp:
            isp = enrich.get("isp")
        if isp and isinstance(isp, str):
            isp_counter[isp.strip()] += 1
        else:
            isp_counter["UNKNOWN"] += 1
    if not isp_counter:
        print("No ISP data available.")
        return
    top = isp_counter.most_common(top_n)
    labels, counts = zip(*top)
    plt.figure(figsize=(8,4.5))
    y_pos = np.arange(len(labels))
    plt.barh(y_pos[::-1], counts[::-1])   # largest on top
    plt.yticks(y_pos, [l if len(l) < 40 else l[:37]+"..." for l in labels])
    plt.xlabel("Count (IOCs)")
    plt.title(f"Top {top_n} ISPs / Hosting Providers (by IOC count)")
    
    # Apply logarithmic scale to make smaller counts more visible
    plt.xscale('log')
    plt.xlim(left=0.5)  # Set a minimum value to avoid issues with log(0)
    
    # Add grid lines for better readability with log scale
    plt.grid(axis='x', alpha=0.25)
    plt.grid(axis='y', alpha=0.25)
    
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"Saved top ISPs plot -> {out_path}")

def get_world_map():
    """Download or retrieve the world map data"""
    cache_dir = Path("cache")
    cache_dir.mkdir(exist_ok=True)
    zip_path = cache_dir / "ne_110m_admin_0_countries.zip"
    shp_path = cache_dir / "ne_110m_admin_0_countries.shp"
    
    # If we already have the shapefile, use it
    if shp_path.exists():
        return gpd.read_file(shp_path)
    
    # If we have the zip but not the shapefile, extract it
    if zip_path.exists():
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(cache_dir)
        return gpd.read_file(shp_path)
    
    # Otherwise, download it with proper headers
    url = "https://naciscdn.org/naturalearth/110m/cultural/ne_110m_admin_0_countries.zip"
    print(f"Downloading world map data from {url}...")
    
    try:
        # Create a request with headers
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3')
        
        # Download the file
        with urllib.request.urlopen(req) as response, open(zip_path, 'wb') as out_file:
            out_file.write(response.read())
        
        # Extract the shapefile from the zip
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(cache_dir)
        
        # Return the path to the shapefile
        return gpd.read_file(shp_path)
    
    except Exception as e:
        print(f"Error downloading world map data: {e}")
        print("Trying alternative method...")
        
        # Alternative: Use the built-in dataset from geodatasets (if available)
        try:
            import geodatasets
            world = geodatasets.data.natural_earth.geography('admin_0_countries')
            return world
        except ImportError:
            print("geodatasets not available. Installing...")
            import subprocess
            subprocess.check_call(["pip", "install", "geodatasets"])
            import geodatasets
            world = geodatasets.data.natural_earth.geography('admin_0_countries')
            return world
        except Exception as e2:
            print(f"Alternative method also failed: {e2}")
            return None

def country_choropleth(items, out_path, agg_by="count"):
    if not HAVE_GPD:
        print("Geopandas not available: skipping choropleth. Install geopandas and pycountry.")
        return

    # Build DataFrame of country ISO2 and counts
    rows = []
    for it in items:
        enrich = it.get("enrichment") or {}
        # several possible fields for country
        c = None
        # prefer enrichment.geoip.country_iso
        geoip = enrich.get("geoip") if isinstance(enrich, dict) else None
        if isinstance(geoip, dict):
            c = geoip.get("country_iso") or geoip.get("country_code") or geoip.get("country")
        if not c:
            # abuseipdb countryCode
            abuse = enrich.get("abuseipdb") if isinstance(enrich, dict) else None
            if isinstance(abuse, dict):
                c = abuse.get("countryCode") or abuse.get("country")
        if not c:
            # generic fallback
            c = enrich.get("country") or "UNK"
        if isinstance(c, str):
            c = c.strip().upper()
        rows.append({"iso2": c if c else "UNK", "score": float(it.get("score") or 0)})
    df = pd.DataFrame(rows)

    # map iso2 -> iso3 using pycountry; treat 'UK' -> 'GB' common case
    def iso2_to_iso3_try(v):
        if not v or v in ("", "UNK", "None"):
            return None
        try:
            # handle accidental 'UK'
            v2 = "GB" if v == "UK" else v
            c = pycountry.countries.get(alpha_2=v2)
            if c:
                return c.alpha_3
            # try fuzzy search
            c2 = pycountry.countries.search_fuzzy(v)
            if c2 and len(c2) > 0:
                return c2[0].alpha_3
        except Exception:
            return None
        return None

    df["iso3"] = df["iso2"].apply(iso2_to_iso3_try)
    if agg_by == "count":
        agg = df.groupby("iso3").size().reset_index(name="count")
        col = "count"
    else:
        agg = df.groupby("iso3")["score"].mean().reset_index(name="avg_score")
        col = "avg_score"

    # Get world map data
    world = get_world_map()
    
    if world is None:
        print("Could not retrieve world map data. Skipping choropleth.")
        return
    
    # Check for the correct column name for ISO3 codes
    possible_iso_columns = ['iso_a3', 'ISO_A3', 'adm0_a3', 'ADM0_A3', 'ISO3', 'iso3']
    iso_column = None
    
    for col_name in possible_iso_columns:
        if col_name in world.columns:
            iso_column = col_name
            break
    
    if iso_column is None:
        print(f"Could not find ISO3 column in world map data. Available columns: {list(world.columns)}")
        return
    
    print(f"Using '{iso_column}' as the ISO3 column for merging")
    
    # merge on the identified ISO3 column
    merged = world.merge(agg, left_on=iso_column, right_on="iso3", how="left")
    fig, ax = plt.subplots(1, 1, figsize=(12,6))
    # use 'OrRd' colormap
    merged.plot(column=col, ax=ax, legend=True, missing_kwds={"color": "lightgrey"}, cmap="OrRd")
    ax.set_title("IOC counts by country" if agg_by=="count" else "Average IOC score by country")
    ax.set_axis_off()
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close()
    print(f"Saved choropleth -> {out_path}")

def score_comparison_chart(out_path):
    """Create a comparison chart showing basic vs improved scoring methods"""
    # Data from the table
    data = [
        {
            "ioc": "95.215.0.144",
            "basic_score": 99,
            "improved_score": 99,
            "change": 0,
            "key_factors": "High abuse confidence, reports, suspicious PTR."
        },
        {
            "ioc": "52.34.12.8",
            "basic_score": 76,
            "improved_score": 62,
            "change": -14,
            "key_factors": "Cloud provider penalty, older reports."
        },
        {
            "ioc": "103.203.57.3",
            "basic_score": 91,
            "improved_score": 91,
            "change": 0,
            "key_factors": "High abuse confidence, recent reports."
        },
        {
            "ioc": "198.51.100.1",
            "basic_score": 45,
            "improved_score": 28,
            "change": -17,
            "key_factors": "Cloud provider penalty, no recent activity."
        },
        {
            "ioc": "example.com",
            "basic_score": 38,
            "improved_score": 52,
            "change": 14,
            "key_factors": "Young domain, recent reports."
        }
    ]
    
    # Create figure with two subplots
    fig = plt.figure(figsize=(18, 14))  # Increased size for better visibility
    gs = fig.add_gridspec(2, 1, height_ratios=[2, 1])
    
    # Bar chart subplot
    ax1 = fig.add_subplot(gs[0])
    
    iocs = [item["ioc"] for item in data]
    basic_scores = [item["basic_score"] for item in data]
    improved_scores = [item["improved_score"] for item in data]
    changes = [item["change"] for item in data]
    
    x = np.arange(len(iocs))
    width = 0.35
    
    bars1 = ax1.bar(x - width/2, basic_scores, width, label='Basic Score', color='skyblue')
    bars2 = ax1.bar(x + width/2, improved_scores, width, label='Improved Score', color='salmon')
    
    ax1.set_ylabel('Score')
    ax1.set_title('Comparison of Basic vs Improved Scoring Methods', fontsize=16)
    ax1.set_xticks(x)
    ax1.set_xticklabels(iocs, fontsize=12)
    ax1.legend(fontsize=12)
    ax1.set_ylim(0, 100)  # Scores range from 0-100
    
    # Add value labels on the bars
    for bar in bars1:
        height = bar.get_height()
        ax1.annotate(f'{height}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=10)
    
    for bar in bars2:
        height = bar.get_height()
        ax1.annotate(f'{height}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=10)
    
    # Add change labels between bars
    for i, change in enumerate(changes):
        if change != 0:
            sign = "+" if change > 0 else ""
            ax1.text(x[i], max(basic_scores[i], improved_scores[i]) + 5, 
                    f"{sign}{change}", ha='center', va='bottom', 
                    color='green' if change > 0 else 'red', fontweight='bold', fontsize=10)
    
    # Table subplot
    ax2 = fig.add_subplot(gs[1])
    ax2.axis('off')
    
    # Prepare table data
    cell_text = []
    for item in data:
        # Wrap the key factors text to fit in the table cell
        wrapped_text = '\n'.join(textwrap.wrap(item["key_factors"], width=40))
        cell_text.append([
            item["ioc"],
            str(item["basic_score"]),
            str(item["improved_score"]),
            f"{item['change']:+d}" if item["change"] != 0 else "0",
            wrapped_text
        ])
    
    # Create the table
    table = ax2.table(cellText=cell_text,
                      colLabels=['IOC', 'Basic Score', 'Improved Score', 'Change', 'Key Factors'],
                      loc='center',
                      cellLoc='left')
    
    # Style the table
    table.auto_set_font_size(False)
    table.set_fontsize(12)  # Increased font size
    table.scale(1, 2)
    
    # Set column widths manually by adjusting cell widths
    col_widths = [0.1, 0.1, 0.1, 0.1, 0.6]  # Relative widths for each column
    for i, width in enumerate(col_widths):
        for j in range(len(data) + 1):  # +1 for header row
            if j == 0:  # Header row
                table[(j, i)].set_width(width)
            else:  # Data rows
                table[(j, i)].set_width(width)
    
    # Color the change column
    for i in range(len(data)):
        change = data[i]["change"]
        if change > 0:
            table[(i+1, 3)].set_facecolor('#d4edda')  # Light green for positive
        elif change < 0:
            table[(i+1, 3)].set_facecolor('#f8d7da')  # Light red for negative
    
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"Saved score comparison chart -> {out_path}")

def pipeline_architecture_diagram(out_path):
    """Create a cleaner diagram showing the pipeline architecture"""
    fig, ax = plt.subplots(figsize=(16, 8))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 6)
    ax.axis('off')
    
    # Define a cleaner color palette
    colors = {
        'collectors': '#3498db',  # Blue
        'enrichment': '#e67e22',  # Orange
        'indexing': '#e74c3c',    # Red
        'exports': '#1abc9c'      # Teal
    }
    
    # Define component positions with better spacing
    components = [
        {
            'name': 'Collectors',
            'x': 0.5,
            'y': 2,
            'width': 2.5,
            'height': 2,
            'color': colors['collectors'],
            'items': [
                'OTX',
                'AbuseIPDB',
                'GitHub IOCs',
                'RSS'
            ],
            'output': 'iocs.json'
        },
        {
            'name': 'Enrichment',
            'x': 3.5,
            'y': 2,
            'width': 2.5,
            'height': 2,
            'color': colors['enrichment'],
            'items': [
                'DNS',
                'Passive DNS',
                'GeoIP',
                'AbuseIPDB details',
                'OTX metadata',
                'WHOIS',
                'HTTP scans',
                'Caching'
            ]
        },
        {
            'name': 'Indexing & Scoring',
            'x': 6.5,
            'y': 2,
            'width': 2.5,
            'height': 2,
            'color': colors['indexing'],
            'items': [
                'Combine enrichment',
                'Compute score',
                'Assign risk_bucket'
            ],
            'output': 'iocs_indexed.json'
        },
        {
            'name': 'Exports',
            'x': 9.5,
            'y': 2,
            'width': 2.5,
            'height': 2,
            'color': colors['exports'],
            'items': [
                'STIX 2.1 bundle',
                'Geospatial outputs'
            ],
            'outputs': [
                'STIX exporter',
                'GeoJSON, folium HTML'
            ]
        }
    ]
    
    # Draw components with cleaner design
    for comp in components:
        # Draw main box with cleaner style
        box = FancyBboxPatch(
            (comp['x'], comp['y']),
            comp['width'], comp['height'],
            boxstyle="round,pad=0.1",
            facecolor=comp['color'],
            edgecolor='white',
            alpha=0.9,
            linewidth=2
        )
        ax.add_patch(box)
        
        # Add title with white text
        ax.text(
            comp['x'] + comp['width']/2,
            comp['y'] + comp['height'] - 0.3,
            comp['name'],
            ha='center',
            va='center',
            fontsize=14,
            fontweight='bold',
            color='white'
        )
        
        # Add items with better formatting
        for i, item in enumerate(comp['items']):
            ax.text(
                comp['x'] + 0.2,
                comp['y'] + comp['height'] - 0.7 - i*0.25,
                f'• {item}',
                ha='left',
                va='center',
                fontsize=10,
                color='white'
            )
        
        # Add output if exists
        if 'output' in comp:
            ax.text(
                comp['x'] + comp['width']/2,
                comp['y'] - 0.4,
                f"Output: {comp['output']}",
                ha='center',
                va='center',
                fontsize=9,
                style='italic',
                bbox=dict(facecolor='white', alpha=0.8, boxstyle='round,pad=0.3')
            )
        
        # Add outputs if exists
        if 'outputs' in comp:
            for i, output in enumerate(comp['outputs']):
                ax.text(
                    comp['x'] + comp['width']/2,
                    comp['y'] - 0.4 - i*0.3,
                    f"Output: {output}",
                    ha='center',
                    va='center',
                    fontsize=9,
                    style='italic',
                    bbox=dict(facecolor='white', alpha=0.8, boxstyle='round,pad=0.3')
                )
    
    # Draw cleaner arrows between components
    arrow_props = dict(arrowstyle='->', lw=3, color='gray')
    ax.annotate('', xy=(3.5, 3), xytext=(3, 3), arrowprops=arrow_props)
    ax.annotate('', xy=(6.5, 3), xytext=(6, 3), arrowprops=arrow_props)
    ax.annotate('', xy=(9.5, 3), xytext=(9, 3), arrowprops=arrow_props)
    
    # Add title with better styling
    ax.text(
        6, 5.5,
        'Pipeline Architecture',
        ha='center',
        va='center',
        fontsize=20,
        fontweight='bold',
        color='#2c3e50'
    )
    
    # Add a cleaner legend
    legend_elements = [
        mpatches.Patch(color=colors['collectors'], label='Collectors'),
        mpatches.Patch(color=colors['enrichment'], label='Enrichment'),
        mpatches.Patch(color=colors['indexing'], label='Indexing & Scoring'),
        mpatches.Patch(color=colors['exports'], label='Exports')
    ]
    ax.legend(handles=legend_elements, loc='lower center', ncol=4, fontsize=10, 
              frameon=True, facecolor='white', edgecolor='white')
    
    # Add a subtle background
    ax.add_patch(Rectangle((0, 0), 12, 6, facecolor='#f8f9fa', alpha=0.5, zorder=-1))
    
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Saved pipeline architecture diagram -> {out_path}")

def main():
    items = load_index(STORE_INDEX)

    # HISTOGRAM
    score_histogram(items, OUT_DIR / "score_histogram.png", bins=40)

    # TOP ISPS (use all scores but you can set min_score)
    top_isps_chart(items, OUT_DIR / "top_isps.png", top_n=10, min_score=None)

    # CHOROPLETH (if geopandas installed)
    country_choropleth(items, OUT_DIR / "choropleth.png", agg_by="count")
    
    # SCORE COMPARISON CHART
    score_comparison_chart(OUT_DIR / "score_comparison.png")
    
    # PIPELINE ARCHITECTURE DIAGRAM
    pipeline_architecture_diagram(OUT_DIR / "pipeline_architecture.png")

if __name__ == "__main__":
    main()