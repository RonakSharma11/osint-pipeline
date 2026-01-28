#!/usr/bin/env python3
"""
ml_rf.py (Stratified Time-Forward Version)

Fixes the issue where the "Future" contained no labeled malicious IOCs.
Splits Malicious and Benious IOCs chronologically separately to ensure
temporal generalization on both classes.

Usage:
    python ml_rf.py --input ./store/iocs_indexed.json --outdir ./store/ml_results
"""
from __future__ import annotations
import argparse
import json
import math
import datetime
from pathlib import Path
from typing import Tuple, List, Any, Dict

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    roc_auc_score, 
    roc_curve,
    precision_recall_curve,
    auc,
    f1_score
)
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.calibration import CalibrationDisplay

# -------------------------
# Helpers
# -------------------------
def safe_get(d: Dict, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur

def make_onehot_encoder(**kwargs):
    try:
        return OneHotEncoder(handle_unknown="ignore", sparse_output=kwargs.get("sparse_output", False))
    except TypeError:
        try:
            return OneHotEncoder(handle_unknown="ignore", sparse=kwargs.get("sparse", False))
        except TypeError:
            return OneHotEncoder(handle_unknown="ignore")

def build_feature_row(ioc: Dict) -> Dict[str, Any]:
    features: Dict[str, Any] = {}
    features["value"] = ioc.get("value")
    features["type"] = ioc.get("type") or "unknown"
    score = ioc.get("score")
    features["score_recorded"] = float(score) if score is not None else 0.0
    
    enrich = ioc.get("enrichment") or {}
    abuse = enrich.get("abuseipdb") or {}
    
    features["abuse_confidence"] = float(safe_get(abuse, "abuseConfidenceScore", default=0) or 0)
    features["total_reports"] = int(safe_get(abuse, "totalReports", default=0) or 0)
    features["distinct_users"] = int(safe_get(abuse, "numDistinctUsers", default=0) or 0)
    
    ptr = safe_get(enrich, "reverse", "ptr", default="") or ""
    features["ptr_suspicious"] = 1 if ptr and any(k in ptr.lower() for k in ("scan", "security", "ipip", "crawl")) else 0
    features["ptr_present"] = 1 if ptr else 0
    
    isp = safe_get(abuse, "isp", default="") or ""
    features["isp"] = isp if isp else "unknown"
    
    country = safe_get(enrich, "geoip", "country_iso", default="") or safe_get(abuse, "countryCode", default="") or "UNK"
    features["country_iso2"] = country
    
    whois = safe_get(enrich, "whois", default={}) or {}
    features["whois_present"] = 1 if whois else 0
    
    last = safe_get(abuse, "lastReportedAt", default=None)
    features["report_dt_raw"] = None
    
    if last:
        try:
            if last.endswith('Z'):
                last = last[:-1] + '+00:00'
            dt = datetime.datetime.fromisoformat(last)
            
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            else:
                dt = dt.astimezone(datetime.timezone.utc)
            
            features["report_dt_raw"] = dt
            
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            delta_days = (now_utc - dt).total_seconds() / 86400.0
            features["days_since_last_report"] = max(0.0, float(delta_days))
        except Exception:
            features["days_since_last_report"] = 0.0
    else:
        features["days_since_last_report"] = 0.0
        
    features["log_reports"] = math.log10(features["total_reports"] + 1)
    features["sqrt_distinct_users"] = math.sqrt(features["distinct_users"])
    return features

def build_dataframe(iocs: List[Dict]) -> pd.DataFrame:
    rows = [build_feature_row(it) for it in iocs]
    df = pd.DataFrame(rows)
    
    numeric_cols = ["abuse_confidence", "total_reports", "distinct_users", "days_since_last_report", "log_reports", "sqrt_distinct_users", "score_recorded"]
    for c in numeric_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
            
    for c in ["type", "isp", "country_iso2"]:
        if c in df.columns:
            df[c] = df[c].astype(str).fillna("UNK")
            
    for c in ["ptr_suspicious", "ptr_present", "whois_present"]:
        if c in df.columns:
            df[c] = df[c].fillna(0).astype(int)
            
    return df

# -------------------------
# Labeling
# -------------------------
def make_silver_labels(df: pd.DataFrame) -> pd.Series:
    cond = (df["abuse_confidence"] >= 100) & (df["total_reports"] >= 1000)
    return cond.astype(int)

# -------------------------
# Training & evaluation
# -------------------------
def train_and_evaluate(X_train: np.ndarray, X_test: np.ndarray, y_train: np.ndarray, y_test: np.ndarray, cols: List[str], outdir: Path):
    clf = RandomForestClassifier(
        n_estimators=200, 
        random_state=42, 
        n_jobs=-1, 
        class_weight='balanced',
        min_samples_leaf=2,
        max_features='sqrt'
    )
    
    print("Training RandomForest on Stratified Time-Forward Split...")
    clf.fit(X_train, y_train)
    
    try:
        y_proba = clf.predict_proba(X_test)[:, 1]
    except Exception:
        y_proba = None

    roc_auc_val = None
    pr_auc_val = None
    f1_val = None

    if y_proba is not None and len(np.unique(y_test)) == 2:
        fpr, tpr, thresholds = roc_curve(y_test, y_proba)
        j_scores = tpr - fpr
        best_idx = np.argmax(j_scores)
        optimal_threshold = thresholds[best_idx]
        
        print(f"Calculated Optimal Decision Threshold: {optimal_threshold:.4f}")
        
        y_pred = (y_proba >= optimal_threshold).astype(int)
        
        roc_auc_val = roc_auc_score(y_test, y_proba)
        f1_val = f1_score(y_test, y_pred)
        
        precision, recall, _ = precision_recall_curve(y_test, y_proba)
        pr_auc_val = auc(recall, precision)
        
        print(f"\n=== Stratified Time-Forward Validation Results ===")
        print(f"PR-AUC: {pr_auc_val:.4f}")
        print(f"F1-Score: {f1_val:.4f}")
        
        rep = classification_report(y_test, y_pred, digits=4, zero_division=0)
        rep += f"\nPR-AUC: {pr_auc_val:.4f}\n"
        rep += f"F1-Score: {f1_val:.4f}\n"
        
        cm = confusion_matrix(y_test, y_pred)
        
        try:
            fig, ax = plt.subplots(figsize=(5,4))
            ax.plot(fpr, tpr, label=f"AUC={roc_auc_val:.4f}")
            ax.plot([0,1],[0,1], linestyle="--", color="gray")
            ax.scatter(fpr[best_idx], tpr[best_idx], marker='o', color='red', label=f'Optimal Threshold ({optimal_threshold:.2f})')
            ax.set_xlabel("FPR")
            ax.set_ylabel("TPR")
            ax.set_title("ROC Curve (Stratified Time-Forward Split)")
            ax.legend()
            roc_png = outdir / "roc_curve_time_split.png"
            fig.tight_layout()
            fig.savefig(roc_png, dpi=150)
            plt.close(fig)
            print("Saved ROC curve ->", roc_png)
        except Exception as e:
            print("Failed to plot ROC curve:", e)

    else:
        y_pred = clf.predict(X_test)
        rep = classification_report(y_test, y_pred, digits=4, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)
            
    outdir.mkdir(parents=True, exist_ok=True)
    
    metrics_txt = outdir / "metrics_time_split.txt"
    with metrics_txt.open("w") as f:
        f.write("Classification report (Stratified Time-Forward Split):\n")
        f.write(rep + "\n\n")
        f.write("Confusion matrix:\n")
        f.write(np.array2string(cm) + "\n\n")
        f.write(f"ROC AUC: {roc_auc_val}\n")
        if pr_auc_val:
            f.write(f"PR-AUC: {pr_auc_val}\n")
            f.write(f"F1-Score: {f1_val}\n")
    print("Metrics written ->", metrics_txt)
    
    # Plot Confusion Matrix
    try:
        fig, ax = plt.subplots(figsize=(5,4))
        im = ax.imshow(cm, cmap="Blues")
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        ax.set_xticks(range(cm.shape[1]))
        ax.set_yticks(range(cm.shape[0]))
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(j, i, str(cm[i,j]), ha="center", va="center", color="black")
        fig.tight_layout()
        cm_png = outdir / "confusion_matrix_time_split.png"
        fig.savefig(cm_png, dpi=150)
        plt.close(fig)
        print("Saved confusion matrix ->", cm_png)
    except Exception as e:
        print("Failed to plot confusion matrix:", e)

     # -------------------------
     # Calibration Plot
     # -------------------------
     # This checks if the predicted probabilities match reality
    try:
        fig = plt.figure(figsize=(5,4))
        # y_test are the labels, y_proba are the probabilities
        CalibrationDisplay.from_predictions(y_test, y_proba, n_bins=10, ax=plt.gca(), name="Random Forest")
        plt.title("Calibration Plot (Reliability)")
        plt.xlabel("Mean Predicted Probability")
        plt.ylabel("Fraction of Positives")
        plt.grid(True, alpha=0.3)
        cal_png = outdir / "calibration_plot.png"
        fig.tight_layout()
        fig.savefig(cal_png, dpi=150)
        plt.close(fig)
        print("Saved calibration plot ->", cal_png)
    except Exception as e:
        print("Failed to plot calibration:", e)
        
    # Feature Importances
    try:
        fi = clf.feature_importances_
        fi_df = pd.DataFrame({"feature": [f"f_{i}" for i in range(len(fi))], "importance": fi})
        if len(cols) == len(fi):
            fi_df["feature"] = cols
        fi_df = fi_df.sort_values("importance", ascending=False)
        fi_csv = outdir / "feature_importances_time_split.csv"
        fi_df.to_csv(fi_csv, index=False)
        print("Saved feature importances ->", fi_csv)
    except Exception as e:
        print("Failed to save feature importances:", e)
        
    model_path = outdir / "model_time_split.joblib"
    joblib.dump({"model": clf}, model_path)
    print("Saved model ->", model_path)
    
    return {"classification_report": rep, "confusion_matrix": cm, "roc_auc": roc_auc_val}

# -------------------------
# Main
# -------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", "-i", default="./store/iocs_indexed.json")
    parser.add_argument("--outdir", "-o", default="./store/ml_results")
    args = parser.parse_args()
    inp = Path(args.input)
    outdir = Path(args.outdir)
    if not inp.exists():
        print("Input not found:", inp)
        return
    
    print("Loading IOCs from", inp)
    with open(inp, "r") as f:
        iocs = json.load(f)
    print("Loaded", len(iocs), "IOCs")
    
    df = build_dataframe(iocs)
    print("Built features DF shape:", df.shape)
    
    # --- STRATIFIED TEMPORAL SPLIT ---
    print("\nPerforming Stratified Time-Forward Split...")
    
    EPOCH_START = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    df['report_dt_raw'] = df['report_dt_raw'].fillna(EPOCH_START)
    
    # 1. Assign Labels
    y = make_silver_labels(df)
    df['label'] = y
    
    # 2. Separate and Sort
    df_0 = df[df['label'] == 0].sort_values(by='report_dt_raw') # Benign
    df_1 = df[df['label'] == 1].sort_values(by='report_dt_raw') # Malicious
    
    # 3. Split Chronologically
    # We take the earliest 80% for training, latest 20% for testing, 
    # ensuring we keep the class ratio reasonable in the test set.
    
    def split_df(df_part):
        split_idx = int(len(df_part) * 0.8)
        return df_part.iloc[:split_idx], df_part.iloc[split_idx:]
    
    df_0_train, df_0_test = split_df(df_0)
    df_1_train, df_1_test = split_df(df_1)
    
    # 4. Combine
    df_train = pd.concat([df_0_train, df_1_train])
    df_test = pd.concat([df_0_test, df_1_test])
    
    # Shuffle Training data (models don't like sorted dates in input usually)
    df_train = df_train.sample(frac=1, random_state=42)
    # Do NOT shuffle test data (keep temporal order of events)
    
    print(f"Train set size: {len(df_train)} (Benign: {len(df_0_train)}, Malicious: {len(df_1_train)})")
    print(f"Test set size: {len(df_test)} (Benign: {len(df_0_test)}, Malicious: {len(df_1_test)})")
    
    # --- FEATURE PREPROCESSING ---
    
    numeric_features = ["distinct_users", "days_since_last_report", "sqrt_distinct_users"]
    categorical_features = ["type", "isp", "country_iso2"]
    binary_features = ["ptr_suspicious", "ptr_present", "whois_present"]
    
    ohe = make_onehot_encoder(sparse_output=False, sparse=False)
    numeric_transformer = Pipeline(steps=[("scaler", StandardScaler())])
    categorical_transformer = Pipeline(steps=[("ohe", ohe)])
    
    preproc = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_features),
            ("cat", categorical_transformer, categorical_features),
        ],
        remainder="drop",
    )
    
    print("Fitting preprocessor on Training data only...")
    X_train = preproc.fit_transform(df_train)
    X_test = preproc.transform(df_test)
    
    try:
        X_train = np.asarray(X_train, dtype=float)
        X_test = np.asarray(X_test, dtype=float)
    except Exception as e:
        print("ERROR: failed converting X to numeric array.")
        raise e

    ohe_names = []
    try:
        ohe_inst = preproc.named_transformers_["cat"].named_steps["ohe"]
        ohe_names = list(ohe_inst.get_feature_names_out(categorical_features))
    except Exception:
        ohe_names = [f"cat_{c}_?" for c in categorical_features]
        
    cols = numeric_features + ohe_names + binary_features
    
    y_train = df_train['label'].values
    y_test = df_test['label'].values
    
    results = train_and_evaluate(X_train, X_test, y_train, y_test, cols, outdir)
    
    print("\n=== Summary ===")
    print("Classification report:\n", results["classification_report"])
    print("Confusion matrix:\n", results["confusion_matrix"])
    print("ROC AUC:", results["roc_auc"])

if __name__ == "__main__":
    main()