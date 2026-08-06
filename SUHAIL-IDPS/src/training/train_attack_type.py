#!/usr/bin/env python3
"""Route B — train the multi-class ATTACK-TYPE classifier.

Where the routine barrier (``train_xgboost.py``) answers *"attack or not?"*, this
model answers *"which kind of attack?"* — portscan / synflood / udpflood /
httpflood / slowloris / ... — using the ``attack_type`` column already present in
the flow dataset.

Input : merged flow CSV with `FLOW_FEATURES` + `attack_type` (+ `label`).
        Only rows that are attacks (``label == 1`` and a non-empty
        ``attack_type``) are used for training.
Output: models/xgboost/{xgb_type_model.pkl, xgb_type_scaler.pkl, xgb_type_labels.pkl}

Once these files exist and xgboost is installed, the engine automatically prefers
this model over the Route A heuristic (see ``src/core/attack_types.py``). Nothing
else to wire — just **Reload Models** in the dashboard.

    python src/training/train_attack_type.py --data data/flows/all_flows.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.flow_features import FLOW_FEATURES, LABEL_COLUMN  # noqa: E402

OUT_DIR = PROJECT_ROOT / "models" / "xgboost"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(PROJECT_ROOT / "data" / "flows" / "all_flows.csv"))
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    try:
        from xgboost import XGBClassifier
    except ImportError:
        raise SystemExit(
            "xgboost is not installed. `pip install xgboost` to train Route B."
        )

    df = pd.read_csv(args.data).fillna(0)
    if "attack_type" not in df.columns:
        raise SystemExit(
            "dataset has no 'attack_type' column — cannot train the type model. "
            "Rebuild flows so attacks carry their archetype label."
        )

    # keep only labelled attack rows with a named type
    df["attack_type"] = df["attack_type"].astype(str).str.strip()
    mask = (df[LABEL_COLUMN].astype(int) == 1) & (df["attack_type"] != "") & (df["attack_type"] != "0")
    df = df[mask]
    if df.empty:
        raise SystemExit("no labelled attack rows with an attack_type to train on.")

    # drop ultra-rare classes that can't be stratified/evaluated meaningfully
    counts = df["attack_type"].value_counts()
    keep = counts[counts >= 10].index
    dropped = sorted(set(counts.index) - set(keep))
    if dropped:
        print(f"[i] dropping rare classes (<10 rows): {dropped}")
    df = df[df["attack_type"].isin(keep)]

    X = df[FLOW_FEATURES].to_numpy(dtype=float)
    encoder = LabelEncoder()
    y = encoder.fit_transform(df["attack_type"].to_numpy())
    classes = list(encoder.classes_)
    print(f"[i] {len(df)} attack flows across {len(classes)} classes: {classes}")

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )

    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_te_s = scaler.transform(X_te)

    model = XGBClassifier(
        n_estimators=400,
        max_depth=7,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=1.0,
        min_child_weight=2,
        objective="multi:softprob",
        num_class=len(classes),
        eval_metric="mlogloss",
        n_jobs=-1,
        random_state=args.seed,
    )
    model.fit(X_tr_s, y_tr, eval_set=[(X_te_s, y_te)], verbose=False)

    pred = model.predict(X_te_s)
    print("\n=== XGBoost attack-type classifier (Route B) ===")
    print("\nConfusion matrix (rows = true, cols = pred):")
    print("labels:", classes)
    print(confusion_matrix(y_te, pred))
    print("\nReport:\n", classification_report(y_te, pred, target_names=classes, digits=4))

    importances = sorted(
        zip(FLOW_FEATURES, model.feature_importances_), key=lambda t: t[1], reverse=True
    )
    print("Top features:")
    for name, imp in importances[:12]:
        print(f"  {name:<22} {imp:.4f}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, OUT_DIR / "xgb_type_model.pkl")
    joblib.dump(scaler, OUT_DIR / "xgb_type_scaler.pkl")
    joblib.dump(classes, OUT_DIR / "xgb_type_labels.pkl")
    print(f"\n[+] saved type model + scaler + labels to {OUT_DIR}")
    print("[+] restart the backend or click 'Reload Models' to serve Route B.")


if __name__ == "__main__":
    main()
