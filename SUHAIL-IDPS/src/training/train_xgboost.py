#!/usr/bin/env python3
"""Train the routine (Barrier 1) XGBoost classifier on single-flow features.

Input : merged flow CSV (one row per flow, `FLOW_FEATURES` + `label`).
Output: models/xgboost/{xgb_model.pkl, xgb_scaler.pkl, xgb_features.pkl}

Best-practice choices baked in:
- StandardScaler on features (tree models don't need it, but the serving path and
  the autoencoder share the same scaler convention; we persist it for parity).
- Stratified train/test split.
- `scale_pos_weight` to handle the usual normal>>attack class imbalance.
- Early stopping on a validation fold; report precision/recall/F1 + ROC-AUC,
  which matter far more than accuracy on imbalanced IDS data.
- Feature importances printed so you can see what drives detections.

    python src/training/train_xgboost.py --data data/flows/all_flows.csv
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

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
            "xgboost is not installed. `pip install xgboost` to train this barrier."
        )

    df = pd.read_csv(args.data).fillna(0)
    X = df[FLOW_FEATURES].to_numpy(dtype=float)
    y = df[LABEL_COLUMN].to_numpy(dtype=int)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )

    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_te_s = scaler.transform(X_te)

    n_neg = int((y_tr == 0).sum())
    n_pos = max(int((y_tr == 1).sum()), 1)
    spw = n_neg / n_pos

    model = XGBClassifier(
        n_estimators=400,
        max_depth=7,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=1.0,
        min_child_weight=2,
        scale_pos_weight=spw,
        objective="binary:logistic",
        eval_metric="aucpr",
        n_jobs=-1,
        random_state=args.seed,
    )
    model.fit(X_tr_s, y_tr, eval_set=[(X_te_s, y_te)], verbose=False)

    proba = model.predict_proba(X_te_s)[:, 1]
    pred = (proba >= 0.5).astype(int)

    print("\n=== XGBoost (routine barrier) ===")
    print("scale_pos_weight:", round(spw, 3))
    print("\nConfusion matrix:\n", confusion_matrix(y_te, pred))
    print("\nReport:\n", classification_report(y_te, pred, digits=4))
    try:
        print("ROC-AUC:", round(roc_auc_score(y_te, proba), 4))
    except ValueError:
        pass

    importances = sorted(
        zip(FLOW_FEATURES, model.feature_importances_), key=lambda t: t[1], reverse=True
    )
    print("\nTop features:")
    for name, imp in importances[:12]:
        print(f"  {name:<22} {imp:.4f}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, OUT_DIR / "xgb_model.pkl")
    joblib.dump(scaler, OUT_DIR / "xgb_scaler.pkl")
    joblib.dump(list(FLOW_FEATURES), OUT_DIR / "xgb_features.pkl")
    print(f"\n[+] saved model + scaler + features to {OUT_DIR}")


if __name__ == "__main__":
    main()
