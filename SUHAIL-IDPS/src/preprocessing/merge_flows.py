#!/usr/bin/env python3
"""Merge per-capture flow CSVs into one shuffled training dataset.

    python src/preprocessing/merge_flows.py \
        --in data/flows/normal_flows.csv data/flows/attack_flows.csv \
        --out data/flows/all_flows.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.flow_features import FLOW_FEATURES, LABEL_COLUMN  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="merge flow CSVs")
    parser.add_argument("--in", dest="inp", nargs="+", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    frames = [pd.read_csv(p) for p in args.inp]
    df = pd.concat(frames, ignore_index=True).fillna(0)

    missing = [c for c in FLOW_FEATURES + [LABEL_COLUMN] if c not in df.columns]
    if missing:
        raise SystemExit(f"merged data missing columns: {missing}")

    df = df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)

    counts = df[LABEL_COLUMN].value_counts().to_dict()
    print(f"[+] merged {len(df)} flows -> {out}")
    print(f"    label counts: {counts}")


if __name__ == "__main__":
    main()
