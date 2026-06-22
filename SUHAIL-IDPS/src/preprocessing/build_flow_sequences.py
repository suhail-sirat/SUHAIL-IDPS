#!/usr/bin/env python3
"""Build per-host flow *sequences* for the transformer (context) barrier.

The routine (XGBoost) and zero-day (autoencoder) barriers work on single flows.
The context barrier instead looks at a *sequence* of consecutive flows from the
same source host, so it can learn multi-flow attack signatures (port scans,
DDoS, beaconing) that a single flow can't express.

This script takes the merged flow CSV (one row per flow, with `src_ip` + `label`)
and produces fixed-length, sliding-window sequences grouped by source host. A
window is labelled attack (1) if ANY flow inside it is an attack - the standard
"window contains attack => malicious window" convention.

Output is a flattened CSV (SEQUENCE_LEN * NUM_FEATURES columns + label), the same
shape the old transformer expected, so training stays simple.

Usage
-----
    python src/preprocessing/build_flow_sequences.py \
        --in data/flows/all_flows.csv \
        --out data/flows/flow_sequences.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.flow_features import (  # noqa: E402
    FLOW_FEATURES,
    LABEL_COLUMN,
    SEQUENCE_LEN,
)


def build_sequences(df: pd.DataFrame, seq_len: int, stride: int) -> tuple[np.ndarray, np.ndarray]:
    feature_cols = FLOW_FEATURES
    X_seqs: list[np.ndarray] = []
    y_seqs: list[int] = []

    # Group by source host so a sequence is one host's activity over time.
    group_key = "src_ip" if "src_ip" in df.columns else None
    groups = df.groupby(group_key, sort=False) if group_key else [(None, df)]

    for _, g in groups:
        feats = g[feature_cols].to_numpy(dtype=float)
        labels = g[LABEL_COLUMN].to_numpy(dtype=int)
        n = len(feats)
        if n < seq_len:
            # pad short hosts up to one window so they're still usable
            if n == 0:
                continue
            pad = np.zeros((seq_len - n, len(feature_cols)))
            window = np.vstack([pad, feats])
            X_seqs.append(window)
            y_seqs.append(int(labels.max()))
            continue
        for start in range(0, n - seq_len + 1, stride):
            window = feats[start : start + seq_len]
            seq_label = int(labels[start : start + seq_len].max())
            X_seqs.append(window)
            y_seqs.append(seq_label)

    if not X_seqs:
        return np.empty((0, seq_len, len(feature_cols))), np.empty((0,))
    return np.asarray(X_seqs), np.asarray(y_seqs)


def main() -> None:
    parser = argparse.ArgumentParser(description="Flows -> transformer sequences")
    parser.add_argument("--in", dest="inp", required=True, help="merged flow CSV")
    parser.add_argument("--out", required=True, help="output sequence CSV")
    parser.add_argument("--seq-len", type=int, default=SEQUENCE_LEN)
    parser.add_argument("--stride", type=int, default=4)
    args = parser.parse_args()

    df = pd.read_csv(args.inp)
    df = df.fillna(0)
    X, y = build_sequences(df, args.seq_len, args.stride)

    print(f"[*] sequences: {X.shape}  attack ratio: {y.mean() if len(y) else 0:.3f}")

    # flatten to (n, seq_len*features) + label
    flat = X.reshape(X.shape[0], -1)
    out_df = pd.DataFrame(flat)
    out_df[LABEL_COLUMN] = y
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(out_path, index=False)
    print(f"[+] wrote {len(out_df)} sequences to {out_path}")


if __name__ == "__main__":
    main()
