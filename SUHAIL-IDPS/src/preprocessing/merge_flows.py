#!/usr/bin/env python3
"""Merge per-capture flow CSVs into one shuffled, optionally balanced dataset.

Basic merge:
    python src/preprocessing/merge_flows.py \
        --in data/flows/normal_flows.csv data/flows/attack_*.csv \
        --out data/flows/all_flows.csv

Balanced merge (recommended for flow-based DoS data, where a SYN/UDP flood can
produce tens of thousands of 1-packet flows that swamp everything else):
    python src/preprocessing/merge_flows.py \
        --in data/flows/normal_flows.csv data/flows/attack_*.csv \
        --out data/flows/all_flows.csv \
        --cap-per-attack 2500        # each attack_type subsampled to <= 2500
        [--cap-normal 8000]          # optional cap on benign flows

Capping is per ``attack_type`` among *attack* rows (label==1). Benign rows
(label==0), whether from the normal capture or background inside an attack PCAP,
are pooled and optionally capped with --cap-normal. Sampling is seeded, so runs
are reproducible.
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
    parser = argparse.ArgumentParser(description="merge (and balance) flow CSVs")
    parser.add_argument("--in", dest="inp", nargs="+", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--cap-per-attack",
        type=int,
        default=None,
        help="subsample each attack_type (label==1) to at most N flows",
    )
    parser.add_argument(
        "--cap-normal",
        type=int,
        default=None,
        help="subsample benign flows (label==0) to at most N",
    )
    args = parser.parse_args()

    frames = [pd.read_csv(p) for p in args.inp]
    df = pd.concat(frames, ignore_index=True).fillna(0)

    missing = [c for c in FLOW_FEATURES + [LABEL_COLUMN] if c not in df.columns]
    if missing:
        raise SystemExit(f"merged data missing columns: {missing}")

    if "attack_type" not in df.columns:
        df["attack_type"] = ""
    df["attack_type"] = df["attack_type"].replace(0, "").fillna("")

    attack = df[df[LABEL_COLUMN] == 1]
    benign = df[df[LABEL_COLUMN] == 0]

    print(f"[*] before balancing: {len(attack)} attack, {len(benign)} benign")
    print("    attack breakdown:")
    for atype, n in attack["attack_type"].value_counts().items():
        print(f"      {atype or '(unlabelled)':16s} {n}")

    # -- cap each attack type -------------------------------------------------
    if args.cap_per_attack:
        capped = []
        for atype, grp in attack.groupby("attack_type"):
            if len(grp) > args.cap_per_attack:
                grp = grp.sample(n=args.cap_per_attack, random_state=args.seed)
            capped.append(grp)
        attack = pd.concat(capped, ignore_index=True) if capped else attack

    # -- cap benign -----------------------------------------------------------
    if args.cap_normal and len(benign) > args.cap_normal:
        benign = benign.sample(n=args.cap_normal, random_state=args.seed)

    df = pd.concat([attack, benign], ignore_index=True)
    df = df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)

    counts = df[LABEL_COLUMN].value_counts().to_dict()
    ratio = (counts.get(1, 0) / counts.get(0, 1)) if counts.get(0) else 0
    print(f"\n[+] merged {len(df)} flows -> {out}")
    print(f"    label counts: benign(0)={counts.get(0,0)}  attack(1)={counts.get(1,0)}"
          f"  (attack:normal = {ratio:.2f}:1)")
    print("    final attack breakdown:")
    for atype, n in df[df[LABEL_COLUMN] == 1]["attack_type"].value_counts().items():
        print(f"      {atype or '(unlabelled)':16s} {n}")


if __name__ == "__main__":
    main()
