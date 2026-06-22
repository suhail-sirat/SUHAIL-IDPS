#!/usr/bin/env python3
"""Train the zero-day (Barrier 3) autoencoder on NORMAL flows only.

The autoencoder learns to reconstruct normal traffic; at serving time a high
reconstruction error means "unlike anything normal" => candidate novel/zero-day
event. Training on normal-only is what makes it a true anomaly detector rather
than a supervised classifier.

Input : merged flow CSV (uses only rows where label == 0).
Output: models/autoencoder/{autoencoder.h5 (or .keras), ae_scaler.pkl, ae_threshold.pkl}

Best-practice choices:
- MinMax scaling (bounded [0,1] inputs pair well with a sigmoid output layer).
- Compact symmetric architecture with a bottleneck.
- Early stopping on validation loss.
- The detection THRESHOLD is derived from the normal reconstruction-error
  distribution (default: 99th percentile) and persisted, so the live engine has
  a principled cutoff instead of a hand-tuned guess. If attack rows are present
  we also print the separation you'd get.

    python src/training/train_autoencoder.py --data data/flows/all_flows.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.flow_features import FLOW_FEATURES, LABEL_COLUMN  # noqa: E402

OUT_DIR = PROJECT_ROOT / "models" / "autoencoder"


def build_model(input_dim: int):
    import tensorflow as tf

    model = tf.keras.Sequential(
        [
            tf.keras.layers.Input(shape=(input_dim,)),
            tf.keras.layers.Dense(48, activation="relu"),
            tf.keras.layers.Dense(24, activation="relu"),
            tf.keras.layers.Dense(12, activation="relu"),   # bottleneck
            tf.keras.layers.Dense(24, activation="relu"),
            tf.keras.layers.Dense(48, activation="relu"),
            tf.keras.layers.Dense(input_dim, activation="sigmoid"),
        ]
    )
    model.compile(optimizer="adam", loss="mse")
    return model


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(PROJECT_ROOT / "data" / "flows" / "all_flows.csv"))
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--batch-size", type=int, default=128)
    ap.add_argument("--percentile", type=float, default=99.0,
                    help="normal-error percentile used as the detection threshold")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    try:
        import tensorflow as tf
    except ImportError:
        raise SystemExit(
            "tensorflow is not installed. `pip install tensorflow-cpu` to train this barrier."
        )
    tf.random.set_seed(args.seed)

    df = pd.read_csv(args.data).fillna(0)
    normal = df[df[LABEL_COLUMN] == 0]
    X_normal = normal[FLOW_FEATURES].to_numpy(dtype=float)

    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X_normal)

    model = build_model(X_scaled.shape[1])
    es = tf.keras.callbacks.EarlyStopping(
        monitor="val_loss", patience=8, restore_best_weights=True
    )
    model.fit(
        X_scaled, X_scaled,
        epochs=args.epochs,
        batch_size=args.batch_size,
        validation_split=0.15,
        callbacks=[es],
        verbose=2,
    )

    # reconstruction error on normal -> threshold
    recon = model.predict(X_scaled, verbose=0)
    normal_err = np.mean(np.square(X_scaled - recon), axis=1)
    threshold = float(np.percentile(normal_err, args.percentile))

    print("\n=== Autoencoder (zero-day barrier) ===")
    print(f"normal error: mean={normal_err.mean():.5f} "
          f"p95={np.percentile(normal_err,95):.5f} "
          f"p99={np.percentile(normal_err,99):.5f}")
    print(f"threshold (p{args.percentile:g}) = {threshold:.6f}")

    attack = df[df[LABEL_COLUMN] == 1]
    if len(attack):
        Xa = scaler.transform(attack[FLOW_FEATURES].to_numpy(dtype=float))
        rec_a = model.predict(Xa, verbose=0)
        atk_err = np.mean(np.square(Xa - rec_a), axis=1)
        detected = float((atk_err >= threshold).mean())
        print(f"attack error mean={atk_err.mean():.5f} | "
              f"attacks above threshold = {detected:.1%}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    # .keras is the modern format; keep .h5 too for backward-compat loaders.
    model.save(OUT_DIR / "autoencoder.keras")
    model.save(OUT_DIR / "autoencoder.h5")
    joblib.dump(scaler, OUT_DIR / "ae_scaler.pkl")
    joblib.dump({"threshold": threshold, "percentile": args.percentile},
                OUT_DIR / "ae_threshold.pkl")
    print(f"\n[+] saved autoencoder + scaler + threshold to {OUT_DIR}")


if __name__ == "__main__":
    main()
