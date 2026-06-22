#!/usr/bin/env python3
"""Train the context (Barrier 2) transformer on per-host flow SEQUENCES.

Input : flattened sequence CSV from build_flow_sequences.py
        (SEQUENCE_LEN * NUM_FEATURES columns + label).
Output: models/transformer/{transformer_model.keras (+ .h5), transformer_scaler.pkl}

The transformer sees a window of consecutive flows from one host and decides
whether that *behaviour over time* is hostile - catching multi-flow attacks
(scans, DDoS, beaconing) that single-flow models miss. We use a small
multi-head-attention encoder with positional information via a learnable
projection, global pooling, and a sigmoid head. Per-feature standardisation is
fit on the training flows and persisted for the serving path.

    python src/training/train_transformer.py --data data/flows/flow_sequences.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.flow_features import (  # noqa: E402
    LABEL_COLUMN,
    NUM_FEATURES,
    SEQUENCE_LEN,
)

OUT_DIR = PROJECT_ROOT / "models" / "transformer"


def transformer_encoder(inputs, head_size, num_heads, ff_dim, dropout):
    import tensorflow as tf

    x = tf.keras.layers.LayerNormalization(epsilon=1e-6)(inputs)
    attn = tf.keras.layers.MultiHeadAttention(
        key_dim=head_size, num_heads=num_heads, dropout=dropout
    )(x, x)
    x = tf.keras.layers.Add()([attn, inputs])

    y = tf.keras.layers.LayerNormalization(epsilon=1e-6)(x)
    y = tf.keras.layers.Dense(ff_dim, activation="relu")(y)
    y = tf.keras.layers.Dropout(dropout)(y)
    y = tf.keras.layers.Dense(inputs.shape[-1])(y)
    return tf.keras.layers.Add()([y, x])


def build_model(seq_len, n_features):
    import tensorflow as tf

    inputs = tf.keras.Input(shape=(seq_len, n_features))
    x = tf.keras.layers.Dense(64)(inputs)            # project + learnable embedding
    for _ in range(2):
        x = transformer_encoder(x, head_size=32, num_heads=4, ff_dim=128, dropout=0.2)
    x = tf.keras.layers.GlobalAveragePooling1D()(x)
    x = tf.keras.layers.Dense(64, activation="relu")(x)
    x = tf.keras.layers.Dropout(0.3)(x)
    outputs = tf.keras.layers.Dense(1, activation="sigmoid")(x)
    model = tf.keras.Model(inputs, outputs)
    model.compile(
        optimizer=tf.keras.optimizers.Adam(1e-3),
        loss="binary_crossentropy",
        metrics=["accuracy", tf.keras.metrics.AUC(name="auc")],
    )
    return model


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(PROJECT_ROOT / "data" / "flows" / "flow_sequences.csv"))
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--batch-size", type=int, default=64)
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
    y = df[LABEL_COLUMN].to_numpy(dtype=int)
    X = df.drop(columns=[LABEL_COLUMN]).to_numpy(dtype=float)

    seq_len, n_features = SEQUENCE_LEN, NUM_FEATURES
    if X.shape[1] != seq_len * n_features:
        # infer in case SEQUENCE_LEN was overridden when building sequences
        n_features = NUM_FEATURES
        seq_len = X.shape[1] // n_features
    X = X.reshape(-1, seq_len, n_features)

    # standardise per feature using training-fold statistics
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=args.seed, stratify=y
    )
    flat = X_tr.reshape(-1, n_features)
    mean = flat.mean(axis=0)
    std = flat.std(axis=0) + 1e-6
    X_tr = (X_tr - mean) / std
    X_te = (X_te - mean) / std

    model = build_model(seq_len, n_features)
    es = tf.keras.callbacks.EarlyStopping(
        monitor="val_auc", mode="max", patience=6, restore_best_weights=True
    )
    model.fit(
        X_tr, y_tr,
        validation_data=(X_te, y_te),
        epochs=args.epochs,
        batch_size=args.batch_size,
        callbacks=[es],
        verbose=2,
    )

    proba = model.predict(X_te, verbose=0).ravel()
    pred = (proba >= 0.5).astype(int)
    print("\n=== Transformer (context barrier) ===")
    print("Confusion matrix:\n", confusion_matrix(y_te, pred))
    print("\nReport:\n", classification_report(y_te, pred, digits=4))
    try:
        print("ROC-AUC:", round(roc_auc_score(y_te, proba), 4))
    except ValueError:
        pass

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    model.save(OUT_DIR / "transformer_model.keras")
    model.save(OUT_DIR / "transformer_model.h5")
    joblib.dump({"mean": mean, "std": std, "seq_len": seq_len, "n_features": n_features},
                OUT_DIR / "transformer_scaler.pkl")
    print(f"\n[+] saved transformer + scaler to {OUT_DIR}")


if __name__ == "__main__":
    main()
