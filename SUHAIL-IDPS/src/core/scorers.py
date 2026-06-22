"""Pluggable barrier scorers with graceful degradation (flow-based).

Each of the three barriers is exposed as a *scorer* with a uniform interface.
When the heavy ML stack is installed and a trained model is present, the scorer
uses the real model (XGBoost / Keras transformer / Keras autoencoder). Otherwise
it transparently falls back to a lightweight, dependency-free **surrogate** that
approximates the same signal from the same flow features.

All scorers operate on the canonical bidirectional-flow feature vector defined in
``src.core.flow_features`` - the SAME features used for offline training (from
PCAPs) and live serving (from the capture stream), so there is no train/serve
skew.

Surrogates are calibrated from a normal-flow profile: if
``data/flows/normal_flows.csv`` exists it is used; otherwise a sensible static
profile of benign-traffic ranges is used so the system still works before any
data is collected. Each scorer reports ``mode`` ("model" or "surrogate") so the
dashboard always shows which engine produced a score.
"""

from __future__ import annotations

import csv
import warnings
from typing import Any

import joblib
import numpy as np

from src.core import config
from src.core.flow_features import FLOW_FEATURES, NUM_FEATURES

warnings.filterwarnings("ignore", message="Trying to unpickle estimator")
warnings.filterwarnings("ignore", message="X has feature names")
warnings.filterwarnings("ignore", message="X does not have valid feature names")

_NORMAL_SAMPLE = 8000


def _sigmoid(x):
    return 1.0 / (1.0 + np.exp(-np.clip(x, -60, 60)))


def _load(path):
    try:
        return joblib.load(path)
    except Exception:
        return None


def _load_keras(primary, fallback):
    """Load a Keras model from the .keras path, falling back to .h5."""
    import tensorflow as tf

    for p in (primary, fallback):
        if p and p.exists():
            return tf.keras.models.load_model(p, compile=False)
    raise FileNotFoundError(f"no model at {primary} or {fallback}")


def _as_row(features: Any) -> np.ndarray:
    """Coerce a feature mapping/sequence into a 1xN float row in FLOW_FEATURES order."""
    if isinstance(features, dict):
        row = [float(features.get(name, 0.0)) for name in FLOW_FEATURES]
    else:
        row = list(np.asarray(features, dtype=float).ravel())
        if len(row) != NUM_FEATURES:
            row = (row + [0.0] * NUM_FEATURES)[:NUM_FEATURES]
    return np.asarray([row], dtype=float)


def _synthetic_normal_profile() -> tuple[np.ndarray, np.ndarray]:
    """Calibrate from the synthetic normal-flow generator when no real data exists.

    This guarantees the surrogate's notion of "normal" matches the normal flows
    the replay produces, so benign traffic scores low and only genuinely
    abnormal flows cross the thresholds.
    """
    import random

    from src.preprocessing.synth_flows import generate_flow

    rng = random.Random(20240601)
    rows = []
    for _ in range(2000):
        feats, _ = generate_flow(False, "10.0.0.1", rng)
        rows.append([float(feats[name]) for name in FLOW_FEATURES])
    arr = np.asarray(rows, dtype=float)
    return arr.mean(axis=0), arr.std(axis=0) + 1e-6


def _normal_profile() -> tuple[np.ndarray, np.ndarray]:
    """Learn (mean, std) of normal flows from the real dataset if present,
    else from the synthetic generator (keeps replay/serving consistent)."""
    path = config.FLOWS_DIR / "normal_flows.csv"
    if not path.exists():
        path = config.FLOWS_DIR / "all_flows.csv"
    if path.exists():
        rows = []
        try:
            with path.open(newline="") as fh:
                reader = csv.DictReader(fh)
                for i, r in enumerate(reader):
                    if i >= _NORMAL_SAMPLE:
                        break
                    if r.get("label") not in (None, "", "0"):
                        continue
                    rows.append([float(r.get(name, 0) or 0) for name in FLOW_FEATURES])
        except OSError:
            rows = []
        if len(rows) >= 50:
            arr = np.asarray(rows, dtype=float)
            return arr.mean(axis=0), arr.std(axis=0) + 1e-6
    return _synthetic_normal_profile()


class RoutineScorer:
    """Barrier 1 - per-flow routine classifier (XGBoost or surrogate)."""

    name = "xgboost"

    def __init__(self):
        self.mode = "unavailable"
        self.error: str | None = None
        self.model = None
        self.scaler = _load(config.XGB_SCALER_PATH)
        self._mu = self._sd = None
        self._load()

    def _load(self) -> None:
        try:
            import xgboost  # noqa: F401

            if not config.XGB_MODEL_PATH.exists():
                raise FileNotFoundError("xgb model not trained yet")
            self.model = joblib.load(config.XGB_MODEL_PATH)
            self.scaler = self.scaler or _load(config.XGB_SCALER_PATH)
            self.mode = "model"
            return
        except Exception as exc:
            self.error = str(exc)
        self._mu, self._sd = _normal_profile()
        self.mode = "surrogate"

    @property
    def available(self) -> bool:
        return self.mode in {"model", "surrogate"}

    def score(self, features) -> tuple[float | None, str | None]:
        row = _as_row(features)
        if self.mode == "model":
            try:
                x = self.scaler.transform(row) if self.scaler is not None else row
                if hasattr(self.model, "predict_proba"):
                    return float(self.model.predict_proba(x)[0][1]), None
                return float(self.model.predict(x)[0]), None
            except Exception as exc:
                return None, str(exc)
        if self.mode == "surrogate":
            return self._surrogate(row[0]), None
        return None, self.error

    def _surrogate(self, row: np.ndarray) -> float:
        """Routine score from normalised distance to the benign-flow centroid."""
        z = (row - self._mu) / self._sd
        dist = float(np.sqrt(np.mean(z * z)))
        return float(_sigmoid(1.6 * (dist - 2.2)))


class AnomalyScorer:
    """Barrier 3 - zero-day anomaly detector (autoencoder or surrogate)."""

    name = "autoencoder"

    def __init__(self):
        self.mode = "unavailable"
        self.error: str | None = None
        self.model = None
        self.scaler = _load(config.AE_SCALER_PATH)
        self.trained_threshold: float | None = None
        self._mu = self._sd = None
        self._load()

    def _load(self) -> None:
        thr = _load(config.AE_THRESHOLD_PATH)
        if isinstance(thr, dict):
            self.trained_threshold = float(thr.get("threshold")) if thr.get("threshold") else None
        try:
            import tensorflow  # noqa: F401

            self.model = _load_keras(config.AE_MODEL_PATH, config.AE_MODEL_PATH_H5)
            self.scaler = self.scaler or _load(config.AE_SCALER_PATH)
            self.mode = "model"
            return
        except Exception as exc:
            self.error = str(exc)
        self._mu, self._sd = _normal_profile()
        self.mode = "surrogate"

    @property
    def available(self) -> bool:
        return self.mode in {"model", "surrogate"}

    def score(self, features) -> tuple[float | None, str | None]:
        row = _as_row(features)
        if self.mode == "model":
            try:
                x = self.scaler.transform(row) if self.scaler is not None else row
                recon = self.model.predict(x, verbose=0)
                return float(np.mean(np.square(x - recon))), None
            except Exception as exc:
                return None, str(exc)
        if self.mode == "surrogate":
            return self._surrogate(row[0]), None
        return None, self.error

    def _surrogate(self, row: np.ndarray) -> float:
        """Reconstruction-error surrogate: mean squared z-distance from normal,
        squashed into a small positive range comparable to an MSE threshold."""
        z = (row - self._mu) / self._sd
        energy = float(np.mean(np.square(np.clip(np.abs(z) - 1.0, 0.0, None))))
        return float(np.tanh(energy / 6.0)) * 0.5 + 1e-6


class ContextScorer:
    """Barrier 2 - per-host flow-sequence transformer (Keras or surrogate)."""

    name = "transformer"

    def __init__(self):
        self.mode = "unavailable"
        self.error: str | None = None
        self.model = None
        self.scaler = _load(config.TRANSFORMER_SCALER_PATH)
        self._mu = self._sd = None
        self._load()

    def _load(self) -> None:
        try:
            import tensorflow  # noqa: F401

            self.model = _load_keras(
                config.TRANSFORMER_MODEL_PATH, config.TRANSFORMER_MODEL_PATH_H5
            )
            self.mode = "model"
            return
        except Exception as exc:
            self.error = str(exc)
        self._mu, self._sd = _normal_profile()
        self.mode = "surrogate"

    @property
    def available(self) -> bool:
        return self.mode in {"model", "surrogate"}

    def score(self, sequence) -> tuple[float | None, str | None]:
        if sequence is None:
            return None, "waiting for sequence context"
        seq = np.asarray(sequence, dtype=float)
        if seq.ndim == 2:
            seq = seq[np.newaxis, ...]
        if self.mode == "model":
            try:
                x = seq
                if isinstance(self.scaler, dict):
                    x = (seq - self.scaler["mean"]) / self.scaler["std"]
                pred = self.model.predict(x, verbose=0)
                return float(np.ravel(pred)[0]), None
            except Exception as exc:
                return None, str(exc)
        if self.mode == "surrogate":
            return self._surrogate(seq[0]), None
        return None, self.error

    def _surrogate(self, window: np.ndarray) -> float:
        """Sequence threat from how far the host's recent flows drift from normal.

        A host whose recent flows are collectively far from the benign centroid
        (many fresh flows, scan-like fan-out, flood-like rates) scores high.
        Zero-padding rows are ignored.
        """
        non_pad = window[np.any(window != 0, axis=1)]
        if len(non_pad) < 2:
            return 0.0
        z = (non_pad - self._mu) / self._sd
        per_flow = np.sqrt(np.mean(z * z, axis=1))
        # combine average drift with how consistent it is (a sustained campaign)
        drift = float(np.mean(per_flow))
        consistency = 1.0 - float(np.std(per_flow)) / (drift + 1e-6)
        consistency = max(min(consistency, 1.0), 0.0)
        signal = drift * (0.6 + 0.4 * consistency)
        return float(_sigmoid(1.4 * (signal - 2.2)))


def health_of(scorer) -> dict[str, Any]:
    return {
        "name": scorer.name,
        "available": scorer.available,
        "mode": scorer.mode,
        "error": scorer.error,
    }
