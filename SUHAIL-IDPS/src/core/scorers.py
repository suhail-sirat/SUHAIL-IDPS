"""Pluggable barrier scorers with graceful degradation.

Each of the three barriers is exposed as a *scorer* with a uniform interface.
When the heavy ML stack is installed the scorer uses the real trained model
(XGBoost / Keras transformer / Keras autoencoder). When it is **not** installed
the scorer transparently falls back to a lightweight, dependency-free surrogate
that approximates the same signal from the same features.

The surrogates are *calibrated against the real data*: at construction they read
the persisted ``MinMaxScaler`` artifacts (which carry the true training feature
ranges) and learn the centroid / spread of normal traffic from the normal CSV.
This makes the fallback statistically grounded rather than arbitrary, so the
whole IDPS - capture, replay, decisioning and the live dashboard - works with
only numpy / pandas / scikit-learn present, and upgrades to the genuine neural
models the moment TensorFlow / XGBoost appear (just restart the backend).

The ``mode`` reported by each scorer ("model" or "surrogate") is surfaced in the
dashboard so the operator always knows which engine produced a score.
"""

from __future__ import annotations

import csv
import warnings
from typing import Any

import joblib
import numpy as np

from src.core import config
from src.core.features import packets_to_frame

# Silence the benign sklearn pickle-version mismatch on the MinMaxScalers; the
# data_min_ / data_max_ arrays we rely on are stable across these versions.
warnings.filterwarnings("ignore", message="Trying to unpickle estimator")
warnings.filterwarnings("ignore", message="X has feature names")
warnings.filterwarnings("ignore", message="X does not have valid feature names")

# Number of normal rows sampled to learn the surrogate's normal profile.
_NORMAL_SAMPLE = 4000


def _sigmoid(x: np.ndarray | float) -> np.ndarray | float:
    return 1.0 / (1.0 + np.exp(-x))


def _load_scaler(path) -> Any | None:
    try:
        return joblib.load(path)
    except Exception:
        return None


def _transform(scaler, frame) -> np.ndarray:
    """MinMax-transform a feature frame, passing raw values to avoid the
    sklearn 'fitted without feature names' warning, and return a 1-D row."""
    values = frame.values if hasattr(frame, "values") else np.asarray(frame)
    return scaler.transform(values)


def _normal_profile(scaler, feature_order: list[str]) -> tuple[np.ndarray, np.ndarray] | None:
    """Learn (mean, std) of scaled normal traffic from the normal CSV.

    Returns None if the file is unavailable so callers can degrade further.
    """
    path = config.DATA_DIR / "normal_processed.csv"
    if not path.exists():
        return None
    rows = []
    try:
        with path.open(newline="") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader):
                if i >= _NORMAL_SAMPLE:
                    break
                row.pop("label", None)
                frame = packets_to_frame(row, feature_order)
                rows.append(np.clip(_transform(scaler, frame)[0], 0.0, 1.0))
    except OSError:
        return None
    if not rows:
        return None
    arr = np.asarray(rows, dtype=float)
    return arr.mean(axis=0), arr.std(axis=0) + 1e-6


class RoutineScorer:
    """Barrier 1 - per-packet routine classifier (XGBoost or surrogate)."""

    name = "xgboost"

    def __init__(self, feature_order: list[str]):
        self.feature_order = feature_order
        self.mode = "unavailable"
        self.error: str | None = None
        self.model = None
        self.scaler = _load_scaler(config.XGB_SCALER_PATH)
        self._mu: np.ndarray | None = None
        self._sd: np.ndarray | None = None
        self._load()

    def _load(self) -> None:
        try:
            import xgboost  # noqa: F401  (presence check)

            self.model = joblib.load(config.XGB_MODEL_PATH)
            if self.scaler is None:
                self.scaler = joblib.load(config.XGB_SCALER_PATH)
            self.mode = "model"
            return
        except Exception as exc:
            self.error = str(exc)

        # Surrogate path: need the scaler + a learned normal profile.
        if self.scaler is None:
            self.mode = "unavailable"
            self.error = "xgb scaler missing"
            return
        profile = _normal_profile(self.scaler, self.feature_order)
        if profile is None:
            self.mode = "unavailable"
            self.error = "normal profile unavailable for surrogate"
            return
        self._mu, self._sd = profile
        self.mode = "surrogate"

    @property
    def available(self) -> bool:
        return self.mode in {"model", "surrogate"}

    def score(self, frame) -> tuple[float | None, str | None]:
        if self.mode == "model":
            try:
                x = _transform(self.scaler, frame[self.feature_order])
                if hasattr(self.model, "predict_proba"):
                    return float(self.model.predict_proba(x)[0][1]), None
                return float(self.model.predict(x)[0]), None
            except Exception as exc:
                return None, str(exc)
        if self.mode == "surrogate":
            return self._surrogate(frame), None
        return None, self.error

    def _surrogate(self, frame) -> float:
        """Routine score in [0, 1] from distance to the normal centroid.

        We scale the packet with the real training scaler, then measure its
        normalised (z-score) distance from the learned normal mean. Packets
        that look like routine traffic sit near the centroid -> low score;
        anything statistically far from normal -> high score. Calibrated so
        typical normal traffic stays well under the suspicious threshold.
        """
        x = np.clip(_transform(self.scaler, frame[self.feature_order])[0], 0.0, 1.0)
        z = (x - self._mu) / self._sd
        dist = float(np.sqrt(np.mean(z * z)))
        return float(_sigmoid(2.0 * (dist - 2.0)))


class AnomalyScorer:
    """Barrier 3 - zero-day anomaly detector (autoencoder or surrogate)."""

    name = "autoencoder"

    def __init__(self, feature_order: list[str]):
        self.feature_order = feature_order
        self.mode = "unavailable"
        self.error: str | None = None
        self.model = None
        self.scaler = _load_scaler(config.AE_SCALER_PATH)
        self._load()

    def _load(self) -> None:
        try:
            import tensorflow as tf

            self.model = tf.keras.models.load_model(config.AE_MODEL_PATH, compile=False)
            if self.scaler is None:
                self.scaler = joblib.load(config.AE_SCALER_PATH)
            self.mode = "model"
            return
        except Exception as exc:
            self.error = str(exc)

        if self.scaler is None:
            self.mode = "unavailable"
            self.error = "ae scaler missing"
            return
        self.mode = "surrogate"

    @property
    def available(self) -> bool:
        return self.mode in {"model", "surrogate"}

    def score(self, frame) -> tuple[float | None, str | None]:
        if self.mode == "model":
            try:
                x = _transform(self.scaler, frame[self.feature_order])
                reconstruction = self.model.predict(x, verbose=0)
                return float(np.mean(np.power(x - reconstruction, 2))), None
            except Exception as exc:
                return None, str(exc)
        if self.mode == "surrogate":
            return self._surrogate(frame), None
        return None, self.error

    def _surrogate(self, frame) -> float:
        """Reconstruction-error surrogate (out-of-normal-range energy).

        The autoencoder learned to reconstruct *normal* traffic, so inputs
        outside the normal min-max band produce high error. We emulate that:
        anything that scales outside [0, 1] under the normal-data scaler is
        "out of the ordinary", and we return the mean squared out-of-range
        distance, squashed with tanh into a small, threshold-comparable range
        so it lines up with the AE MSE threshold (~0.02 default).
        """
        raw = _transform(self.scaler, frame[self.feature_order])[0]
        over = np.clip(raw - 1.0, 0.0, None)
        under = np.clip(-raw, 0.0, None)
        out_of_range = over + under
        energy = float(np.mean(np.power(out_of_range, 2)))
        # Map unbounded energy into a bounded, threshold-friendly scale.
        return float(np.tanh(energy)) * 0.5 + 1e-6


class ContextScorer:
    """Barrier 2 - session/window transformer (Keras or surrogate)."""

    name = "transformer"

    def __init__(self, feature_order: list[str]):
        self.feature_order = feature_order
        self.mode = "unavailable"
        self.error: str | None = None
        self.model = None
        self._load()

    def _load(self) -> None:
        try:
            import tensorflow as tf

            self.model = tf.keras.models.load_model(
                config.TRANSFORMER_MODEL_PATH, compile=False
            )
            self.mode = "model"
        except Exception as exc:
            self.error = str(exc)
            # The surrogate needs no artifact - it reads the raw sequence.
            self.mode = "surrogate"

    @property
    def available(self) -> bool:
        return self.mode in {"model", "surrogate"}

    def score(self, sequence: np.ndarray | None) -> tuple[float | None, str | None]:
        if sequence is None:
            return None, "waiting for sequence context"
        if self.mode == "model":
            try:
                pred = self.model.predict(sequence, verbose=0)
                return float(np.ravel(pred)[0]), None
            except Exception as exc:
                return None, str(exc)
        if self.mode == "surrogate":
            return self._surrogate(sequence), None
        return None, self.error

    def _surrogate(self, sequence: np.ndarray) -> float:
        """Sequence-level threat from temporal statistics.

        The transformer's job is the "broader view": catching attacks visible
        only across a window (floods, scans, beaconing). We approximate that
        from the window's own statistics - regular high packet-rate (low delta
        variance == beaconing/flood) and high size dispersion (scanning) both
        raise the session threat.
        """
        window = np.asarray(sequence, dtype=float)
        if window.ndim == 3:
            window = window[0]
        idx = {f: i for i, f in enumerate(self.feature_order)}

        def col(name: str) -> np.ndarray:
            return window[:, idx[name]] if name in idx else np.zeros(len(window))

        # ignore zero-padding rows when computing stats
        non_pad = window[np.any(window != 0, axis=1)]
        if len(non_pad) < 2:
            return 0.0

        deltas = col("frame.time_delta")
        deltas = deltas[deltas > 0]
        lens = col("frame.len")
        lens = lens[lens > 0]

        if len(deltas) >= 2:
            rate_regularity = 1.0 / (
                1.0 + float(np.std(deltas)) / (float(np.mean(deltas)) + 1e-6)
            )
            speed = 1.0 / (1.0 + float(np.mean(deltas)))
        else:
            rate_regularity = speed = 0.0

        if len(lens) >= 2:
            size_spread = min(float(np.std(lens)) / (float(np.mean(lens)) + 1e-6), 1.0)
        else:
            size_spread = 0.0

        signal = 1.8 * rate_regularity * speed + 1.2 * size_spread
        return float(_sigmoid(3.0 * (signal - 0.8)))


def health_of(scorer) -> dict[str, Any]:
    return {
        "name": scorer.name,
        "available": scorer.available,
        "mode": scorer.mode,
        "error": scorer.error,
    }
