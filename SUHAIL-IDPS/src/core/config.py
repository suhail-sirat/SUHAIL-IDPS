"""Central configuration and runtime state for the SUHAIL-IDPS engine.

Everything that needs tuning lives here so the dashboard, the engine and the
capture layer all agree on a single source of truth. Values can be overridden
with environment variables (prefixed ``IDPS_``) or, at runtime, through the
``/api/settings`` endpoint which persists to ``config.runtime.json``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from threading import RLock
from typing import Any

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
BASE_DIR = Path(__file__).resolve().parents[2]          # .../SUHAIL-IDPS
MODELS_DIR = BASE_DIR / "models"
DATA_DIR = BASE_DIR / "data" / "raw"
LOGS_DIR = BASE_DIR / "logs"
RUNTIME_CONFIG_PATH = BASE_DIR / "config.runtime.json"

LOGS_DIR.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------- #
# Model artifact locations
# --------------------------------------------------------------------------- #
XGB_MODEL_PATH = MODELS_DIR / "xgboost" / "xgb_model.pkl"
XGB_SCALER_PATH = MODELS_DIR / "xgboost" / "xgb_scaler.pkl"
XGB_FEATURES_PATH = MODELS_DIR / "xgboost" / "xgb_features.pkl"

AE_MODEL_PATH = MODELS_DIR / "autoencoder" / "autoencoder.h5"
AE_SCALER_PATH = MODELS_DIR / "autoencoder" / "ae_scaler.pkl"

TRANSFORMER_MODEL_PATH = MODELS_DIR / "transformer" / "transformer_model.h5"

# --------------------------------------------------------------------------- #
# Sequence / flow parameters (must match training: SEQ_LEN=50, 13 features)
# --------------------------------------------------------------------------- #
SEQUENCE_LEN = int(os.getenv("IDPS_SEQUENCE_LEN", "50"))
MAX_FLOWS = int(os.getenv("IDPS_MAX_FLOWS", "4096"))

# When True the transformer pads short flows up to SEQUENCE_LEN and scores
# early (lower confidence) instead of waiting for a full real window.
TRANSFORMER_PAD_EARLY = os.getenv("IDPS_TRANSFORMER_PAD_EARLY", "1") == "1"
# Minimum real packets in a flow before an early/padded transformer read.
TRANSFORMER_MIN_CONTEXT = int(os.getenv("IDPS_TRANSFORMER_MIN_CONTEXT", "8"))


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


# Default decision thresholds. The autoencoder threshold is a reconstruction
# error (MSE) cutoff; the others are probabilities in [0, 1].
DEFAULT_THRESHOLDS: dict[str, float] = {
    "xgb_suspicious": _env_float("IDPS_XGB_SUSPICIOUS_THRESHOLD", 0.60),
    "xgb_attack": _env_float("IDPS_XGB_ATTACK_THRESHOLD", 0.85),
    "autoencoder": _env_float("IDPS_AE_THRESHOLD", 0.02),
    "transformer": _env_float("IDPS_TRANSFORMER_THRESHOLD", 0.50),
}

# Prevention / response policy defaults.
DEFAULT_POLICY: dict[str, Any] = {
    "auto_block": False,
    # dry_run False == real iptables enforcement (requires root). The dashboard
    # exposes a clear toggle; default to enforce per project requirement.
    "dry_run": False,
    "block_threshold": 5,
    "block_duration_seconds": 300,
    "event_limit": 1000,
    "alert_min_severity": "suspicious",   # observe | suspicious | attack
}


class Settings:
    """Thread-safe, persistable runtime settings.

    Holds the decision thresholds and the prevention policy. Reads from the
    persisted JSON file on construction, writes back on every update so a
    backend restart keeps the operator's tuning.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self.thresholds: dict[str, float] = dict(DEFAULT_THRESHOLDS)
        self.policy: dict[str, Any] = dict(DEFAULT_POLICY)
        self._load()

    # -- persistence ------------------------------------------------------- #
    def _load(self) -> None:
        if not RUNTIME_CONFIG_PATH.exists():
            return
        try:
            data = json.loads(RUNTIME_CONFIG_PATH.read_text())
        except (OSError, json.JSONDecodeError):
            return
        with self._lock:
            for key, value in (data.get("thresholds") or {}).items():
                if key in self.thresholds:
                    try:
                        self.thresholds[key] = float(value)
                    except (TypeError, ValueError):
                        pass
            for key, value in (data.get("policy") or {}).items():
                if key in self.policy:
                    self.policy[key] = value

    def _save(self) -> None:
        try:
            RUNTIME_CONFIG_PATH.write_text(
                json.dumps(
                    {"thresholds": self.thresholds, "policy": self.policy},
                    indent=2,
                )
            )
        except OSError:
            pass

    # -- mutation ---------------------------------------------------------- #
    def update_thresholds(self, values: dict[str, Any]) -> dict[str, float]:
        with self._lock:
            for key in self.thresholds:
                if key in values:
                    try:
                        self.thresholds[key] = float(values[key])
                    except (TypeError, ValueError):
                        continue
            self._save()
            return dict(self.thresholds)

    def update_policy(self, values: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            for key in self.policy:
                if key in values:
                    self.policy[key] = values[key]
            self._save()
            return dict(self.policy)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "thresholds": dict(self.thresholds),
                "policy": dict(self.policy),
                "sequence_len": SEQUENCE_LEN,
                "transformer_pad_early": TRANSFORMER_PAD_EARLY,
            }


# Singleton shared by engine + backend.
settings = Settings()
