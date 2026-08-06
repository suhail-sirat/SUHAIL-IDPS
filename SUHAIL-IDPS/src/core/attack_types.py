"""Attack-type naming for hostile flows — Route A (heuristic) + Route B (model).

When a barrier decides a flow is ATTACK/SUSPICIOUS the operator wants to know
*what kind* of attack it is, not just that something is wrong. This module names
the archetype behind a flow:

* **Route A — heuristic (always available).** A dependency-free rule labeler that
  reads the canonical flow features and matches the well-known signatures
  (port scan, SYN/UDP/ICMP flood, HTTP flood, Slowloris/slow-DoS). It needs no
  ML stack, runs live, and is fully explainable — so the dashboard can always
  name an attack, even before any model is trained.

* **Route B — model (optional upgrade).** A multi-class classifier trained on the
  ``attack_type`` column of the flow dataset (see
  ``src/training/train_attack_type.py``). When its artifacts are present *and*
  xgboost is installed, it is used and returns a real per-class probability;
  otherwise the scorer transparently falls back to Route A.

The two routes share one interface (:class:`AttackTypeScorer.classify`) so the
engine doesn't care which is active, and switching from A to B is just "train the
type model, then Reload Models".
"""

from __future__ import annotations

import warnings
from typing import Any

import joblib
import numpy as np

from src.core import config
from src.core.flow_features import FLOW_FEATURES

warnings.filterwarnings("ignore", message="X has feature names")
warnings.filterwarnings("ignore", message="X does not have valid feature names")

# Canonical archetypes the heuristic + the model both speak.
ATTACK_TYPES = (
    "portscan",
    "synflood",
    "udpflood",
    "icmpflood",
    "httpflood",
    "slowloris",
    "dos",          # generic flood/DoS that doesn't match a sharper signature
    "anomaly",      # hostile-but-unrecognised (fallback)
)

_HTTP_PORTS = {80, 443, 8080, 8000, 8443}
# Well-known service ports: a half-open flood against one of these reads as a
# SYN flood; against varied/uncommon ports it reads as a port scan (the port
# fan-out that distinguishes them isn't visible inside a single flow).
_SERVICE_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587,
    993, 995, 3306, 3389, 5432, 6379, 8000, 8080, 8443,
}


def _feat(features: Any) -> dict[str, float]:
    """Coerce a feature mapping/vector into a name->value dict (missing -> 0)."""
    if isinstance(features, dict):
        return {name: float(features.get(name, 0.0) or 0.0) for name in FLOW_FEATURES}
    row = list(np.asarray(features, dtype=float).ravel())
    row = (row + [0.0] * len(FLOW_FEATURES))[: len(FLOW_FEATURES)]
    return dict(zip(FLOW_FEATURES, row))


def heuristic_attack_type(features: Any) -> tuple[str, float]:
    """Route A: name the attack archetype from a single flow's features.

    Returns ``(type, confidence)`` where confidence is a rough 0-1 strength of
    the match. The rules mirror the archetype signatures used across the
    flow-based NIDS literature (CIC-IDS style) and this project's own generator.
    """
    f = _feat(features)
    proto = int(round(f.get("protocol", 0)))
    fwd = f.get("total_fwd_packets", 0.0)
    pps = f.get("flow_pkts_per_s", 0.0)
    syn = f.get("syn_flag_count", 0.0)
    ack = f.get("ack_flag_count", 0.0)
    dur = f.get("flow_duration", 0.0)
    dport = int(round(f.get("dst_port", 0)))
    service_port = dport in _SERVICE_PORTS
    web_port = dport in _HTTP_PORTS

    # ICMP flood — any sustained ICMP volume.
    if proto == 1 and (pps >= 100 or fwd >= 100):
        return "icmpflood", 0.9

    # UDP flood — UDP with a high packet rate or a big one-shot burst.
    if proto == 17 and (pps >= 500 or fwd >= 200):
        return "udpflood", min(0.97, 0.6 + pps / 1_000_000.0)

    if proto == 6:
        # Slowloris / slow-DoS — long-lived, trickle-rate TCP session.
        if dur >= 10 and pps <= 5:
            return "slowloris", 0.85

        half_open = syn >= 1 and ack <= max(1.0, syn)   # SYN(s) with no real reply
        established_flood = syn <= 0 and ack >= 1        # reuses a connection, floods requests

        # HTTP flood — established TCP to a web port (no in-flow handshake),
        # i.e. request flooding over a reused connection. Slowloris is already
        # taken above by its long-duration/trickle signature.
        if established_flood and web_port:
            return "httpflood", 0.75 if (pps >= 50 or fwd >= 50) else 0.6

        # Half-open burst — a service port reads as a SYN flood; varied/uncommon
        # ports read as a port scan (per-flow we can't see the port fan-out).
        if half_open:
            if service_port:
                return "synflood", min(0.97, 0.6 + syn / 4000.0)
            return "portscan", 0.85

        # Fast TCP that didn't match a sharper signature.
        if pps >= 1000 or fwd >= 500:
            return "httpflood" if web_port else "dos", 0.6

        # Flagged TCP to a web port that isn't a half-open flood or a slow-DoS:
        # short, complete request sessions repeated as a flood.
        if web_port:
            return "httpflood", 0.55

    # Recognisably flood-like but no sharp match.
    if pps >= 2000 or fwd >= 500:
        return "dos", 0.55

    return "anomaly", 0.4


class AttackTypeScorer:
    """Names the attack behind a hostile flow (Route B model, else Route A)."""

    name = "attack_type"

    def __init__(self) -> None:
        self.mode = "heuristic"        # "model" (Route B) or "heuristic" (Route A)
        self.error: str | None = None
        self.model = None
        self.scaler = None
        self.labels: list[str] | None = None
        self._load()

    def _load(self) -> None:
        try:
            import xgboost  # noqa: F401

            if not config.XGB_TYPE_MODEL_PATH.exists():
                raise FileNotFoundError("attack-type model not trained yet")
            self.model = joblib.load(config.XGB_TYPE_MODEL_PATH)
            if config.XGB_TYPE_SCALER_PATH.exists():
                self.scaler = joblib.load(config.XGB_TYPE_SCALER_PATH)
            self.labels = list(joblib.load(config.XGB_TYPE_LABELS_PATH))
            self.mode = "model"
        except Exception as exc:
            self.error = str(exc)
            self.mode = "heuristic"

    @property
    def route(self) -> str:
        return "B (multi-class model)" if self.mode == "model" else "A (heuristic)"

    def classify(self, features: Any) -> dict[str, Any]:
        """Return ``{"type", "confidence", "source"}`` for a hostile flow."""
        if self.mode == "model" and self.model is not None:
            try:
                row = np.asarray([[
                    float(_feat(features)[name]) for name in FLOW_FEATURES
                ]], dtype=float)
                x = self.scaler.transform(row) if self.scaler is not None else row
                proba = np.asarray(self.model.predict_proba(x))[0]
                idx = int(np.argmax(proba))
                label = self.labels[idx] if self.labels else str(idx)
                return {
                    "type": str(label),
                    "confidence": round(float(proba[idx]), 4),
                    "source": "model",
                }
            except Exception as exc:  # fall back rather than lose the label
                self.error = str(exc)

        atype, conf = heuristic_attack_type(features)
        return {"type": atype, "confidence": round(float(conf), 4), "source": "heuristic"}

    def health(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "mode": self.mode,
            "route": self.route,
            "classes": list(self.labels) if self.labels else list(ATTACK_TYPES),
            "error": self.error,
        }
