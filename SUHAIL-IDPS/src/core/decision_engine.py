"""Serving-time three-barrier IDPS decision engine (flow-based).

The engine scores **bidirectional flows** (not single packets) and fuses three
independently-trained models into a layered defence:

* **Barrier 1 - Routine (XGBoost):** classifies each completed flow's feature
  vector. Always-on first line.
* **Barrier 2 - Context (Transformer):** looks at the recent *sequence of flows*
  from the same source host - the "broader view" that catches multi-flow attacks
  (scans, DDoS, beaconing). Engages when a flow is suspicious/anomalous, padding
  short host-histories so it can give an early read on live traffic.
* **Barrier 3 - Zero-day (Autoencoder):** reconstruction-error anomaly detector
  trained on normal flows only. High error == out-of-distribution == candidate
  novel/zero-day event.

Every barrier is backed by a pluggable scorer (``src.core.scorers``) that uses
the real trained model when available and a dependency-free surrogate otherwise,
so the full pipeline runs either way and upgrades automatically once flow models
are trained (Models -> Reload).

`analyze_flow` is the entry point; it takes a flow feature mapping plus metadata.
`analyze_packet` is kept as a thin compatibility shim used by the offline/legacy
per-packet callers and tests.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any

import numpy as np

from src.core import config
from src.core.config import settings
from src.core.flow_features import FLOW_FEATURES, NUM_FEATURES
from src.core.scorers import AnomalyScorer, ContextScorer, RoutineScorer, health_of


class DecisionEngine:
    """Serving-time three-barrier IDPS engine over bidirectional flows."""

    def __init__(
        self,
        sequence_len: int = config.SEQUENCE_LEN,
        max_hosts: int = config.MAX_FLOWS,
    ):
        self.sequence_len = sequence_len
        self.max_hosts = max_hosts
        self.feature_order = list(FLOW_FEATURES)
        self.num_features = NUM_FEATURES
        self.lock = Lock()
        # per-source-host history of recent flow feature rows (for the context barrier)
        self.host_history: dict[str, deque[list[float]]] = defaultdict(
            lambda: deque(maxlen=self.sequence_len)
        )

        self.routine = RoutineScorer()
        self.context = ContextScorer()
        self.anomaly = AnomalyScorer()

    # -- thresholds proxy --------------------------------------------------- #
    @property
    def thresholds(self) -> dict[str, float]:
        return settings.thresholds

    def update_thresholds(self, values: dict[str, Any]) -> dict[str, float]:
        return settings.update_thresholds(values)

    def reload_models(self) -> dict[str, Any]:
        with self.lock:
            self.routine = RoutineScorer()
            self.context = ContextScorer()
            self.anomaly = AnomalyScorer()
        return self.health()

    def health(self) -> dict[str, Any]:
        return {
            "feature_order": self.feature_order,
            "sequence_len": self.sequence_len,
            "transformer_pad_early": config.TRANSFORMER_PAD_EARLY,
            "flow_based": True,
            "thresholds": dict(settings.thresholds),
            "models": {
                "xgboost": health_of(self.routine),
                "autoencoder": health_of(self.anomaly),
                "transformer": health_of(self.context),
            },
        }

    # -- host history bookkeeping ------------------------------------------ #
    def _host_key(self, metadata: dict[str, Any] | None) -> str:
        if not metadata:
            return "global"
        return str(metadata.get("src_ip") or metadata.get("source") or "unknown-src")

    def _remember(self, host: str, row: list[float]) -> int:
        with self.lock:
            if len(self.host_history) > self.max_hosts and host not in self.host_history:
                self.host_history.pop(next(iter(self.host_history)), None)
            self.host_history[host].append(row)
            return len(self.host_history[host])

    def _sequence_for(self, host: str) -> tuple[np.ndarray | None, bool]:
        with self.lock:
            rows = list(self.host_history.get(host, []))
        if len(rows) >= self.sequence_len:
            return np.asarray(rows[-self.sequence_len :], dtype=float), False
        if config.TRANSFORMER_PAD_EARLY and len(rows) >= config.TRANSFORMER_MIN_CONTEXT:
            pad = [[0.0] * self.num_features for _ in range(self.sequence_len - len(rows))]
            return np.asarray(pad + rows, dtype=float), True
        return None, False

    @staticmethod
    def _row_from(features: Any) -> list[float]:
        if isinstance(features, dict):
            return [float(features.get(name, 0.0)) for name in FLOW_FEATURES]
        arr = list(np.asarray(features, dtype=float).ravel())
        return (arr + [0.0] * NUM_FEATURES)[:NUM_FEATURES]

    # -- main entry point --------------------------------------------------- #
    def analyze_flow(
        self,
        features: Any,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        started = time.perf_counter()
        th = settings.thresholds
        row = self._row_from(features)
        host = self._host_key(metadata)
        history_len = self._remember(host, row)

        t0 = time.perf_counter()
        xgb_score, xgb_error = self.routine.score(row)
        xgb_latency = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        ae_score, ae_error = self.anomaly.score(row)
        ae_latency = (time.perf_counter() - t0) * 1000

        xgb_suspicious = xgb_score is not None and xgb_score >= th["xgb_suspicious"]
        ae_anomaly = ae_score is not None and ae_score >= th["autoencoder"]
        needs_context = xgb_suspicious or ae_anomaly

        transformer_score = None
        transformer_error = None
        transformer_latency = 0.0
        transformer_padded = False

        if needs_context:
            seq, transformer_padded = self._sequence_for(host)
            t0 = time.perf_counter()
            transformer_score, transformer_error = self.context.score(seq)
            transformer_latency = (time.perf_counter() - t0) * 1000

        status, severity, reason = self._decide(
            xgb_score, ae_score, transformer_score, transformer_padded
        )
        threat_score = self._threat_score(xgb_score, ae_score, transformer_score)

        return {
            "status": status,
            "severity": severity,
            "reason": reason,
            "threat_score": threat_score,
            "flow_key": host,
            "sequence": {
                "required": needs_context,
                "length": history_len,
                "ready": history_len >= self.sequence_len,
                "padded": transformer_padded,
                "target_length": self.sequence_len,
            },
            "barriers": {
                "routine_xgboost": {
                    "score": xgb_score,
                    "threshold": th["xgb_suspicious"],
                    "attack_threshold": th["xgb_attack"],
                    "mode": self.routine.mode,
                    "state": self._state(xgb_score, th["xgb_suspicious"], xgb_error),
                    "latency_ms": round(xgb_latency, 3),
                    "error": xgb_error,
                },
                "context_transformer": {
                    "score": transformer_score,
                    "threshold": th["transformer"],
                    "padded": transformer_padded,
                    "mode": self.context.mode,
                    "state": self._state(
                        transformer_score, th["transformer"], transformer_error,
                        waiting_text="WAITING",
                    ),
                    "latency_ms": round(transformer_latency, 3),
                    "error": transformer_error,
                },
                "zero_day_autoencoder": {
                    "score": ae_score,
                    "threshold": th["autoencoder"],
                    "mode": self.anomaly.mode,
                    "state": self._state(ae_score, th["autoencoder"], ae_error),
                    "latency_ms": round(ae_latency, 3),
                    "error": ae_error,
                },
            },
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
        }

    # compatibility shim for per-packet callers / tests
    def analyze_packet(self, packet, sequence=None, metadata=None):
        return self.analyze_flow(packet, metadata=metadata)

    def _state(self, score, threshold, error, waiting_text="UNAVAILABLE") -> str:
        if score is None:
            return waiting_text if error == "waiting for sequence context" else "UNAVAILABLE"
        return "ALERT" if score >= threshold else "PASS"

    def _decide(self, xgb, ae, tr, padded) -> tuple[str, str, str]:
        th = settings.thresholds
        xgb_attack = xgb is not None and xgb >= th["xgb_attack"]
        xgb_susp = xgb is not None and xgb >= th["xgb_suspicious"]
        ae_anom = ae is not None and ae >= th["autoencoder"]
        session = tr is not None and tr >= th["transformer"]

        if session and not padded:
            return "ATTACK", "critical", "Transformer confirmed hostile flow-sequence context."
        if session and padded:
            return "SUSPICIOUS", "high", "Transformer flagged the host on partial (early) context."
        if xgb_attack and ae_anom:
            return "ATTACK", "high", "Routine classifier and anomaly detector both crossed attack policy."
        if xgb_attack:
            return "ATTACK", "high", "Routine XGBoost barrier crossed attack threshold."
        if ae_anom and xgb_susp:
            return "SUSPICIOUS", "medium", "Flow is suspicious and outside normal reconstruction range."
        if ae_anom:
            return "SUSPICIOUS", "medium", "Autoencoder found an out-of-ordinary flow."
        if xgb_susp:
            return "SUSPICIOUS", "medium", "Routine XGBoost barrier marked the flow suspicious."
        if xgb is None and ae is None and tr is None:
            return "UNKNOWN", "low", "No model was available to score this flow."
        return "NORMAL", "low", "All available barriers are below policy thresholds."

    def _threat_score(self, xgb, ae, tr) -> float:
        th = settings.thresholds
        cands = []
        if xgb is not None:
            cands.append(float(np.clip(xgb, 0, 1)))
        if tr is not None:
            cands.append(float(np.clip(tr, 0, 1)))
        if ae is not None:
            thr = max(th["autoencoder"], 1e-9)
            cands.append(float(np.clip(ae / (thr * 2), 0, 1)))
        return round(max(cands) if cands else 0.0, 4)


engine = DecisionEngine()


def analyze_flow(features, metadata=None):
    return engine.analyze_flow(features, metadata=metadata)


def analyze_packet(packet_df, sequence=None, metadata=None):
    return engine.analyze_flow(packet_df, metadata=metadata)
