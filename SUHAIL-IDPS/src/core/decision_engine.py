"""Serving-time three-barrier IDPS decision engine.

The engine fuses three independently trained models into a layered defence:

* **Barrier 1 - Routine (XGBoost):** fast per-packet classifier that scores
  every packet. This is the always-on first line.
* **Barrier 2 - Context (Transformer):** session/window classifier with a
  "broader point of view". It looks at the recent sequence of a flow so it can
  catch slow, multi-packet attacks the per-packet view misses. It engages when
  a packet is suspicious or anomalous (or always, if configured), padding short
  flows so it can give an early read instead of staying silent on live traffic.
* **Barrier 3 - Zero-day (Autoencoder):** reconstruction-error anomaly detector
  trained on normal traffic only. High error == "out of the ordinary" == a
  candidate novel/zero-day event.

Each barrier is backed by a *pluggable scorer* (see ``src.core.scorers``) that
uses the real trained model when TensorFlow / XGBoost are installed and a
lightweight, dependency-free surrogate otherwise - so the full pipeline runs
either way and upgrades automatically when the heavy stack appears.

The fused verdict (NORMAL / SUSPICIOUS / ATTACK / UNKNOWN) plus a normalised
threat score is what the dashboard renders live.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any

import joblib
import numpy as np

from src.core import config
from src.core.config import settings
from src.core.features import DEFAULT_FEATURES, frame_to_sequence_row, packets_to_frame
from src.core.scorers import AnomalyScorer, ContextScorer, RoutineScorer, health_of


class DecisionEngine:
    """Serving-time three-barrier IDPS engine."""

    def __init__(
        self,
        sequence_len: int = config.SEQUENCE_LEN,
        max_flows: int = config.MAX_FLOWS,
    ):
        self.sequence_len = sequence_len
        self.max_flows = max_flows
        self.lock = Lock()
        self.feature_order = self._load_features()
        self.num_features = len(self.feature_order)
        self.flow_sequences: dict[str, deque[list[float]]] = defaultdict(
            lambda: deque(maxlen=self.sequence_len)
        )

        self.routine = RoutineScorer(self.feature_order)
        self.context = ContextScorer(self.feature_order)
        self.anomaly = AnomalyScorer(self.feature_order)

    # -- thresholds proxy (kept on settings, exposed here for compatibility) - #
    @property
    def thresholds(self) -> dict[str, float]:
        return settings.thresholds

    def update_thresholds(self, values: dict[str, Any]) -> dict[str, float]:
        return settings.update_thresholds(values)

    def _load_features(self) -> list[str]:
        try:
            return list(joblib.load(config.XGB_FEATURES_PATH))
        except Exception:
            return list(DEFAULT_FEATURES)

    def reload_models(self) -> dict[str, Any]:
        """Reload all scorers from disk (e.g. after retraining or installing deps)."""
        with self.lock:
            self.feature_order = self._load_features()
            self.num_features = len(self.feature_order)
            self.routine = RoutineScorer(self.feature_order)
            self.context = ContextScorer(self.feature_order)
            self.anomaly = AnomalyScorer(self.feature_order)
        return self.health()

    def health(self) -> dict[str, Any]:
        return {
            "feature_order": self.feature_order,
            "sequence_len": self.sequence_len,
            "transformer_pad_early": config.TRANSFORMER_PAD_EARLY,
            "thresholds": dict(settings.thresholds),
            "models": {
                "xgboost": health_of(self.routine),
                "autoencoder": health_of(self.anomaly),
                "transformer": health_of(self.context),
            },
        }

    # -- flow bookkeeping --------------------------------------------------- #
    def _flow_key(self, metadata: dict[str, Any] | None) -> str:
        if not metadata:
            return "global"
        src = metadata.get("src_ip") or metadata.get("source") or "unknown-src"
        dst = metadata.get("dst_ip") or metadata.get("destination") or "unknown-dst"
        proto = metadata.get("protocol") or metadata.get("ip.proto") or "ip"
        sport = metadata.get("src_port") or metadata.get("sport") or ""
        dport = metadata.get("dst_port") or metadata.get("dport") or ""
        return f"{src}:{sport}>{dst}:{dport}/{proto}"

    def _remember_sequence(self, flow_key: str, frame) -> int:
        with self.lock:
            if (
                len(self.flow_sequences) > self.max_flows
                and flow_key not in self.flow_sequences
            ):
                oldest_key = next(iter(self.flow_sequences))
                self.flow_sequences.pop(oldest_key, None)

            self.flow_sequences[flow_key].append(
                frame_to_sequence_row(frame, self.feature_order)
            )
            return len(self.flow_sequences[flow_key])

    def _get_sequence(
        self, flow_key: str, explicit_sequence: Any | None
    ) -> tuple[np.ndarray | None, bool]:
        """Return (sequence_tensor, is_padded).

        With pad-early enabled, a flow with at least ``TRANSFORMER_MIN_CONTEXT``
        real packets is left-padded with zeros up to ``sequence_len`` so the
        context barrier can produce an early read. Otherwise None is returned
        and the barrier stays WAITING.
        """
        if explicit_sequence is not None:
            array = np.asarray(explicit_sequence, dtype=float)
            if array.ndim == 2:
                array = np.expand_dims(array, axis=0)
            return array, False

        with self.lock:
            values = list(self.flow_sequences.get(flow_key, []))

        if len(values) >= self.sequence_len:
            window = values[-self.sequence_len :]
            return np.asarray([window], dtype=float), False

        if config.TRANSFORMER_PAD_EARLY and len(values) >= config.TRANSFORMER_MIN_CONTEXT:
            pad_count = self.sequence_len - len(values)
            padding = [[0.0] * self.num_features for _ in range(pad_count)]
            window = padding + values
            return np.asarray([window], dtype=float), True

        return None, False

    # -- main entry point --------------------------------------------------- #
    def analyze_packet(
        self,
        packet: Any,
        sequence: Any | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        started = time.perf_counter()
        th = settings.thresholds
        frame = packets_to_frame(packet, self.feature_order)
        flow_key = self._flow_key(metadata)
        sequence_size = self._remember_sequence(flow_key, frame)

        xgb_started = time.perf_counter()
        xgb_score, xgb_error = self.routine.score(frame)
        xgb_latency = (time.perf_counter() - xgb_started) * 1000

        ae_started = time.perf_counter()
        ae_score, ae_error = self.anomaly.score(frame)
        ae_latency = (time.perf_counter() - ae_started) * 1000

        xgb_suspicious = xgb_score is not None and xgb_score >= th["xgb_suspicious"]
        ae_anomaly = ae_score is not None and ae_score >= th["autoencoder"]
        needs_context = xgb_suspicious or ae_anomaly or sequence is not None

        transformer_score = None
        transformer_error = None
        transformer_latency = 0.0
        transformer_padded = False

        if needs_context:
            seq_tensor, transformer_padded = self._get_sequence(flow_key, sequence)
            transformer_started = time.perf_counter()
            transformer_score, transformer_error = self.context.score(seq_tensor)
            transformer_latency = (time.perf_counter() - transformer_started) * 1000

        status, severity, reason = self._decide(
            xgb_score, ae_score, transformer_score, transformer_padded
        )
        threat_score = self._threat_score(xgb_score, ae_score, transformer_score)

        return {
            "status": status,
            "severity": severity,
            "reason": reason,
            "threat_score": threat_score,
            "flow_key": flow_key,
            "sequence": {
                "required": needs_context,
                "length": sequence_size,
                "ready": sequence is not None or sequence_size >= self.sequence_len,
                "padded": transformer_padded,
                "target_length": self.sequence_len,
            },
            "barriers": {
                "routine_xgboost": {
                    "score": xgb_score,
                    "threshold": th["xgb_suspicious"],
                    "attack_threshold": th["xgb_attack"],
                    "mode": self.routine.mode,
                    "state": self._state_for_score(
                        xgb_score, th["xgb_suspicious"], xgb_error
                    ),
                    "latency_ms": round(xgb_latency, 3),
                    "error": xgb_error,
                },
                "context_transformer": {
                    "score": transformer_score,
                    "threshold": th["transformer"],
                    "padded": transformer_padded,
                    "mode": self.context.mode,
                    "state": self._state_for_score(
                        transformer_score,
                        th["transformer"],
                        transformer_error,
                        waiting_text="WAITING",
                    ),
                    "latency_ms": round(transformer_latency, 3),
                    "error": transformer_error,
                },
                "zero_day_autoencoder": {
                    "score": ae_score,
                    "threshold": th["autoencoder"],
                    "mode": self.anomaly.mode,
                    "state": self._state_for_score(
                        ae_score, th["autoencoder"], ae_error
                    ),
                    "latency_ms": round(ae_latency, 3),
                    "error": ae_error,
                },
            },
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
        }

    def _state_for_score(
        self,
        score: float | None,
        threshold: float,
        error: str | None,
        waiting_text: str = "UNAVAILABLE",
    ) -> str:
        if score is None:
            return waiting_text if error == "waiting for sequence context" else "UNAVAILABLE"
        return "ALERT" if score >= threshold else "PASS"

    def _decide(
        self,
        xgb_score: float | None,
        ae_score: float | None,
        transformer_score: float | None,
        transformer_padded: bool = False,
    ) -> tuple[str, str, str]:
        th = settings.thresholds
        xgb_attack = xgb_score is not None and xgb_score >= th["xgb_attack"]
        xgb_suspicious = xgb_score is not None and xgb_score >= th["xgb_suspicious"]
        ae_anomaly = ae_score is not None and ae_score >= th["autoencoder"]
        session_attack = (
            transformer_score is not None and transformer_score >= th["transformer"]
        )

        # A padded (early, low-confidence) context read is downgraded from a
        # hard ATTACK to SUSPICIOUS so we don't over-trust partial context.
        if session_attack and not transformer_padded:
            return "ATTACK", "critical", "Transformer confirmed hostile sequence context."
        if session_attack and transformer_padded:
            return (
                "SUSPICIOUS",
                "high",
                "Transformer flagged the flow on partial (early) context.",
            )
        if xgb_attack and ae_anomaly:
            return (
                "ATTACK",
                "high",
                "Routine classifier and anomaly detector both crossed attack policy.",
            )
        if xgb_attack:
            return "ATTACK", "high", "Routine XGBoost barrier crossed attack threshold."
        if ae_anomaly and xgb_suspicious:
            return (
                "SUSPICIOUS",
                "medium",
                "Packet is suspicious and outside normal reconstruction range.",
            )
        if ae_anomaly:
            return "SUSPICIOUS", "medium", "Autoencoder found out-of-ordinary packet behavior."
        if xgb_suspicious:
            return "SUSPICIOUS", "medium", "Routine XGBoost barrier marked packet suspicious."
        if xgb_score is None and ae_score is None and transformer_score is None:
            return "UNKNOWN", "low", "No model was available to score this packet."
        return "NORMAL", "low", "All available barriers are below policy thresholds."

    def _threat_score(
        self,
        xgb_score: float | None,
        ae_score: float | None,
        transformer_score: float | None,
    ) -> float:
        th = settings.thresholds
        candidates = []
        if xgb_score is not None:
            candidates.append(float(np.clip(xgb_score, 0, 1)))
        if transformer_score is not None:
            candidates.append(float(np.clip(transformer_score, 0, 1)))
        if ae_score is not None:
            threshold = max(th["autoencoder"], 1e-9)
            candidates.append(float(np.clip(ae_score / (threshold * 2), 0, 1)))
        return round(max(candidates) if candidates else 0.0, 4)


engine = DecisionEngine()


def analyze_packet(
    packet_df: Any, sequence: Any | None = None, metadata: dict[str, Any] | None = None
):
    return engine.analyze_packet(packet_df, sequence=sequence, metadata=metadata)
