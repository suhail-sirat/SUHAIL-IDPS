from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from typing import Any

import joblib
import numpy as np

from src.core.features import DEFAULT_FEATURES, frame_to_sequence_row, packets_to_frame


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

XGB_MODEL_PATH = os.path.join(BASE_DIR, "models", "xgboost", "xgb_model.pkl")
XGB_SCALER_PATH = os.path.join(BASE_DIR, "models", "xgboost", "xgb_scaler.pkl")
XGB_FEATURES_PATH = os.path.join(BASE_DIR, "models", "xgboost", "xgb_features.pkl")

AE_MODEL_PATH = os.path.join(BASE_DIR, "models", "autoencoder", "autoencoder.h5")
AE_SCALER_PATH = os.path.join(BASE_DIR, "models", "autoencoder", "ae_scaler.pkl")

TRANSFORMER_MODEL_PATH = os.path.join(BASE_DIR, "models", "transformer", "transformer_model.h5")


@dataclass
class ModelSlot:
    name: str
    available: bool = False
    model: Any = None
    scaler: Any = None
    error: str | None = None

    def health(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "error": self.error,
        }


class DecisionEngine:
    """Serving-time three-barrier IDPS engine.

    Barrier 1: XGBoost routine packet classification.
    Barrier 2: Transformer session/window classification when context exists.
    Barrier 3: Autoencoder anomaly detection for out-of-distribution packets.
    """

    def __init__(self, sequence_len: int = 50, max_flows: int = 2048):
        self.sequence_len = sequence_len
        self.max_flows = max_flows
        self.lock = Lock()
        self.feature_order = self._load_features()
        self.flow_sequences: dict[str, deque[list[float]]] = defaultdict(
            lambda: deque(maxlen=self.sequence_len)
        )

        self.thresholds = {
            "xgb_suspicious": float(os.getenv("IDPS_XGB_SUSPICIOUS_THRESHOLD", "0.60")),
            "xgb_attack": float(os.getenv("IDPS_XGB_ATTACK_THRESHOLD", "0.85")),
            "autoencoder": float(os.getenv("IDPS_AE_THRESHOLD", "0.02")),
            "transformer": float(os.getenv("IDPS_TRANSFORMER_THRESHOLD", "0.50")),
        }

        self.xgb = self._load_xgboost()
        self.autoencoder = self._load_autoencoder()
        self.transformer = self._load_transformer()

    def _load_features(self) -> list[str]:
        try:
            return list(joblib.load(XGB_FEATURES_PATH))
        except Exception:
            return list(DEFAULT_FEATURES)

    def _load_xgboost(self) -> ModelSlot:
        slot = ModelSlot("xgboost")
        try:
            slot.model = joblib.load(XGB_MODEL_PATH)
            slot.scaler = joblib.load(XGB_SCALER_PATH)
            slot.available = True
        except Exception as exc:
            slot.error = str(exc)
        return slot

    def _load_autoencoder(self) -> ModelSlot:
        slot = ModelSlot("autoencoder")
        try:
            import tensorflow as tf

            slot.model = tf.keras.models.load_model(AE_MODEL_PATH, compile=False)
            slot.scaler = joblib.load(AE_SCALER_PATH)
            slot.available = True
        except Exception as exc:
            slot.error = str(exc)
        return slot

    def _load_transformer(self) -> ModelSlot:
        slot = ModelSlot("transformer")
        try:
            import tensorflow as tf

            slot.model = tf.keras.models.load_model(TRANSFORMER_MODEL_PATH, compile=False)
            slot.available = True
        except Exception as exc:
            slot.error = str(exc)
        return slot

    def health(self) -> dict[str, Any]:
        return {
            "feature_order": self.feature_order,
            "sequence_len": self.sequence_len,
            "thresholds": self.thresholds,
            "models": {
                "xgboost": self.xgb.health(),
                "autoencoder": self.autoencoder.health(),
                "transformer": self.transformer.health(),
            },
        }

    def update_thresholds(self, values: dict[str, Any]) -> dict[str, float]:
        for key in self.thresholds:
            if key in values:
                self.thresholds[key] = float(values[key])
        return dict(self.thresholds)

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
            if len(self.flow_sequences) > self.max_flows and flow_key not in self.flow_sequences:
                oldest_key = next(iter(self.flow_sequences))
                self.flow_sequences.pop(oldest_key, None)

            self.flow_sequences[flow_key].append(frame_to_sequence_row(frame, self.feature_order))
            return len(self.flow_sequences[flow_key])

    def _get_sequence(self, flow_key: str, explicit_sequence: Any | None) -> np.ndarray | None:
        if explicit_sequence is not None:
            array = np.asarray(explicit_sequence, dtype=float)
            if array.ndim == 2:
                array = np.expand_dims(array, axis=0)
            return array

        with self.lock:
            values = list(self.flow_sequences.get(flow_key, []))

        if len(values) < self.sequence_len:
            return None

        return np.asarray([values[-self.sequence_len :]], dtype=float)

    def _xgb_score(self, frame) -> tuple[float | None, str | None]:
        if not self.xgb.available:
            return None, self.xgb.error
        try:
            x = self.xgb.scaler.transform(frame[self.feature_order])
            if hasattr(self.xgb.model, "predict_proba"):
                return float(self.xgb.model.predict_proba(x)[0][1]), None
            return float(self.xgb.model.predict(x)[0]), None
        except Exception as exc:
            return None, str(exc)

    def _ae_score(self, frame) -> tuple[float | None, str | None]:
        if not self.autoencoder.available:
            return None, self.autoencoder.error
        try:
            x = self.autoencoder.scaler.transform(frame[self.feature_order])
            reconstruction = self.autoencoder.model.predict(x, verbose=0)
            return float(np.mean(np.power(x - reconstruction, 2))), None
        except Exception as exc:
            return None, str(exc)

    def _transformer_score(self, sequence: np.ndarray | None) -> tuple[float | None, str | None]:
        if sequence is None:
            return None, "waiting for sequence context"
        if not self.transformer.available:
            return None, self.transformer.error
        try:
            pred = self.transformer.model.predict(sequence, verbose=0)
            return float(np.ravel(pred)[0]), None
        except Exception as exc:
            return None, str(exc)

    def analyze_packet(
        self,
        packet: Any,
        sequence: Any | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        started = time.perf_counter()
        frame = packets_to_frame(packet, self.feature_order)
        flow_key = self._flow_key(metadata)
        sequence_size = self._remember_sequence(flow_key, frame)

        xgb_started = time.perf_counter()
        xgb_score, xgb_error = self._xgb_score(frame)
        xgb_latency = (time.perf_counter() - xgb_started) * 1000

        ae_started = time.perf_counter()
        ae_score, ae_error = self._ae_score(frame)
        ae_latency = (time.perf_counter() - ae_started) * 1000

        xgb_suspicious = xgb_score is not None and xgb_score >= self.thresholds["xgb_suspicious"]
        ae_anomaly = ae_score is not None and ae_score >= self.thresholds["autoencoder"]
        needs_context = xgb_suspicious or ae_anomaly or sequence is not None
        transformer_score = None
        transformer_error = None
        transformer_latency = 0.0

        if needs_context:
            transformer_started = time.perf_counter()
            transformer_score, transformer_error = self._transformer_score(
                self._get_sequence(flow_key, sequence)
            )
            transformer_latency = (time.perf_counter() - transformer_started) * 1000

        status, severity, reason = self._decide(xgb_score, ae_score, transformer_score)
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
                "target_length": self.sequence_len,
            },
            "barriers": {
                "routine_xgboost": {
                    "score": xgb_score,
                    "threshold": self.thresholds["xgb_suspicious"],
                    "attack_threshold": self.thresholds["xgb_attack"],
                    "state": self._state_for_score(xgb_score, self.thresholds["xgb_suspicious"], xgb_error),
                    "latency_ms": round(xgb_latency, 3),
                    "error": xgb_error,
                },
                "context_transformer": {
                    "score": transformer_score,
                    "threshold": self.thresholds["transformer"],
                    "state": self._state_for_score(
                        transformer_score,
                        self.thresholds["transformer"],
                        transformer_error,
                        waiting_text="WAITING",
                    ),
                    "latency_ms": round(transformer_latency, 3),
                    "error": transformer_error,
                },
                "zero_day_autoencoder": {
                    "score": ae_score,
                    "threshold": self.thresholds["autoencoder"],
                    "state": self._state_for_score(ae_score, self.thresholds["autoencoder"], ae_error),
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
    ) -> tuple[str, str, str]:
        xgb_attack = xgb_score is not None and xgb_score >= self.thresholds["xgb_attack"]
        xgb_suspicious = xgb_score is not None and xgb_score >= self.thresholds["xgb_suspicious"]
        ae_anomaly = ae_score is not None and ae_score >= self.thresholds["autoencoder"]
        session_attack = (
            transformer_score is not None
            and transformer_score >= self.thresholds["transformer"]
        )

        if session_attack:
            return "ATTACK", "critical", "Transformer confirmed hostile sequence context."
        if xgb_attack and ae_anomaly:
            return "ATTACK", "high", "Routine classifier and anomaly detector both crossed attack policy."
        if xgb_attack:
            return "ATTACK", "high", "Routine XGBoost barrier crossed attack threshold."
        if ae_anomaly and xgb_suspicious:
            return "SUSPICIOUS", "medium", "Packet is suspicious and outside normal reconstruction range."
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
        candidates = []
        if xgb_score is not None:
            candidates.append(float(np.clip(xgb_score, 0, 1)))
        if transformer_score is not None:
            candidates.append(float(np.clip(transformer_score, 0, 1)))
        if ae_score is not None:
            threshold = max(self.thresholds["autoencoder"], 1e-9)
            candidates.append(float(np.clip(ae_score / (threshold * 2), 0, 1)))
        return round(max(candidates) if candidates else 0.0, 4)


engine = DecisionEngine()


def analyze_packet(packet_df: Any, sequence: Any | None = None, metadata: dict[str, Any] | None = None):
    return engine.analyze_packet(packet_df, sequence=sequence, metadata=metadata)
