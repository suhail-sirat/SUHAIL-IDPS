from __future__ import annotations

import math
from typing import Any, Iterable

import pandas as pd


DEFAULT_FEATURES = [
    "frame.number",
    "frame.time_relative",
    "frame.len",
    "frame.time_delta",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "icmp.type",
    "icmp.seq",
    "mqtt.msgtype",
]


def _to_number(value: Any) -> float:
    if value is None:
        return 0.0

    if isinstance(value, bool):
        return float(value)

    if isinstance(value, (int, float)):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return 0.0
        return float(value)

    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        return 0.0

    try:
        if text.lower().startswith("0x"):
            return float(int(text, 16))
        return float(text.replace(",", "."))
    except ValueError:
        return 0.0


def packets_to_frame(packet: Any, feature_order: Iterable[str] | None = None) -> pd.DataFrame:
    features = list(feature_order or DEFAULT_FEATURES)

    if isinstance(packet, pd.DataFrame):
        frame = packet.copy()
    elif isinstance(packet, list):
        frame = pd.DataFrame(packet)
    elif isinstance(packet, dict):
        frame = pd.DataFrame([packet])
    else:
        raise TypeError("packet must be a dict, list of dicts, or pandas DataFrame")

    for feature in features:
        if feature not in frame.columns:
            frame[feature] = 0

    frame = frame[features].copy()
    for column in frame.columns:
        frame[column] = frame[column].map(_to_number)

    return frame.fillna(0)


def frame_to_sequence_row(frame: pd.DataFrame, feature_order: Iterable[str] | None = None) -> list[float]:
    features = list(feature_order or DEFAULT_FEATURES)
    clean = packets_to_frame(frame, features)
    return clean.iloc[-1].astype(float).tolist()
