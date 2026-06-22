"""Stateful bidirectional-flow assembly shared by offline + live paths.

`FlowStats` accumulates packets belonging to one 5-tuple flow and turns them into
the feature vector defined in `flow_features.FLOW_FEATURES`. `FlowTracker` keys
packets into flows, expires idle/long flows (CICFlowMeter-style timeouts) and
hands completed flows back to the caller.

The *same* `FlowStats.to_features()` is used to build training CSVs (from PCAPs)
and to score live traffic, guaranteeing the model sees one consistent feature
space everywhere.

A "packet" here is a small dict with these keys (all optional except ts/len):
    ts: float          capture timestamp (seconds)
    length: int        total frame length in bytes
    proto: int         IP protocol number (6 TCP, 17 UDP, 1 ICMP)
    src_ip, dst_ip: str
    src_port, dst_port: int
    header_len: int    L3+L4 header length in bytes
    tcp_flags: int     raw TCP flags byte (0 if not TCP)
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterable

from src.core.flow_features import (
    ACTIVE_TIMEOUT,
    FLOW_FEATURES,
    IDLE_TIMEOUT,
)

# TCP flag bit masks
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20


def _stats(values: list[float]) -> tuple[float, float, float, float]:
    """Return (max, min, mean, std) of a list, zeros if empty."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    n = len(values)
    mx = max(values)
    mn = min(values)
    mean = sum(values) / n
    var = sum((v - mean) ** 2 for v in values) / n
    return mx, mn, mean, math.sqrt(var)


@dataclass
class FlowStats:
    """Accumulates one bidirectional flow and emits its feature vector."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    first_ts: float = 0.0
    last_ts: float = 0.0
    started: bool = False

    # per-direction packet lengths
    fwd_lengths: list[float] = field(default_factory=list)
    bwd_lengths: list[float] = field(default_factory=list)

    # per-direction timestamps (for IAT)
    fwd_times: list[float] = field(default_factory=list)
    bwd_times: list[float] = field(default_factory=list)
    all_times: list[float] = field(default_factory=list)

    fwd_header_bytes: float = 0.0
    bwd_header_bytes: float = 0.0

    fin = syn = rst = psh = ack = urg = 0

    def key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

    def add(self, pkt: dict[str, Any], forward: bool) -> None:
        ts = float(pkt.get("ts", 0.0))
        length = float(pkt.get("length", 0))
        if not self.started:
            self.first_ts = ts
            self.started = True
        self.last_ts = ts
        self.all_times.append(ts)

        if forward:
            self.fwd_lengths.append(length)
            self.fwd_times.append(ts)
            self.fwd_header_bytes += float(pkt.get("header_len", 0))
        else:
            self.bwd_lengths.append(length)
            self.bwd_times.append(ts)
            self.bwd_header_bytes += float(pkt.get("header_len", 0))

        flags = int(pkt.get("tcp_flags", 0) or 0)
        if flags:
            self.fin += bool(flags & FIN)
            self.syn += bool(flags & SYN)
            self.rst += bool(flags & RST)
            self.psh += bool(flags & PSH)
            self.ack += bool(flags & ACK)
            self.urg += bool(flags & URG)

    # -- helpers ---------------------------------------------------------- #
    @staticmethod
    def _iat(times: list[float]) -> list[float]:
        return [t2 - t1 for t1, t2 in zip(times, times[1:])] if len(times) > 1 else []

    def packet_count(self) -> int:
        return len(self.fwd_lengths) + len(self.bwd_lengths)

    def idle_for(self, now: float) -> float:
        return now - self.last_ts

    def is_expired(self, now: float) -> bool:
        return (
            self.idle_for(now) >= IDLE_TIMEOUT
            or (now - self.first_ts) >= ACTIVE_TIMEOUT
        )

    # -- the feature vector ---------------------------------------------- #
    def to_features(self) -> dict[str, float]:
        duration = max(self.last_ts - self.first_ts, 0.0)
        fwd_n = len(self.fwd_lengths)
        bwd_n = len(self.bwd_lengths)
        total_n = fwd_n + bwd_n
        fwd_bytes = sum(self.fwd_lengths)
        bwd_bytes = sum(self.bwd_lengths)
        total_bytes = fwd_bytes + bwd_bytes
        all_lengths = self.fwd_lengths + self.bwd_lengths

        f_mx, f_mn, f_mean, f_std = _stats(self.fwd_lengths)
        b_mx, b_mn, b_mean, b_std = _stats(self.bwd_lengths)
        a_mx, a_mn, a_mean, a_std = _stats(all_lengths)

        flow_iat = self._iat(self.all_times)
        fi_mx, fi_mn, fi_mean, fi_std = _stats(flow_iat)
        fwd_iat = self._iat(self.fwd_times)
        ff_mx, ff_mn, ff_mean, ff_std = _stats(fwd_iat)
        bwd_iat = self._iat(self.bwd_times)
        bb_mx, bb_mn, bb_mean, bb_std = _stats(bwd_iat)

        dur = duration if duration > 0 else 1e-6

        feats = {
            "flow_duration": duration,
            "total_fwd_packets": fwd_n,
            "total_bwd_packets": bwd_n,
            "total_packets": total_n,
            "total_fwd_bytes": fwd_bytes,
            "total_bwd_bytes": bwd_bytes,
            "total_bytes": total_bytes,
            "fwd_pkt_len_max": f_mx,
            "fwd_pkt_len_min": f_mn,
            "fwd_pkt_len_mean": f_mean,
            "fwd_pkt_len_std": f_std,
            "bwd_pkt_len_max": b_mx,
            "bwd_pkt_len_min": b_mn,
            "bwd_pkt_len_mean": b_mean,
            "bwd_pkt_len_std": b_std,
            "pkt_len_max": a_mx,
            "pkt_len_min": a_mn,
            "pkt_len_mean": a_mean,
            "pkt_len_std": a_std,
            "pkt_len_var": a_std * a_std,
            "flow_bytes_per_s": total_bytes / dur,
            "flow_pkts_per_s": total_n / dur,
            "fwd_pkts_per_s": fwd_n / dur,
            "bwd_pkts_per_s": bwd_n / dur,
            "down_up_ratio": (bwd_n / fwd_n) if fwd_n else 0.0,
            "flow_iat_mean": fi_mean,
            "flow_iat_std": fi_std,
            "flow_iat_max": fi_mx,
            "flow_iat_min": fi_mn,
            "fwd_iat_total": sum(fwd_iat),
            "fwd_iat_mean": ff_mean,
            "fwd_iat_std": ff_std,
            "fwd_iat_max": ff_mx,
            "fwd_iat_min": ff_mn,
            "bwd_iat_total": sum(bwd_iat),
            "bwd_iat_mean": bb_mean,
            "bwd_iat_std": bb_std,
            "bwd_iat_max": bb_mx,
            "bwd_iat_min": bb_mn,
            "fin_flag_count": self.fin,
            "syn_flag_count": self.syn,
            "rst_flag_count": self.rst,
            "psh_flag_count": self.psh,
            "ack_flag_count": self.ack,
            "urg_flag_count": self.urg,
            "fwd_header_len": self.fwd_header_bytes,
            "bwd_header_len": self.bwd_header_bytes,
            "avg_pkt_size": (total_bytes / total_n) if total_n else 0.0,
            "fwd_seg_size_avg": (fwd_bytes / fwd_n) if fwd_n else 0.0,
            "bwd_seg_size_avg": (bwd_bytes / bwd_n) if bwd_n else 0.0,
            "protocol": float(self.protocol),
            "dst_port": float(self.dst_port),
        }
        # guard against inf/nan from pathological divisions
        return {k: _finite(feats[k]) for k in FLOW_FEATURES}

    def feature_row(self) -> list[float]:
        feats = self.to_features()
        return [feats[name] for name in FLOW_FEATURES]


def _finite(x: float) -> float:
    if x is None or math.isnan(x) or math.isinf(x):
        return 0.0
    return float(x)


class FlowTracker:
    """Keys packets into bidirectional flows and expires completed ones."""

    def __init__(self, max_flows: int = 65536):
        self.max_flows = max_flows
        self.flows: dict[tuple, FlowStats] = {}

    @staticmethod
    def _canonical(pkt: dict[str, Any]) -> tuple[tuple, bool]:
        """Return (flow_key, is_forward).

        The forward direction is fixed by ordering the endpoints so both
        directions of a conversation map to the same key. The first-seen
        ordering decides forward; here we use (ip,port) tuple comparison which
        is deterministic and direction-stable.
        """
        a = (pkt.get("src_ip", ""), int(pkt.get("src_port", 0) or 0))
        b = (pkt.get("dst_ip", ""), int(pkt.get("dst_port", 0) or 0))
        proto = int(pkt.get("proto", 0) or 0)
        if a <= b:
            key = (a[0], b[0], a[1], b[1], proto)
            return key, True
        key = (b[0], a[0], b[1], a[1], proto)
        return key, False

    def add_packet(self, pkt: dict[str, Any]) -> list[FlowStats]:
        """Add a packet; return any flows that expired as a result."""
        now = float(pkt.get("ts", 0.0))
        key, forward = self._canonical(pkt)

        flow = self.flows.get(key)
        if flow is None:
            flow = FlowStats(
                src_ip=key[0], dst_ip=key[1],
                src_port=key[2], dst_port=key[3], protocol=key[4],
            )
            self.flows[key] = flow
        flow.add(pkt, forward)

        expired = self._collect_expired(now)
        # If a TCP flow sees RST or both-side FIN, close it promptly.
        if flow.protocol == 6 and (flow.rst > 0 or flow.fin >= 2):
            expired.append(flow)
            self.flows.pop(key, None)

        if len(self.flows) > self.max_flows:
            oldest = min(self.flows, key=lambda k: self.flows[k].last_ts)
            expired.append(self.flows.pop(oldest))
        return expired

    def _collect_expired(self, now: float) -> list[FlowStats]:
        expired = []
        for key in list(self.flows.keys()):
            if self.flows[key].is_expired(now):
                expired.append(self.flows.pop(key))
        return expired

    def flush(self) -> list[FlowStats]:
        """Emit all remaining flows (end of a PCAP / capture stop)."""
        out = list(self.flows.values())
        self.flows.clear()
        return out


def packets_to_flows(packets: Iterable[dict[str, Any]]) -> list[FlowStats]:
    """Offline helper: run a packet iterable through a tracker and return all flows."""
    tracker = FlowTracker()
    completed: list[FlowStats] = []
    for pkt in packets:
        completed.extend(tracker.add_packet(pkt))
    completed.extend(tracker.flush())
    return completed
