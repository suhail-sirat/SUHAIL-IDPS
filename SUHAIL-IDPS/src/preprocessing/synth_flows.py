"""Synthetic flow generator for replay / demo / smoke-tests.

Produces realistic-ish bidirectional-flow feature vectors (in the canonical
`FLOW_FEATURES` schema) for both normal traffic and a few attack archetypes
(port scan, SYN flood, slow-DoS, UDP flood). This lets the dashboard show live,
differentiated traffic without a packet capture, and gives the test suite a
labelled stream that exercises every barrier.

This is NOT a substitute for real captured data - it's for demos and tests. Real
training data comes from PCAPs via `pcap_to_flows.py` (see DATA_COLLECTION.md).
"""

from __future__ import annotations

import random
from typing import Any

from src.core.flow_features import FLOW_FEATURES

ATTACK_KINDS = ("portscan", "synflood", "udpflood", "slowdos")


def _normal(rng: random.Random) -> dict[str, float]:
    """A benign flow: balanced bidirectional exchange, moderate rates/sizes."""
    fwd = rng.randint(4, 30)
    bwd = rng.randint(4, 30)
    dur = rng.uniform(0.3, 8.0)
    fwd_len_mean = rng.uniform(120, 700)
    bwd_len_mean = rng.uniform(200, 1200)
    fwd_bytes = fwd * fwd_len_mean
    bwd_bytes = bwd * bwd_len_mean
    total = fwd + bwd
    total_bytes = fwd_bytes + bwd_bytes
    iat = dur / max(total, 1)
    proto = rng.choice([6, 6, 6, 17])
    dport = rng.choice([80, 443, 22, 53, 8000, 3306])
    return {
        "flow_duration": dur,
        "total_fwd_packets": fwd, "total_bwd_packets": bwd, "total_packets": total,
        "total_fwd_bytes": fwd_bytes, "total_bwd_bytes": bwd_bytes, "total_bytes": total_bytes,
        "fwd_pkt_len_max": fwd_len_mean * 1.6, "fwd_pkt_len_min": 40,
        "fwd_pkt_len_mean": fwd_len_mean, "fwd_pkt_len_std": fwd_len_mean * 0.3,
        "bwd_pkt_len_max": bwd_len_mean * 1.6, "bwd_pkt_len_min": 40,
        "bwd_pkt_len_mean": bwd_len_mean, "bwd_pkt_len_std": bwd_len_mean * 0.3,
        "pkt_len_max": max(fwd_len_mean, bwd_len_mean) * 1.6, "pkt_len_min": 40,
        "pkt_len_mean": total_bytes / total, "pkt_len_std": 250, "pkt_len_var": 250**2,
        "flow_bytes_per_s": total_bytes / dur, "flow_pkts_per_s": total / dur,
        "fwd_pkts_per_s": fwd / dur, "bwd_pkts_per_s": bwd / dur,
        "down_up_ratio": bwd / max(fwd, 1),
        "flow_iat_mean": iat, "flow_iat_std": iat * 0.5, "flow_iat_max": iat * 3, "flow_iat_min": iat * 0.2,
        "fwd_iat_total": dur * 0.5, "fwd_iat_mean": iat, "fwd_iat_std": iat * 0.5,
        "fwd_iat_max": iat * 3, "fwd_iat_min": iat * 0.2,
        "bwd_iat_total": dur * 0.5, "bwd_iat_mean": iat, "bwd_iat_std": iat * 0.5,
        "bwd_iat_max": iat * 3, "bwd_iat_min": iat * 0.2,
        "fin_flag_count": rng.randint(0, 1), "syn_flag_count": 1, "rst_flag_count": 0,
        "psh_flag_count": rng.randint(1, 4), "ack_flag_count": total, "urg_flag_count": 0,
        "fwd_header_len": fwd * 32, "bwd_header_len": bwd * 32,
        "avg_pkt_size": total_bytes / total,
        "fwd_seg_size_avg": fwd_len_mean, "bwd_seg_size_avg": bwd_len_mean,
        "protocol": proto, "dst_port": dport,
    }


def _attack(kind: str, rng: random.Random) -> dict[str, float]:
    f = _normal(rng)  # start from benign then distort by archetype
    if kind == "portscan":
        # many tiny forward-only flows, no/low response, varied dst ports
        f.update({
            "total_fwd_packets": rng.randint(1, 3), "total_bwd_packets": 0,
            "fwd_pkt_len_mean": 40, "bwd_pkt_len_mean": 0, "down_up_ratio": 0,
            "syn_flag_count": 1, "ack_flag_count": 0, "rst_flag_count": rng.randint(0, 1),
            "flow_duration": rng.uniform(0.001, 0.05), "dst_port": rng.randint(1, 65535),
            "protocol": 6,
        })
    elif kind == "synflood":
        f.update({
            "total_fwd_packets": rng.randint(200, 2000), "total_bwd_packets": 0,
            "syn_flag_count": rng.randint(200, 2000), "ack_flag_count": 0,
            "fwd_pkt_len_mean": 40, "flow_pkts_per_s": rng.uniform(5000, 40000),
            "flow_iat_mean": rng.uniform(1e-5, 1e-4), "down_up_ratio": 0,
            "protocol": 6, "dst_port": 80,
        })
    elif kind == "udpflood":
        f.update({
            "total_fwd_packets": rng.randint(300, 3000), "total_bwd_packets": rng.randint(0, 5),
            "protocol": 17, "syn_flag_count": 0, "ack_flag_count": 0,
            "flow_pkts_per_s": rng.uniform(8000, 50000),
            "flow_iat_mean": rng.uniform(1e-5, 8e-5), "fwd_pkt_len_mean": rng.uniform(60, 200),
            "dst_port": rng.choice([53, 123, 1900]),
        })
    elif kind == "slowdos":
        f.update({
            "flow_duration": rng.uniform(60, 240),
            "total_fwd_packets": rng.randint(5, 20), "total_bwd_packets": rng.randint(0, 2),
            "flow_iat_mean": rng.uniform(5, 30), "flow_iat_max": rng.uniform(30, 120),
            "flow_pkts_per_s": rng.uniform(0.05, 0.5), "psh_flag_count": rng.randint(5, 20),
            "protocol": 6, "dst_port": 80,
        })
    # recompute a couple of derived rates for coherence
    total = f["total_fwd_packets"] + f["total_bwd_packets"]
    f["total_packets"] = total
    dur = max(f["flow_duration"], 1e-6)
    f["fwd_pkts_per_s"] = f["total_fwd_packets"] / dur
    f["bwd_pkts_per_s"] = f["total_bwd_packets"] / dur
    return f


def generate_flow(
    is_attack: bool, src_ip: str, rng: random.Random
) -> tuple[dict[str, float], dict[str, Any]]:
    if is_attack:
        kind = rng.choice(ATTACK_KINDS)
        feats = _attack(kind, rng)
        attack_type = kind
    else:
        feats = _normal(rng)
        attack_type = ""
    # ensure exactly the schema, in order
    features = {name: float(feats.get(name, 0.0)) for name in FLOW_FEATURES}
    meta = {
        "src_ip": src_ip,
        "dst_ip": "10.10.0.5",
        "protocol": {6: "TCP", 17: "UDP", 1: "ICMP"}.get(int(features["protocol"]), "IP"),
        "src_port": rng.randint(1024, 65535),
        "dst_port": int(features["dst_port"]),
        "attack_type": attack_type,
    }
    return features, meta
