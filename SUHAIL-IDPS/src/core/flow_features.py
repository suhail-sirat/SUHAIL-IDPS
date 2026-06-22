"""Canonical bidirectional-flow feature definition for SUHAIL-IDPS.

This is the **single source of truth** for what "a flow's features" are. Both the
offline PCAP->CSV conversion (`src/preprocessing/pcap_to_flows.py`) and the live
serving path (`src/core/flow_tracker.py`) build feature vectors through this
module, so the model never sees a different feature space at train vs. serve time
(the classic train/serve skew that breaks IDS in production).

Design follows the CICFlowMeter / CIC-IDS-2017 bidirectional-flow convention used
across the modern flow-based NIDS literature: a flow is keyed by the 5-tuple
(src ip, dst ip, src port, dst port, protocol); the first packet fixes the
*forward* direction (src->dst) and the reverse is *backward* (dst->src). We then
compute per-direction and total statistics over packet sizes, inter-arrival
times, TCP flags and throughput.

We intentionally keep a focused, well-understood ~50-feature subset (not the full
80+) - enough to be competitive on the public benchmarks while staying cheap to
compute live, packet-by-packet, in pure Python.

Sources for the convention:
- CIC-IDS2017 / CSE-CIC-IDS2018 (Canadian Institute for Cybersecurity)
- CICFlowMeter (ahlashkari/CICFlowMeter)
"""

from __future__ import annotations

# Ordered list of flow feature columns the models train and serve on.
# Keep this list and `FlowStats.to_features()` in lock-step.
FLOW_FEATURES: list[str] = [
    # --- duration / counts ---
    "flow_duration",            # seconds, last_ts - first_ts
    "total_fwd_packets",
    "total_bwd_packets",
    "total_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "total_bytes",
    # --- forward packet-length stats ---
    "fwd_pkt_len_max",
    "fwd_pkt_len_min",
    "fwd_pkt_len_mean",
    "fwd_pkt_len_std",
    # --- backward packet-length stats ---
    "bwd_pkt_len_max",
    "bwd_pkt_len_min",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_std",
    # --- overall packet-length stats ---
    "pkt_len_max",
    "pkt_len_min",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_var",
    # --- throughput ---
    "flow_bytes_per_s",
    "flow_pkts_per_s",
    "fwd_pkts_per_s",
    "bwd_pkts_per_s",
    "down_up_ratio",            # bwd_pkts / fwd_pkts
    # --- flow inter-arrival times (IAT) ---
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    # --- forward IAT ---
    "fwd_iat_total",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    # --- backward IAT ---
    "bwd_iat_total",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bwd_iat_min",
    # --- TCP flag counts (whole flow) ---
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    # --- header / ratio ---
    "fwd_header_len",
    "bwd_header_len",
    "avg_pkt_size",
    "fwd_seg_size_avg",
    "bwd_seg_size_avg",
    # --- protocol / ports (context) ---
    "protocol",                 # 6=TCP, 17=UDP, 1=ICMP
    "dst_port",
]

NUM_FEATURES = len(FLOW_FEATURES)

# Label column name used in every produced CSV.
LABEL_COLUMN = "label"

# Sequence length for the transformer barrier (number of consecutive flows
# per host grouped into one sequence).
SEQUENCE_LEN = 16

# Flow timeout / activity parameters (seconds). A flow is emitted when it goes
# idle for longer than IDLE_TIMEOUT or lives longer than ACTIVE_TIMEOUT - the
# standard bi-flow cutoffs used by CICFlowMeter.
IDLE_TIMEOUT = 15.0
ACTIVE_TIMEOUT = 120.0
