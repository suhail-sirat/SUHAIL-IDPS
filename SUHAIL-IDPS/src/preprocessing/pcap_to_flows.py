#!/usr/bin/env python3
"""Convert PCAP capture(s) into a labelled bidirectional-flow CSV.

This is the bridge from raw `tcpdump` captures (see DATA_COLLECTION.md) to the
training-ready flow dataset. It reads one or more `.pcap` files, assembles
bidirectional flows with `FlowTracker`, and writes one row per flow using the
canonical `FLOW_FEATURES` schema plus a `label` column.

Usage
-----
    # one file, one label (0 = normal, 1 = attack)
    python src/preprocessing/pcap_to_flows.py \
        --pcap captures/normal.pcap --label 0 --out data/flows/normal_flows.csv

    # several attack captures into one file
    python src/preprocessing/pcap_to_flows.py \
        --pcap captures/syn_flood.pcap captures/portscan.pcap \
        --label 1 --out data/flows/attack_flows.csv

    # attack-type sub-label (kept in `attack_type` column for analysis)
    python src/preprocessing/pcap_to_flows.py \
        --pcap captures/portscan.pcap --label 1 --attack-type portscan \
        --out data/flows/portscan_flows.csv

Requires scapy (already a project dependency). For very large PCAPs scapy's
PcapReader streams packets, so memory stays bounded.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.flow_features import FLOW_FEATURES, LABEL_COLUMN  # noqa: E402
from src.core.flow_tracker import FlowTracker  # noqa: E402


def iter_packets(pcap_path: Path):
    """Yield normalised packet dicts from a PCAP using scapy's streaming reader."""
    from scapy.all import ICMP, IP, TCP, UDP, PcapReader

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            proto = int(ip.proto)
            src_port = dst_port = 0
            tcp_flags = 0
            l4_header = 0

            if TCP in pkt:
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
                tcp_flags = int(pkt[TCP].flags)
                l4_header = int(pkt[TCP].dataofs or 5) * 4
            elif UDP in pkt:
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
                l4_header = 8
            elif ICMP in pkt:
                l4_header = 8

            ip_header = int(getattr(ip, "ihl", 5) or 5) * 4

            yield {
                "ts": float(pkt.time),
                "length": int(len(pkt)),
                "proto": proto,
                "src_ip": str(ip.src),
                "dst_ip": str(ip.dst),
                "src_port": src_port,
                "dst_port": dst_port,
                "header_len": ip_header + l4_header,
                "tcp_flags": tcp_flags,
            }


def convert(
    pcaps: list[Path],
    label: int,
    out_path: Path,
    attack_type: str | None,
    min_packets: int,
) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    header = FLOW_FEATURES + ["src_ip", "dst_ip", "attack_type", LABEL_COLUMN]

    tracker = FlowTracker()
    written = 0
    skipped = 0

    with out_path.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)

        def emit(flow):
            nonlocal written, skipped
            if flow.packet_count() < min_packets:
                skipped += 1
                return
            feats = flow.feature_row()
            writer.writerow(
                feats + [flow.src_ip, flow.dst_ip, attack_type or "", label]
            )
            written += 1

        for pcap in pcaps:
            print(f"[*] reading {pcap} ...")
            count = 0
            for pkt in iter_packets(pcap):
                for flow in tracker.add_packet(pkt):
                    emit(flow)
                count += 1
            print(f"    {count} packets")
        for flow in tracker.flush():
            emit(flow)

    print(f"[+] wrote {written} flows to {out_path} ({skipped} short flows skipped)")
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description="PCAP -> labelled flow CSV")
    parser.add_argument("--pcap", nargs="+", required=True, help="PCAP file(s)")
    parser.add_argument("--label", type=int, required=True, help="0=normal, 1=attack")
    parser.add_argument("--out", required=True, help="output CSV path")
    parser.add_argument("--attack-type", default=None, help="optional sub-label")
    parser.add_argument(
        "--min-packets",
        type=int,
        default=1,
        help="drop flows with fewer than this many packets (default 1: keep "
        "single-packet flows, which are the signal for port scans)",
    )
    args = parser.parse_args()

    pcaps = [Path(p) for p in args.pcap]
    for p in pcaps:
        if not p.exists():
            parser.error(f"pcap not found: {p}")

    convert(pcaps, args.label, Path(args.out), args.attack_type, args.min_packets)


if __name__ == "__main__":
    main()
