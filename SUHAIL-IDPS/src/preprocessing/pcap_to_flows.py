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


class AttackLabeler:
    """Rule-based flow labeller (time + IP + port windowed labelling).

    This is how CIC-IDS2017/UNSW-NB15-style datasets are built: a capture is
    never labelled wholesale. A flow is marked as attack only if it matches the
    known attack signature (attacker <-> victim, on the victim port(s), inside
    the attack time window). Everything else in the same PCAP - the occasional
    background/normal flow that inevitably shows up - stays benign (label 0).

    When ``victim_ip`` is None the labeller is disabled and every flow gets the
    file-level ``attack_label`` (the old wholesale behaviour, fine for pure
    single-service captures).
    """

    def __init__(
        self,
        attack_label: int,
        victim_ip: str | None = None,
        attacker_ip: str | None = None,
        victim_ports: set[int] | None = None,
        window: tuple[float, float] | None = None,
    ):
        self.attack_label = attack_label
        self.victim_ip = victim_ip
        self.attacker_ip = attacker_ip
        self.victim_ports = victim_ports or set()
        self.window = window

    @property
    def enabled(self) -> bool:
        return self.victim_ip is not None

    def label_for(self, flow) -> int:
        if not self.enabled:
            return self.attack_label
        ips = {flow.src_ip, flow.dst_ip}
        if self.victim_ip not in ips:
            return 0
        if self.attacker_ip and self.attacker_ip not in ips:
            return 0
        if self.victim_ports and not (
            flow.src_port in self.victim_ports or flow.dst_port in self.victim_ports
        ):
            return 0
        if self.window:
            start, end = self.window
            if flow.last_ts < start or flow.first_ts > end:
                return 0
        return self.attack_label


def convert(
    pcaps: list[Path],
    label: int,
    out_path: Path,
    attack_type: str | None,
    min_packets: int,
    labeler: "AttackLabeler | None" = None,
) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    header = FLOW_FEATURES + ["src_ip", "dst_ip", "attack_type", LABEL_COLUMN]
    labeler = labeler or AttackLabeler(label)

    tracker = FlowTracker()
    written = 0
    skipped = 0
    attack_flows = 0
    benign_flows = 0

    with out_path.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)

        def emit(flow):
            nonlocal written, skipped, attack_flows, benign_flows
            if flow.packet_count() < min_packets:
                skipped += 1
                return
            row_label = labeler.label_for(flow)
            row_type = attack_type or "" if row_label else ""
            feats = flow.feature_row()
            writer.writerow(
                feats + [flow.src_ip, flow.dst_ip, row_type, row_label]
            )
            written += 1
            if row_label:
                attack_flows += 1
            else:
                benign_flows += 1

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

    if labeler.enabled:
        print(
            f"[+] wrote {written} flows to {out_path} "
            f"({attack_flows} attack, {benign_flows} benign background, "
            f"{skipped} short flows skipped)"
        )
    else:
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
    # -- attack-aware (windowed) labelling --------------------------------- #
    parser.add_argument(
        "--victim-ip",
        default=None,
        help="enable rule-based labelling: only flows matching the attack "
        "signature get --label, other (background) flows get 0",
    )
    parser.add_argument("--attacker-ip", default=None, help="attacker host (optional)")
    parser.add_argument(
        "--victim-ports",
        nargs="+",
        type=int,
        default=None,
        help="attacked port(s); flows not touching these stay benign",
    )
    parser.add_argument("--window-start", type=float, default=None, help="epoch seconds")
    parser.add_argument("--window-end", type=float, default=None, help="epoch seconds")
    parser.add_argument(
        "--meta",
        default=None,
        help="attack metadata JSON (from collect_attack.sh) to auto-fill the "
        "victim/attacker/ports/window; explicit flags override it",
    )
    args = parser.parse_args()

    pcaps = [Path(p) for p in args.pcap]
    for p in pcaps:
        if not p.exists():
            parser.error(f"pcap not found: {p}")

    # metadata sidecar (optional) fills defaults; explicit flags win
    meta = {}
    if args.meta:
        import json

        meta = json.loads(Path(args.meta).read_text())

    victim_ip = args.victim_ip or meta.get("victim_ip")
    attacker_ip = args.attacker_ip or meta.get("attacker_ip")
    ports = args.victim_ports or meta.get("victim_ports")
    victim_ports = set(ports) if ports else None
    w_start = args.window_start if args.window_start is not None else meta.get("start_ts")
    w_end = args.window_end if args.window_end is not None else meta.get("end_ts")
    window = (float(w_start), float(w_end)) if (w_start and w_end) else None
    attack_type = args.attack_type or meta.get("attack_type")

    labeler = AttackLabeler(
        attack_label=args.label,
        victim_ip=victim_ip,
        attacker_ip=attacker_ip,
        victim_ports=victim_ports,
        window=window,
    )
    if labeler.enabled:
        print(
            f"[*] attack-aware labelling: victim={victim_ip} "
            f"attacker={attacker_ip or 'any'} ports={sorted(victim_ports) if victim_ports else 'any'} "
            f"window={'yes' if window else 'no'}"
        )

    convert(
        pcaps, args.label, Path(args.out), attack_type, args.min_packets, labeler
    )


if __name__ == "__main__":
    main()
