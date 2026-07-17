"""Analyze a folder of capture PCAPs and report dataset health.

Streams every packet (memory-light) and reports: volume, temporal coverage,
protocol mix, service/port diversity, endpoint diversity, packet-size and rate
distributions, TCP session health, flow (5-tuple) count, and a set of data
health checks with an overall percentage score.

Usage:
    python3 src/preprocessing/analyze_captures.py --dir dataset/normal
    python3 src/preprocessing/analyze_captures.py --dir dataset/normal --json report.json
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import statistics
import sys
from collections import Counter, defaultdict

try:
    from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, PcapReader
except Exception as exc:  # pragma: no cover
    print("scapy is required:", exc)
    sys.exit(1)


WELL_KNOWN = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
    123: "ntp", 143: "imap", 161: "snmp", 179: "bgp", 443: "https",
    465: "smtps", 587: "smtp", 993: "imaps", 995: "pop3s", 1883: "mqtt",
    3306: "mysql", 3389: "rdp", 5222: "xmpp", 5353: "mdns", 5060: "sip",
    8080: "http-alt", 8443: "https-alt", 8883: "mqtts", 51820: "wireguard",
}


def is_private(ip: str) -> bool:
    try:
        parts = [int(p) for p in ip.split(".")]
    except ValueError:
        return False
    if len(parts) != 4:
        return False
    a, b = parts[0], parts[1]
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
        or (a == 169 and b == 254)
    )


def human(n: float) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def analyze(directory: str) -> dict:
    files = sorted(glob.glob(os.path.join(directory, "*.pcap")) +
                   glob.glob(os.path.join(directory, "*.pcapng")))
    if not files:
        print(f"No PCAP files in {directory}")
        sys.exit(1)

    stats = {
        "files": [],
        "total_packets": 0,
        "total_bytes": 0,
        "l3": Counter(),          # IPv4 / IPv6 / ARP / other
        "l4": Counter(),          # TCP / UDP / ICMP / other
        "dst_ports": Counter(),
        "services": Counter(),
        "src_ips": Counter(),
        "dst_ips": Counter(),
        "tcp_flags": Counter(),
        "sizes": [],              # sampled packet sizes
        "size_sum": 0,
        "size_min": math.inf,
        "size_max": 0,
        "first_ts": math.inf,
        "last_ts": 0.0,
        "flows": set(),           # 5-tuples
        "local_to_remote": 0,
        "remote_to_local": 0,
        "local_to_local": 0,
        "dns_queries": 0,
        "tls_pkts": 0,
        "http_pkts": 0,
    }

    SIZE_SAMPLE_EVERY = 7  # subsample sizes to bound memory

    for path in files:
        f_pkts = 0
        f_bytes = 0
        f_first = math.inf
        f_last = 0.0
        try:
            with PcapReader(path) as reader:
                for i, pkt in enumerate(reader):
                    size = len(pkt)
                    ts = float(getattr(pkt, "time", 0.0))
                    f_pkts += 1
                    f_bytes += size
                    if ts:
                        f_first = min(f_first, ts)
                        f_last = max(f_last, ts)
                    stats["total_packets"] += 1
                    stats["total_bytes"] += size
                    stats["size_sum"] += size
                    stats["size_min"] = min(stats["size_min"], size)
                    stats["size_max"] = max(stats["size_max"], size)
                    if stats["total_packets"] % SIZE_SAMPLE_EVERY == 0:
                        stats["sizes"].append(size)

                    # L3
                    if IP in pkt:
                        stats["l3"]["IPv4"] += 1
                        ipl = pkt[IP]
                        src, dst = ipl.src, ipl.dst
                        stats["src_ips"][src] += 1
                        stats["dst_ips"][dst] += 1
                        s_priv, d_priv = is_private(src), is_private(dst)
                        if s_priv and not d_priv:
                            stats["local_to_remote"] += 1
                        elif d_priv and not s_priv:
                            stats["remote_to_local"] += 1
                        else:
                            stats["local_to_local"] += 1

                        proto = None
                        sport = dport = 0
                        if TCP in pkt:
                            stats["l4"]["TCP"] += 1
                            proto = "TCP"
                            t = pkt[TCP]
                            sport, dport = int(t.sport), int(t.dport)
                            stats["tcp_flags"][str(t.flags)] += 1
                            if dport == 443 or sport == 443:
                                stats["tls_pkts"] += 1
                            if dport == 80 or sport == 80:
                                stats["http_pkts"] += 1
                        elif UDP in pkt:
                            stats["l4"]["UDP"] += 1
                            proto = "UDP"
                            u = pkt[UDP]
                            sport, dport = int(u.sport), int(u.dport)
                        elif ICMP in pkt:
                            stats["l4"]["ICMP"] += 1
                            proto = "ICMP"
                        else:
                            stats["l4"]["other-ip"] += 1
                            proto = str(ipl.proto)

                        if dport:
                            stats["dst_ports"][dport] += 1
                            svc = WELL_KNOWN.get(dport) or WELL_KNOWN.get(sport)
                            if svc:
                                stats["services"][svc] += 1
                        if DNS in pkt:
                            stats["dns_queries"] += 1

                        # flow 5-tuple (direction-normalised)
                        if proto in ("TCP", "UDP"):
                            a = (src, sport)
                            b = (dst, dport)
                            key = (proto, *(a if a <= b else b), *(b if a <= b else a))
                            stats["flows"].add(key)
                    elif IPv6 in pkt:
                        stats["l3"]["IPv6"] += 1
                    elif ARP in pkt:
                        stats["l3"]["ARP"] += 1
                    else:
                        stats["l3"]["other"] += 1
        except Exception as exc:
            print(f"  ! error reading {os.path.basename(path)}: {exc}")

        if f_first is math.inf:
            f_first = 0.0
        stats["first_ts"] = min(stats["first_ts"], f_first) if f_first else stats["first_ts"]
        stats["last_ts"] = max(stats["last_ts"], f_last)
        dur = max(f_last - f_first, 0.0)
        stats["files"].append({
            "name": os.path.basename(path),
            "packets": f_pkts,
            "bytes": f_bytes,
            "duration_s": round(dur, 1),
            "size_on_disk": os.path.getsize(path),
        })
        print(f"  {os.path.basename(path):40s} {f_pkts:>8d} pkts  "
              f"{human(f_bytes):>10s}  {dur/60:6.1f} min")

    stats["flow_count"] = len(stats["flows"])
    del stats["flows"]  # not JSON-serialisable / large
    return stats


def report(stats: dict) -> None:
    tp = stats["total_packets"]
    if tp == 0:
        print("No packets found.")
        return
    span = max(stats["last_ts"] - stats["first_ts"], 0.0)
    active = sum(f["duration_s"] for f in stats["files"])
    sizes = stats["sizes"] or [0]
    mean_size = stats["size_sum"] / tp
    l4 = stats["l4"]
    tcp = l4.get("TCP", 0)
    udp = l4.get("UDP", 0)
    icmp = l4.get("ICMP", 0)
    ippkts = stats["l3"].get("IPv4", 0) + stats["l3"].get("IPv6", 0)

    def pctf(n, d):
        return (100.0 * n / d) if d else 0.0

    print("\n" + "=" * 66)
    print("  DATASET HEALTH REPORT — normal traffic")
    print("=" * 66)

    print("\n VOLUME")
    print(f"   Files                : {len(stats['files'])}")
    print(f"   Total packets        : {tp:,}")
    print(f"   Total bytes          : {human(stats['total_bytes'])}")
    print(f"   Capture time (active): {active/60:.1f} min  ({active/3600:.2f} h)")
    print(f"   Avg packet rate      : {tp/active:.0f} pkt/s" if active else "")
    print(f"   Est. flows (5-tuple) : {stats['flow_count']:,}")

    print("\n PROTOCOL MIX (of IP packets)")
    print(f"   TCP   : {tcp:>9,}  ({pctf(tcp, ippkts):5.1f}%)")
    print(f"   UDP   : {udp:>9,}  ({pctf(udp, ippkts):5.1f}%)")
    print(f"   ICMP  : {icmp:>9,}  ({pctf(icmp, ippkts):5.1f}%)")
    print(f"   IPv6  : {stats['l3'].get('IPv6', 0):>9,}")
    print(f"   ARP   : {stats['l3'].get('ARP', 0):>9,}")

    print("\n SERVICE / APPLICATION DIVERSITY")
    print(f"   Distinct destination ports : {len(stats['dst_ports']):,}")
    print(f"   Recognised services        : {len(stats['services'])}")
    for svc, c in stats["services"].most_common(12):
        print(f"     {svc:12s} {c:>9,}  ({pctf(c, tp):4.1f}%)")

    print("\n ENDPOINT DIVERSITY")
    print(f"   Unique source IPs      : {len(stats['src_ips']):,}")
    print(f"   Unique destination IPs : {len(stats['dst_ips']):,}")
    print(f"   Local→remote packets   : {pctf(stats['local_to_remote'], tp):.1f}%")
    print(f"   Remote→local packets   : {pctf(stats['remote_to_local'], tp):.1f}%")
    print("   Top destination IPs:")
    for ip, c in stats["dst_ips"].most_common(6):
        print(f"     {ip:20s} {c:>9,}  ({pctf(c, tp):4.1f}%)")

    print("\n PACKET SIZE")
    print(f"   min / mean / max : {stats['size_min']} / {mean_size:.0f} / {stats['size_max']} bytes")
    print(f"   median (sampled) : {statistics.median(sizes):.0f} bytes")

    print("\n TCP SESSION HEALTH (flag mix)")
    for fl, c in stats["tcp_flags"].most_common(8):
        print(f"     {fl:6s} {c:>9,}")

    # -------- health scoring --------
    checks = []

    def add(name, ok, detail, weight=1.0):
        checks.append({"name": name, "ok": ok, "score": ok, "detail": detail, "weight": weight})

    add("Volume ≥ 200k packets", min(tp / 200_000, 1.0),
        f"{tp:,} packets", 1.5)
    add("Capture time ≥ 60 min", min(active / 3600, 1.0),
        f"{active/60:.0f} min", 1.0)
    add("Flow count ≥ 5,000", min(stats["flow_count"] / 5000, 1.0),
        f"{stats['flow_count']:,} flows", 1.5)
    tcp_share = pctf(tcp, ippkts) / 100
    udp_share = pctf(udp, ippkts) / 100
    add("Protocol balance (TCP & UDP both present)",
        min(tcp_share * 4, 1.0) * min(udp_share * 20, 1.0) if udp else 0.0,
        f"TCP {tcp_share*100:.0f}% / UDP {udp_share*100:.0f}%", 1.0)
    add("Service diversity ≥ 6 recognised",
        min(len(stats["services"]) / 6, 1.0),
        f"{len(stats['services'])} services", 1.5)
    add("Destination-port diversity ≥ 50",
        min(len(stats["dst_ports"]) / 50, 1.0),
        f"{len(stats['dst_ports'])} ports", 1.0)
    add("External endpoint diversity ≥ 100 dst IPs",
        min(len(stats["dst_ips"]) / 100, 1.0),
        f"{len(stats['dst_ips'])} dst IPs", 1.0)
    has_syn = any("S" in f for f in stats["tcp_flags"])
    has_fin = any("F" in f for f in stats["tcp_flags"])
    add("Real TCP sessions (SYN+FIN seen)",
        1.0 if (has_syn and has_fin) else (0.5 if has_syn else 0.0),
        f"SYN={has_syn} FIN={has_fin}", 1.0)
    add("Not single-host loopback",
        0.0 if pctf(stats["local_to_local"], tp) > 95 else 1.0,
        f"local↔local {pctf(stats['local_to_local'], tp):.0f}%", 1.0)
    add("Bidirectional (both directions present)",
        1.0 if stats["local_to_remote"] and stats["remote_to_local"] else 0.3,
        "yes" if stats["local_to_remote"] and stats["remote_to_local"] else "one-sided", 1.0)

    total_w = sum(c["weight"] for c in checks)
    got = sum(c["score"] * c["weight"] for c in checks)
    health = 100.0 * got / total_w

    print("\n HEALTH CHECKS")
    for c in checks:
        mark = "PASS" if c["score"] >= 0.8 else ("WARN" if c["score"] >= 0.4 else "FAIL")
        print(f"   [{mark}] {c['name']:42s} {c['score']*100:5.0f}%  ({c['detail']})")

    print("\n" + "=" * 66)
    print(f"   OVERALL NORMAL-DATA HEALTH : {health:.0f}%")
    print("=" * 66)
    stats["_health_pct"] = round(health, 1)
    stats["_checks"] = checks


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="folder of PCAPs")
    ap.add_argument("--json", help="optional path to write the JSON summary")
    args = ap.parse_args()

    print(f"Analyzing {args.dir} ...\n")
    stats = analyze(args.dir)
    report(stats)

    if args.json:
        stats.pop("sizes", None)
        with open(args.json, "w") as fh:
            json.dump(stats, fh, indent=2, default=str)
        print(f"\nJSON summary -> {args.json}")


if __name__ == "__main__":
    main()
