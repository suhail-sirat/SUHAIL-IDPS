"""SUHAIL-IDPS dashboard backend.

A Flask app that drives the live three-barrier IDPS:

* enumerates this machine's network interfaces and lets the operator capture
  live traffic from any of them with optional BPF source filtering,
* replays the bundled labelled datasets for demos / testing,
* streams every scored packet to the dashboard over Server-Sent Events,
* keeps rolling statistics, an alert feed and per-source intelligence,
* applies the prevention policy (auto-block via iptables, with a dry-run mode),
* exposes persisted settings, NDJSON event export and per-flow drill-down.

Run:  python dashboard/backend/app.py   (root needed for live capture / iptables)
"""

from __future__ import annotations

import csv
import json
import os
import queue
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, request, send_file, stream_with_context

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.core import config  # noqa: E402
from src.core.config import settings  # noqa: E402
from src.core.decision_engine import engine  # noqa: E402
from src.core.flow_features import FLOW_FEATURES  # noqa: E402
from src.live_ids.flow_source import LiveFlowSource  # noqa: E402

app = Flask(__name__)

FRONTEND_DIR = PROJECT_ROOT / "dashboard" / "frontend"
# Flow datasets produced by the preprocessing pipeline (data/flows). When absent,
# replay generates synthetic flows so the dashboard always has live traffic.
FLOWS_DIR = config.FLOWS_DIR

EVENTS: deque[dict[str, Any]] = deque(maxlen=2000)
ALERTS: deque[dict[str, Any]] = deque(maxlen=500)
SUBSCRIBERS: list[queue.Queue] = []
LOCK = threading.Lock()

STARTED_AT = time.time()
FRAME_COUNTER = 0
LAST_PACKET_TS: float | None = None
REPLAY_THREAD: threading.Thread | None = None
REPLAY_STOP = threading.Event()
CAPTURE_THREAD: threading.Thread | None = None
CAPTURE_STOP = threading.Event()
CAPTURE_INFO: dict[str, Any] = {"interface": None, "filter": None}

# 60-second resolution rolling throughput buckets (last 30 min).
THROUGHPUT = deque(maxlen=1800)

STATS = {
    "total": 0,
    "normal": 0,
    "suspicious": 0,
    "attacks": 0,
    "unknown": 0,
    "by_status_minute": defaultdict(lambda: {"normal": 0, "suspicious": 0, "attacks": 0}),
    "model_alerts": Counter(),
    "by_source": defaultdict(
        lambda: {"total": 0, "attacks": 0, "suspicious": 0, "last_seen": None}
    ),
    "by_protocol": Counter(),
    "recent_timestamps": deque(maxlen=600),
}

BLOCKED: dict[str, dict[str, Any]] = {}
SOURCE_ALERTS = Counter()


# --------------------------------------------------------------------------- #
# CORS + static
# --------------------------------------------------------------------------- #
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def dashboard():
    return send_file(FRONTEND_DIR / "index.html")


@app.route("/<path:page>")
def static_page(page: str):
    candidate = (FRONTEND_DIR / page).resolve()
    # prevent path traversal outside the frontend dir
    if FRONTEND_DIR in candidate.parents and candidate.is_file():
        return send_file(candidate)
    return send_file(FRONTEND_DIR / "index.html")


# --------------------------------------------------------------------------- #
# Health / status
# --------------------------------------------------------------------------- #
@app.route("/api/health")
def health():
    return jsonify(
        {
            "ok": True,
            "uptime_seconds": round(time.time() - STARTED_AT, 1),
            "engine": engine.health(),
            "capture": capture_status(),
            "replay": replay_status(),
            "prevention": prevention_status(),
            "settings": settings.snapshot(),
        }
    )


@app.route("/api/interfaces")
def interfaces():
    return jsonify({"interfaces": list_interfaces()})


# --------------------------------------------------------------------------- #
# Settings (thresholds + policy), persisted
# --------------------------------------------------------------------------- #
@app.route("/api/settings", methods=["GET", "POST", "OPTIONS"])
def settings_route():
    if request.method == "OPTIONS":
        return ("", 204)
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        if "thresholds" in payload:
            settings.update_thresholds(payload["thresholds"])
        if "policy" in payload:
            settings.update_policy(payload["policy"])
    return jsonify(settings.snapshot())


# Backwards-compatible alias used by older clients.
@app.route("/api/config", methods=["GET", "POST", "OPTIONS"])
def config_route():
    if request.method == "OPTIONS":
        return ("", 204)
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        policy_keys = set(config.DEFAULT_POLICY)
        policy = {k: payload[k] for k in policy_keys if k in payload}
        if policy:
            settings.update_policy(policy)
        if "thresholds" in payload:
            settings.update_thresholds(payload["thresholds"])
    snap = settings.snapshot()
    return jsonify({"config": snap["policy"], "thresholds": snap["thresholds"]})


@app.route("/api/reload", methods=["POST", "OPTIONS"])
def reload_models():
    if request.method == "OPTIONS":
        return ("", 204)
    return jsonify(engine.reload_models())


# --------------------------------------------------------------------------- #
# Stats / events / alerts
# --------------------------------------------------------------------------- #
@app.route("/api/stats")
def stats():
    cleanup_expired_blocks()
    with LOCK:
        now = time.time()
        recent = [ts for ts in STATS["recent_timestamps"] if now - ts <= 60]
        total = max(STATS["total"], 1)
        payload = {
            "total": STATS["total"],
            "normal": STATS["normal"],
            "suspicious": STATS["suspicious"],
            "attacks": STATS["attacks"],
            "unknown": STATS["unknown"],
            "attack_rate": round(STATS["attacks"] / total, 4),
            "packets_per_minute": len(recent),
            "model_alerts": dict(STATS["model_alerts"]),
            "by_protocol": dict(STATS["by_protocol"]),
            "top_sources": top_sources(),
            "blocked_count": len(BLOCKED),
            "alert_count": len(ALERTS),
            "throughput": list(THROUGHPUT)[-60:],
            "uptime_seconds": round(now - STARTED_AT, 1),
        }
    return jsonify(payload)


@app.route("/api/events")
def events():
    limit = min(int(request.args.get("limit", 100)), settings.policy["event_limit"])
    status_filter = request.args.get("status")
    source_filter = request.args.get("source")
    with LOCK:
        items = list(EVENTS)
    if status_filter and status_filter != "all":
        items = [e for e in items if e["result"]["status"] == status_filter]
    if source_filter:
        items = [
            e
            for e in items
            if (e["metadata"].get("src_ip") or e["metadata"].get("source")) == source_filter
        ]
    return jsonify(items[-limit:])


@app.route("/api/events/export")
def export_events():
    """Download the current event buffer as newline-delimited JSON."""
    with LOCK:
        items = list(EVENTS)
    body = "\n".join(json.dumps(e) for e in items)
    filename = f"idps-events-{int(time.time())}.ndjson"
    return Response(
        body,
        mimetype="application/x-ndjson",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/api/alerts")
def alerts():
    limit = min(int(request.args.get("limit", 100)), 500)
    with LOCK:
        return jsonify(list(ALERTS)[-limit:])


@app.route("/api/flow/<path:flow_key>")
def flow_detail(flow_key: str):
    """Return the recent events that belong to one flow for drill-down."""
    with LOCK:
        items = [e for e in EVENTS if e["result"].get("flow_key") == flow_key]
    return jsonify(items[-100:])


@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(force=True)
    # accept either {"flow": {...}} / {"packet": {...}} / a bare feature dict
    features = payload.get("flow") or payload.get("packet") or payload
    metadata = payload.get("metadata", {})
    event = process_flow(features, metadata=metadata, source="api")
    return jsonify(event)


# --------------------------------------------------------------------------- #
# Replay control
# --------------------------------------------------------------------------- #
@app.route("/api/replay/start", methods=["POST", "OPTIONS"])
def start_replay():
    global REPLAY_THREAD
    if request.method == "OPTIONS":
        return ("", 204)
    if REPLAY_THREAD and REPLAY_THREAD.is_alive():
        return jsonify(replay_status())

    payload = request.get_json(silent=True) or {}
    profile = payload.get("profile", "mixed")
    speed = float(payload.get("speed", 20))
    limit = int(payload.get("limit", 0))

    REPLAY_STOP.clear()
    REPLAY_THREAD = threading.Thread(
        target=replay_packets, args=(profile, max(speed, 1.0), limit), daemon=True
    )
    REPLAY_THREAD.start()
    return jsonify(replay_status())


@app.route("/api/replay/stop", methods=["POST", "OPTIONS"])
def stop_replay():
    if request.method == "OPTIONS":
        return ("", 204)
    REPLAY_STOP.set()
    return jsonify(replay_status())


@app.route("/api/replay/status")
def replay_state():
    return jsonify(replay_status())


# --------------------------------------------------------------------------- #
# Live capture control
# --------------------------------------------------------------------------- #
@app.route("/api/capture/start", methods=["POST", "OPTIONS"])
def start_capture():
    global CAPTURE_THREAD
    if request.method == "OPTIONS":
        return ("", 204)
    if CAPTURE_THREAD and CAPTURE_THREAD.is_alive():
        return jsonify(capture_status())

    payload = request.get_json(silent=True) or {}
    interface = payload.get("interface") or None
    bpf_filter = build_bpf(payload)

    CAPTURE_INFO["interface"] = interface or "all"
    CAPTURE_INFO["filter"] = bpf_filter
    CAPTURE_STOP.clear()
    CAPTURE_THREAD = threading.Thread(
        target=capture_packets, args=(interface, bpf_filter), daemon=True
    )
    CAPTURE_THREAD.start()
    return jsonify(capture_status())


@app.route("/api/capture/stop", methods=["POST", "OPTIONS"])
def stop_capture():
    if request.method == "OPTIONS":
        return ("", 204)
    CAPTURE_STOP.set()
    return jsonify(capture_status())


@app.route("/api/capture/status")
def capture_state():
    return jsonify(capture_status())


# --------------------------------------------------------------------------- #
# Prevention
# --------------------------------------------------------------------------- #
@app.route("/api/blocked")
def blocked():
    cleanup_expired_blocks()
    return jsonify(list(BLOCKED.values()))


@app.route("/api/block", methods=["POST", "OPTIONS"])
def block_ip_route():
    if request.method == "OPTIONS":
        return ("", 204)
    ip = (request.get_json(force=True) or {}).get("ip")
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    return jsonify(block_ip(ip, reason="manual"))


@app.route("/api/unblock", methods=["POST", "OPTIONS"])
def unblock_ip_route():
    if request.method == "OPTIONS":
        return ("", 204)
    ip = (request.get_json(force=True) or {}).get("ip")
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    return jsonify(unblock_ip(ip))


# --------------------------------------------------------------------------- #
# Live SSE stream
# --------------------------------------------------------------------------- #
@app.route("/api/stream")
def stream():
    subscriber = queue.Queue(maxsize=200)
    SUBSCRIBERS.append(subscriber)

    def generate():
        try:
            yield "event: hello\ndata: {}\n\n"
            while True:
                try:
                    item = subscriber.get(timeout=15)
                    yield f"event: packet\ndata: {json.dumps(item)}\n\n"
                except queue.Empty:
                    # keep-alive comment so proxies don't drop the connection
                    yield ": keep-alive\n\n"
        except GeneratorExit:
            pass
        finally:
            if subscriber in SUBSCRIBERS:
                SUBSCRIBERS.remove(subscriber)

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


# --------------------------------------------------------------------------- #
# Core flow processing
# --------------------------------------------------------------------------- #
def process_flow(
    features: dict[str, Any],
    metadata: dict[str, Any] | None = None,
    source: str = "live",
    final: bool = True,
) -> dict[str, Any]:
    """Score one bidirectional-flow feature vector and emit a dashboard event."""
    global FRAME_COUNTER
    metadata = metadata or {}
    result = engine.analyze_flow(features, metadata=metadata)

    with LOCK:
        FRAME_COUNTER += 1
        event_id = FRAME_COUNTER

    event = {
        "id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "final": final,
        "metadata": metadata,
        "flow": {name: round(float(features.get(name, 0)), 4) for name in FLOW_FEATURES},
        "result": result,
        "action": maybe_respond(metadata, result),
    }
    record_event(event)
    publish(event)
    return event


# Back-compat: /api/analyze and tests may post a raw feature dict.
def process_packet(
    packet: dict[str, Any],
    metadata: dict[str, Any] | None = None,
    sequence: Any | None = None,
    source: str = "api",
) -> dict[str, Any]:
    return process_flow(packet, metadata=metadata, source=source)


def record_event(event: dict[str, Any]) -> None:
    status = event["result"]["status"]
    metadata = event["metadata"]
    source_ip = metadata.get("src_ip") or metadata.get("source") or "unknown"
    protocol = metadata.get("protocol") or "ip"
    minute = int(time.time() // 60)

    with LOCK:
        EVENTS.append(event)
        STATS["total"] += 1
        STATS["recent_timestamps"].append(time.time())
        STATS["by_protocol"][str(protocol)] += 1

        if status == "NORMAL":
            STATS["normal"] += 1
        elif status == "SUSPICIOUS":
            STATS["suspicious"] += 1
            STATS["by_status_minute"][minute]["suspicious"] += 1
        elif status == "ATTACK":
            STATS["attacks"] += 1
            STATS["by_status_minute"][minute]["attacks"] += 1
        else:
            STATS["unknown"] += 1
        if status in ("NORMAL",):
            STATS["by_status_minute"][minute]["normal"] += 1

        src = STATS["by_source"][source_ip]
        src["total"] += 1
        src["last_seen"] = event["timestamp"]
        if status == "ATTACK":
            src["attacks"] += 1
        if status == "SUSPICIOUS":
            src["suspicious"] += 1

        for name, barrier in event["result"]["barriers"].items():
            if barrier["state"] == "ALERT":
                STATS["model_alerts"][name] += 1

        if status in ("ATTACK", "SUSPICIOUS"):
            ALERTS.append(
                {
                    "id": event["id"],
                    "timestamp": event["timestamp"],
                    "status": status,
                    "severity": event["result"]["severity"],
                    "src_ip": source_ip,
                    "dst_ip": metadata.get("dst_ip", "unknown"),
                    "protocol": str(protocol),
                    "threat_score": event["result"]["threat_score"],
                    "reason": event["result"]["reason"],
                    "flow_key": event["result"].get("flow_key"),
                    "action": event["action"].get("type"),
                }
            )

        # roll up a per-second throughput sample
        sec = int(time.time())
        if THROUGHPUT and THROUGHPUT[-1]["t"] == sec:
            THROUGHPUT[-1]["count"] += 1
            if status == "ATTACK":
                THROUGHPUT[-1]["attacks"] += 1
        else:
            THROUGHPUT.append(
                {"t": sec, "count": 1, "attacks": 1 if status == "ATTACK" else 0}
            )


def publish(event: dict[str, Any]) -> None:
    for subscriber in list(SUBSCRIBERS):
        try:
            subscriber.put_nowait(event)
        except queue.Full:
            try:
                subscriber.get_nowait()
                subscriber.put_nowait(event)
            except queue.Empty:
                pass


def maybe_respond(metadata: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    source_ip = metadata.get("src_ip") or metadata.get("source")
    policy = settings.policy
    if not source_ip:
        return {"type": "observe", "message": "No source IP available."}
    if result["status"] not in {"ATTACK", "SUSPICIOUS"}:
        return {"type": "observe", "message": "Below response threshold."}

    SOURCE_ALERTS[source_ip] += 1
    if policy["auto_block"] and SOURCE_ALERTS[source_ip] >= int(policy["block_threshold"]):
        return block_ip(source_ip, reason=f"{SOURCE_ALERTS[source_ip]} alerts")
    return {
        "type": "watch",
        "message": f"{SOURCE_ALERTS[source_ip]} alert(s) from source.",
    }


def block_ip(ip: str, reason: str) -> dict[str, Any]:
    policy = settings.policy
    expires_at = time.time() + int(policy["block_duration_seconds"])
    entry = {
        "ip": ip,
        "reason": reason,
        "dry_run": bool(policy["dry_run"]),
        "blocked_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
        "active": True,
    }
    if not policy["dry_run"]:
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True
            )
        except Exception as exc:
            entry["active"] = False
            entry["error"] = str(exc)

    BLOCKED[ip] = entry
    return {"type": "block", "message": f"Block registered for {ip}.", "entry": entry}


def unblock_ip(ip: str) -> dict[str, Any]:
    entry = BLOCKED.pop(ip, None)
    if entry and not entry.get("dry_run"):
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True
            )
        except Exception as exc:
            return {"type": "unblock", "ip": ip, "active": False, "error": str(exc)}
    return {"type": "unblock", "ip": ip, "active": False}


def cleanup_expired_blocks() -> None:
    now = time.time()
    for ip, entry in list(BLOCKED.items()):
        try:
            expires = datetime.fromisoformat(entry["expires_at"]).timestamp()
        except (ValueError, KeyError):
            continue
        if expires <= now:
            unblock_ip(ip)


def top_sources() -> list[dict[str, Any]]:
    rows = [{"ip": ip, **values} for ip, values in STATS["by_source"].items()]
    return sorted(
        rows,
        key=lambda row: (row["attacks"], row["suspicious"], row["total"]),
        reverse=True,
    )[:10]


# --------------------------------------------------------------------------- #
# Replay - synthesises flow feature vectors so the dashboard has live traffic
# for demos/testing without needing a capture. If a trained-data flow CSV exists
# it is replayed verbatim; otherwise realistic normal/attack flows are generated.
# --------------------------------------------------------------------------- #
import random  # noqa: E402

from src.preprocessing.synth_flows import generate_flow  # noqa: E402


def replay_packets(profile: str, speed: float, limit: int) -> None:
    # Prefer real labelled flows if the user has built a dataset.
    csv_path = FLOWS_DIR / "all_flows.csv"
    if csv_path.exists():
        _replay_from_csv(csv_path, profile, speed, limit)
        return

    rng = random.Random(1234)
    emitted = 0
    delay = 1.0 / max(speed, 1.0)
    hosts = [f"10.10.{1 if a else 2}.{h}" for a in (0, 1) for h in range(10, 18)]

    while not REPLAY_STOP.is_set():
        if profile == "attack":
            is_attack = True
        elif profile == "normal":
            is_attack = False
        else:  # mixed
            is_attack = rng.random() < 0.4

        host = rng.choice([h for h in hosts if h.startswith("10.10.1")] if is_attack
                          else [h for h in hosts if h.startswith("10.10.2")])
        features, meta = generate_flow(is_attack, host, rng)
        label = "attack-replay" if is_attack else "normal-replay"
        process_flow(features, metadata={**meta, "label": label}, source=label)

        emitted += 1
        if limit and emitted >= limit:
            break
        time.sleep(delay)


def _replay_from_csv(csv_path: Path, profile: str, speed: float, limit: int) -> None:
    import pandas as pd

    df = pd.read_csv(csv_path).fillna(0)
    if profile == "attack":
        df = df[df["label"] == 1]
    elif profile == "normal":
        df = df[df["label"] == 0]
    df = df.sample(frac=1.0).reset_index(drop=True)

    delay = 1.0 / max(speed, 1.0)
    emitted = 0
    for _, row in df.iterrows():
        if REPLAY_STOP.is_set():
            break
        features = {name: float(row.get(name, 0)) for name in FLOW_FEATURES}
        is_attack = int(row.get("label", 0)) == 1
        src = str(row.get("src_ip") or (f"10.10.1.{emitted % 8 + 10}" if is_attack
                                        else f"10.10.2.{emitted % 8 + 10}"))
        meta = {
            "src_ip": src,
            "dst_ip": str(row.get("dst_ip", "10.10.0.5")),
            "protocol": protocol_name(features.get("protocol")),
            "src_port": 0,
            "dst_port": int(features.get("dst_port", 0)),
            "label": "attack-replay" if is_attack else "normal-replay",
        }
        process_flow(features, metadata=meta, source=meta["label"])
        emitted += 1
        if limit and emitted >= limit:
            break
        time.sleep(delay)


# --------------------------------------------------------------------------- #
# Live capture (scapy)
# --------------------------------------------------------------------------- #
def build_bpf(payload: dict[str, Any]) -> str:
    """Compose a BPF filter from the dashboard's source-filter controls."""
    base = payload.get("filter") or "ip"
    src = payload.get("source_ip")
    proto = payload.get("protocol")  # tcp | udp | icmp
    parts = [base]
    if proto and proto in {"tcp", "udp", "icmp"}:
        parts.append(proto)
    if src:
        parts.append(f"src host {src}")
    return " and ".join(parts)


def list_interfaces() -> list[dict[str, Any]]:
    try:
        from scapy.all import get_if_list
    except Exception as exc:  # scapy unavailable
        return [{"name": "any", "address": "", "error": str(exc)}]

    try:
        from scapy.arch import get_if_addr
    except Exception:
        get_if_addr = None

    out = []
    for name in get_if_list():
        address = ""
        if get_if_addr:
            try:
                address = get_if_addr(name)
            except Exception:
                address = ""
        out.append({"name": name, "address": address})
    return out


CAPTURE_SOURCE: LiveFlowSource | None = None


def capture_packets(interface: str | None, bpf_filter: str) -> None:
    global CAPTURE_SOURCE
    CAPTURE_SOURCE = LiveFlowSource(protocol_name)
    try:
        from scapy.all import sniff

        # Periodically flush idle flows even if no new packet arrives, so the
        # dashboard finalises quiet flows in a timely way.
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=process_scapy_packet,
            store=False,
            timeout=None,
            stop_filter=lambda _: CAPTURE_STOP.is_set(),
        )
    except Exception as exc:
        publish(
            {
                "id": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "capture-error",
                "metadata": {"error": str(exc)},
                "flow": {},
                "result": {
                    "status": "UNKNOWN",
                    "severity": "low",
                    "reason": "Live capture could not start (need root / valid interface).",
                    "threat_score": 0,
                    "barriers": {},
                },
                "action": {"type": "observe", "message": str(exc)},
            }
        )
    finally:
        # finalise whatever flows were still open when capture stopped
        if CAPTURE_SOURCE is not None:
            for ev in CAPTURE_SOURCE.flush():
                process_flow(ev["features"], metadata=ev["metadata"],
                             source="capture", final=ev["final"])


def process_scapy_packet(pkt) -> None:
    """Turn a scapy packet into a normalised packet dict, assemble it into a
    flow, and score any flows that emit."""
    try:
        from scapy.all import ICMP, IP, TCP, UDP

        if IP not in pkt or CAPTURE_SOURCE is None:
            return

        ip = pkt[IP]
        proto = int(ip.proto)
        src_port = dst_port = tcp_flags = l4 = 0
        if TCP in pkt:
            src_port, dst_port = int(pkt[TCP].sport), int(pkt[TCP].dport)
            tcp_flags = int(pkt[TCP].flags)
            l4 = int(pkt[TCP].dataofs or 5) * 4
        elif UDP in pkt:
            src_port, dst_port = int(pkt[UDP].sport), int(pkt[UDP].dport)
            l4 = 8
        elif ICMP in pkt:
            l4 = 8

        packet = {
            "ts": float(pkt.time) if hasattr(pkt, "time") else time.time(),
            "length": int(len(pkt)),
            "proto": proto,
            "src_ip": str(ip.src),
            "dst_ip": str(ip.dst),
            "src_port": src_port,
            "dst_port": dst_port,
            "header_len": int(getattr(ip, "ihl", 5) or 5) * 4 + l4,
            "tcp_flags": tcp_flags,
        }
        for ev in CAPTURE_SOURCE.feed(packet):
            meta = {**ev["metadata"], "interface": CAPTURE_INFO.get("interface")}
            process_flow(ev["features"], metadata=meta, source="capture",
                         final=ev["final"])
    except Exception as exc:
        print("Packet processing error:", exc)


def protocol_name(value: Any) -> str:
    try:
        proto = int(float(value))
    except (TypeError, ValueError):
        return "ip"
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))


# --------------------------------------------------------------------------- #
# Status helpers
# --------------------------------------------------------------------------- #
def replay_status() -> dict[str, Any]:
    return {
        "running": bool(
            REPLAY_THREAD and REPLAY_THREAD.is_alive() and not REPLAY_STOP.is_set()
        ),
        "stop_requested": REPLAY_STOP.is_set(),
    }


def capture_status() -> dict[str, Any]:
    return {
        "running": bool(
            CAPTURE_THREAD and CAPTURE_THREAD.is_alive() and not CAPTURE_STOP.is_set()
        ),
        "stop_requested": CAPTURE_STOP.is_set(),
        "interface": CAPTURE_INFO.get("interface"),
        "filter": CAPTURE_INFO.get("filter"),
    }


def prevention_status() -> dict[str, Any]:
    policy = settings.policy
    return {
        "auto_block": policy["auto_block"],
        "dry_run": policy["dry_run"],
        "block_threshold": policy["block_threshold"],
        "block_duration_seconds": policy["block_duration_seconds"],
        "blocked_count": len(BLOCKED),
    }


if __name__ == "__main__":
    app.run(
        host=os.getenv("IDPS_HOST", "0.0.0.0"),
        port=int(os.getenv("IDPS_PORT", "5000")),
        threaded=True,
    )
