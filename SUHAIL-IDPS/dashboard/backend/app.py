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

from src.core.decision_engine import engine  # noqa: E402
from src.core.features import DEFAULT_FEATURES  # noqa: E402


app = Flask(__name__)

FRONTEND_PATH = PROJECT_ROOT / "dashboard" / "frontend" / "index.html"
DATA_DIR = PROJECT_ROOT / "data" / "raw"
NORMAL_FILE = DATA_DIR / "normal_processed.csv"
ATTACK_FILE = DATA_DIR / "attack_processed.csv"

EVENTS = deque(maxlen=1000)
SUBSCRIBERS: list[queue.Queue] = []
LOCK = threading.Lock()

STARTED_AT = time.time()
FRAME_COUNTER = 0
LAST_PACKET_TS: float | None = None
REPLAY_THREAD: threading.Thread | None = None
REPLAY_STOP = threading.Event()
CAPTURE_THREAD: threading.Thread | None = None
CAPTURE_STOP = threading.Event()

CONFIG = {
    "auto_block": False,
    "dry_run": True,
    "block_threshold": 5,
    "block_duration_seconds": 300,
    "event_limit": 1000,
}

STATS = {
    "total": 0,
    "normal": 0,
    "suspicious": 0,
    "attacks": 0,
    "unknown": 0,
    "model_alerts": Counter(),
    "by_source": defaultdict(lambda: {"total": 0, "attacks": 0, "suspicious": 0}),
    "recent_timestamps": deque(maxlen=300),
}

BLOCKED: dict[str, dict[str, Any]] = {}
SOURCE_ALERTS = Counter()


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def dashboard():
    return send_file(FRONTEND_PATH)


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
        }
    )


@app.route("/api/config", methods=["GET", "POST", "OPTIONS"])
def config():
    if request.method == "OPTIONS":
        return ("", 204)
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        for key in CONFIG:
            if key in payload:
                CONFIG[key] = payload[key]
        if "thresholds" in payload:
            engine.update_thresholds(payload["thresholds"])
    return jsonify({"config": CONFIG, "thresholds": engine.thresholds})


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
            "top_sources": top_sources(),
            "blocked_count": len(BLOCKED),
            "uptime_seconds": round(now - STARTED_AT, 1),
        }
    return jsonify(payload)


@app.route("/api/events")
def events():
    limit = min(int(request.args.get("limit", 100)), CONFIG["event_limit"])
    with LOCK:
        return jsonify(list(EVENTS)[-limit:])


@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(force=True)
    packet = payload.get("packet", payload)
    sequence = payload.get("sequence")
    metadata = payload.get("metadata", {})
    event = process_packet(packet, metadata=metadata, sequence=sequence, source="api")
    return jsonify(event)


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
        target=replay_packets,
        args=(profile, max(speed, 1.0), limit),
        daemon=True,
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


@app.route("/api/capture/start", methods=["POST", "OPTIONS"])
def start_capture():
    global CAPTURE_THREAD
    if request.method == "OPTIONS":
        return ("", 204)
    if CAPTURE_THREAD and CAPTURE_THREAD.is_alive():
        return jsonify(capture_status())

    payload = request.get_json(silent=True) or {}
    interface = payload.get("interface") or None
    bpf_filter = payload.get("filter", "ip")

    CAPTURE_STOP.clear()
    CAPTURE_THREAD = threading.Thread(
        target=capture_packets,
        args=(interface, bpf_filter),
        daemon=True,
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


@app.route("/api/stream")
def stream():
    subscriber = queue.Queue(maxsize=100)
    SUBSCRIBERS.append(subscriber)

    def generate():
        try:
            yield "event: hello\ndata: {}\n\n"
            while True:
                item = subscriber.get()
                yield f"event: packet\ndata: {json.dumps(item)}\n\n"
        except GeneratorExit:
            pass
        finally:
            if subscriber in SUBSCRIBERS:
                SUBSCRIBERS.remove(subscriber)

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


def process_packet(
    packet: dict[str, Any],
    metadata: dict[str, Any] | None = None,
    sequence: Any | None = None,
    source: str = "live",
) -> dict[str, Any]:
    global FRAME_COUNTER
    metadata = metadata or {}
    result = engine.analyze_packet(packet, sequence=sequence, metadata=metadata)

    with LOCK:
        FRAME_COUNTER += 1
        event_id = FRAME_COUNTER

    event = {
        "id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "metadata": metadata,
        "packet": {key: packet.get(key, 0) for key in DEFAULT_FEATURES},
        "result": result,
        "action": maybe_respond(metadata, result),
    }
    record_event(event)
    publish(event)
    return event


def record_event(event: dict[str, Any]) -> None:
    status = event["result"]["status"]
    source_ip = event["metadata"].get("src_ip") or event["metadata"].get("source") or "unknown"

    with LOCK:
        EVENTS.append(event)
        STATS["total"] += 1
        STATS["recent_timestamps"].append(time.time())
        if status == "NORMAL":
            STATS["normal"] += 1
        elif status == "SUSPICIOUS":
            STATS["suspicious"] += 1
        elif status == "ATTACK":
            STATS["attacks"] += 1
        else:
            STATS["unknown"] += 1

        STATS["by_source"][source_ip]["total"] += 1
        if status == "ATTACK":
            STATS["by_source"][source_ip]["attacks"] += 1
        if status == "SUSPICIOUS":
            STATS["by_source"][source_ip]["suspicious"] += 1

        for name, barrier in event["result"]["barriers"].items():
            if barrier["state"] == "ALERT":
                STATS["model_alerts"][name] += 1


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
    if not source_ip:
        return {"type": "observe", "message": "No source IP available."}

    if result["status"] not in {"ATTACK", "SUSPICIOUS"}:
        return {"type": "observe", "message": "Below response threshold."}

    SOURCE_ALERTS[source_ip] += 1
    if CONFIG["auto_block"] and SOURCE_ALERTS[source_ip] >= int(CONFIG["block_threshold"]):
        return block_ip(source_ip, reason=f"{SOURCE_ALERTS[source_ip]} alerts")
    return {
        "type": "watch",
        "message": f"{SOURCE_ALERTS[source_ip]} alert(s) from source.",
    }


def block_ip(ip: str, reason: str) -> dict[str, Any]:
    expires_at = time.time() + int(CONFIG["block_duration_seconds"])
    entry = {
        "ip": ip,
        "reason": reason,
        "dry_run": bool(CONFIG["dry_run"]),
        "blocked_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
        "active": True,
    }

    if not CONFIG["dry_run"]:
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        except Exception as exc:
            entry["active"] = False
            entry["error"] = str(exc)

    BLOCKED[ip] = entry
    return {"type": "block", "message": f"Block registered for {ip}.", "entry": entry}


def unblock_ip(ip: str) -> dict[str, Any]:
    entry = BLOCKED.pop(ip, None)
    if entry and not entry.get("dry_run"):
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        except Exception as exc:
            return {"type": "unblock", "ip": ip, "active": False, "error": str(exc)}
    return {"type": "unblock", "ip": ip, "active": False}


def cleanup_expired_blocks() -> None:
    now = time.time()
    for ip, entry in list(BLOCKED.items()):
        expires = datetime.fromisoformat(entry["expires_at"]).timestamp()
        if expires <= now:
            unblock_ip(ip)


def top_sources() -> list[dict[str, Any]]:
    rows = []
    for ip, values in STATS["by_source"].items():
        rows.append({"ip": ip, **values})
    return sorted(rows, key=lambda row: (row["attacks"], row["suspicious"], row["total"]), reverse=True)[:8]


def replay_packets(profile: str, speed: float, limit: int) -> None:
    files = []
    if profile in {"normal", "mixed"}:
        files.append((NORMAL_FILE, "normal-replay"))
    if profile in {"attack", "mixed"}:
        files.append((ATTACK_FILE, "attack-replay"))

    readers = []
    handles = []
    try:
        for path, label in files:
            handle = path.open(newline="")
            handles.append(handle)
            reader = csv.DictReader(handle)
            readers.append((reader, label))

        emitted = 0
        delay = 1.0 / speed
        while not REPLAY_STOP.is_set():
            made_progress = False
            for reader, label in readers:
                if REPLAY_STOP.is_set():
                    break
                try:
                    row = next(reader)
                except StopIteration:
                    continue
                made_progress = True
                row.pop("label", None)
                metadata = replay_metadata(row, label)
                process_packet(row, metadata=metadata, source=label)
                emitted += 1
                if limit and emitted >= limit:
                    REPLAY_STOP.set()
                    break
                time.sleep(delay)
            if not made_progress:
                break
    finally:
        for handle in handles:
            handle.close()


def replay_metadata(row: dict[str, Any], label: str) -> dict[str, Any]:
    source_octet = int(float(row.get("frame.number", 1))) % 240 + 10
    return {
        "src_ip": f"10.10.{1 if label.startswith('attack') else 2}.{source_octet}",
        "dst_ip": "10.10.0.5",
        "protocol": protocol_name(row.get("ip.proto")),
        "src_port": int(float(row.get("tcp.srcport") or row.get("udp.srcport") or 0)),
        "dst_port": int(float(row.get("tcp.dstport") or row.get("udp.dstport") or 0)),
        "label": label,
    }


def capture_packets(interface: str | None, bpf_filter: str) -> None:
    try:
        from scapy.all import sniff

        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=lambda pkt: process_scapy_packet(pkt),
            store=False,
            stop_filter=lambda _: CAPTURE_STOP.is_set(),
        )
    except Exception as exc:
        publish(
            {
                "id": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "capture-error",
                "metadata": {"error": str(exc)},
                "packet": {},
                "result": {
                    "status": "UNKNOWN",
                    "severity": "low",
                    "reason": "Live capture could not start.",
                    "threat_score": 0,
                    "barriers": {},
                },
                "action": {"type": "observe", "message": str(exc)},
            }
        )


def process_scapy_packet(pkt) -> None:
    global LAST_PACKET_TS
    try:
        from scapy.all import ICMP, IP, TCP, UDP

        if IP not in pkt:
            return

        now = time.time()
        delta = 0 if LAST_PACKET_TS is None else now - LAST_PACKET_TS
        LAST_PACKET_TS = now

        packet = {
            "frame.number": FRAME_COUNTER + 1,
            "frame.time_relative": now - STARTED_AT,
            "frame.len": len(pkt),
            "frame.time_delta": delta,
            "ip.proto": pkt[IP].proto,
            "tcp.srcport": pkt[TCP].sport if TCP in pkt else 0,
            "tcp.dstport": pkt[TCP].dport if TCP in pkt else 0,
            "udp.srcport": pkt[UDP].sport if UDP in pkt else 0,
            "udp.dstport": pkt[UDP].dport if UDP in pkt else 0,
            "tcp.flags": int(pkt[TCP].flags) if TCP in pkt else 0,
            "icmp.type": pkt[ICMP].type if ICMP in pkt else 0,
            "icmp.seq": getattr(pkt[ICMP], "seq", 0) if ICMP in pkt else 0,
            "mqtt.msgtype": 0,
        }
        metadata = {
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "protocol": protocol_name(pkt[IP].proto),
            "src_port": packet["tcp.srcport"] or packet["udp.srcport"],
            "dst_port": packet["tcp.dstport"] or packet["udp.dstport"],
        }
        process_packet(packet, metadata=metadata, source="capture")
    except Exception as exc:
        print("Packet processing error:", exc)


def protocol_name(value: Any) -> str:
    try:
        proto = int(float(value))
    except Exception:
        return "ip"
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))


def replay_status() -> dict[str, Any]:
    return {
        "running": bool(REPLAY_THREAD and REPLAY_THREAD.is_alive() and not REPLAY_STOP.is_set()),
        "stop_requested": REPLAY_STOP.is_set(),
    }


def capture_status() -> dict[str, Any]:
    return {
        "running": bool(CAPTURE_THREAD and CAPTURE_THREAD.is_alive() and not CAPTURE_STOP.is_set()),
        "stop_requested": CAPTURE_STOP.is_set(),
    }


def prevention_status() -> dict[str, Any]:
    return {
        "auto_block": CONFIG["auto_block"],
        "dry_run": CONFIG["dry_run"],
        "block_threshold": CONFIG["block_threshold"],
        "block_duration_seconds": CONFIG["block_duration_seconds"],
        "blocked_count": len(BLOCKED),
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("IDPS_PORT", "5000")), threaded=True)
